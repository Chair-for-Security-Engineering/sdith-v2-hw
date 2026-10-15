# SPDX-FileCopyrightText: 2026 Stef Halmans, Niklas Höher
# SPDX-License-Identifier: LicenseRef-RUB-SecEng

"""
Cocotb KAT test for sign_top.

Tests the full signing pipeline against NIST Known Answer Test vectors
from PQCsignKAT_*.rsp files. Reuses test_sign.sv as the DUT wrapper.

Configuration via environment variables:
  SEC_LEVEL  -- 1, 3, or 5 (inherited from sdith_params_pkg.sv / Makefile)
  PARAM_SET  -- 0 (SHORT) or 1 (FAST) (inherited)
  KAT_COUNT  -- number of KAT entries to test (default 0 = all 100)
  KAT_START  -- first KAT entry index (default 0)

Example:
  make sign_kat                              # all 100 entries, current params
  make sign_kat KAT_COUNT=10                 # first 10 entries
  make sign_kat SEC_LEVEL=3 PARAM_SET=1      # SEC3 FAST

Requires: pycryptodome (pip install pycryptodome)
"""

import os
import sys

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, Timer

from sdith_params import *

_REPO_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), '../../..'))
sys.path.insert(0, os.path.join(_REPO_ROOT, 'scripts'))

from kat_to_vectors import parse_kat_rsp, NistDrbg

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

KAT_COUNT = int(os.environ.get("KAT_COUNT", "0"))  # 0 = all entries
KAT_START = int(os.environ.get("KAT_START", "0"))

# ---------------------------------------------------------------------------
# Locate .rsp file for current parameter set.
# KAT/ at the repository root holds the KAT files of the official SDitH-v2
# submission package (only the .rsp files are used).
# ---------------------------------------------------------------------------

_SEC_DIR = {1: 'sdith_cat1', 3: 'sdith_cat3', 5: 'sdith_cat5'}
_PAR_DIR = {0: 'short', 1: 'fast'}
_SK_BYTES_MAP = {1: 163, 3: 232, 5: 307}

RSP_PATH = os.path.join(
    _REPO_ROOT, 'KAT',
    f'{_SEC_DIR[SECURITY_LEVEL]}_{_PAR_DIR[PARAMETER_SET]}',
    f'PQCsignKAT_{_SK_BYTES_MAP[SECURITY_LEVEL]}.rsp'
)

# ---------------------------------------------------------------------------
# Derived byte sizes for NIST signature fields
# ---------------------------------------------------------------------------

WIT_BYTES = (WIT_SIZE + 7) // 8
CCHK_U_BYTES = NUM_CCHK_PAIRS // 8

# NIST signature field descriptors.
# Crypto-derived fields (SHAKE / AES outputs) are stored big-endian per
# 64-bit word in the RTL.  Arithmetic fields are little-endian.
_FIELD_DEFS = [
    # (name,                  bram_offset,        n_words,           n_bytes,                    big_endian)
    ('global_salt',           SALT_SIG_OFFSET,     SALT_SIG_WORDS,    LAMBDA_BYTES,               False),
    ('ggm_sibling_path',      SIG_SIB_OFFSET,      SIG_SIB_WORDS,     T_OPEN * LAMBDA_BYTES,      True),
    ('ggm_hidden_leaf_cmt',   SIG_CMT_OFFSET,      SIG_CMT_WORDS,     TAU * 2 * LAMBDA_BYTES,     True),
    # corr_u is handled separately (TAU-1 word-aligned entries)
    ('cchk_u',                SIG_CCHK_U_OFFSET,   SIG_CCHK_U_WORDS,  CCHK_U_BYTES,               False),
    ('circuit_in_pub',        DWIT_SIG_OFFSET,     DWIT_SIG_WORDS,    WIT_BYTES,                  False),
    ('circuit_cz_pub',        PALPHA_SIG_OFFSET,   PALPHA_SIG_WORDS,  DEGREE * LAMBDA_BYTES,      False),
    ('hash_piop',             H_PIOP_SIG_OFFSET,   H_PIOP_SIG_SIZE,   2 * LAMBDA_BYTES,           True),
    ('proofow_ctr_reveal',    SIG_POW_OFFSET,      SIG_POW_WORDS,     4,                          False),
]

_FIELD_NAMES = (
    [d[0] for d in _FIELD_DEFS[:3]]
    + ['corr_u']
    + [d[0] for d in _FIELD_DEFS[3:]]
)


# ---------------------------------------------------------------------------
# Memory helpers
# ---------------------------------------------------------------------------

def bytes_to_words(data, n_words):
    padded = data + b'\x00' * max(0, n_words * 8 - len(data))
    return [int.from_bytes(padded[i*8:(i+1)*8], 'little') for i in range(n_words)]


async def write_key_word(dut, addr, word64):
    dut.dbg_key_wr_en_i.value = 1
    dut.dbg_key_addr_i.value = addr
    dut.dbg_key_data_i.value = word64
    await RisingEdge(dut.clk_i)
    dut.dbg_key_wr_en_i.value = 0


async def write_bytes_to_key(dut, base_addr, data, n_words):
    words = bytes_to_words(data, n_words)
    for i, w in enumerate(words):
        await write_key_word(dut, base_addr + i, w)


async def write_msg_word(dut, addr, data):
    dut.dbg_msg_wr_en_i.value = 1
    dut.dbg_msg_addr_i.value = addr
    dut.dbg_msg_data_i.value = data
    await RisingEdge(dut.clk_i)
    dut.dbg_msg_wr_en_i.value = 0


async def read_sig_word(dut, addr):
    dut.dbg_sig_rd_en_i.value = 1
    dut.dbg_sig_addr_i.value = addr
    await RisingEdge(dut.clk_i)
    await RisingEdge(dut.clk_i)
    val = int(dut.dbg_sig_data_o.value)
    dut.dbg_sig_rd_en_i.value = 0
    return val


async def wait_done(dut, timeout=100_000_000):
    cycles = 0
    while not dut.fsm_done_o.value.is_resolvable or not dut.fsm_done_o.value:
        await RisingEdge(dut.clk_i)
        cycles += 1
        if cycles > timeout:
            raise TimeoutError(f"sign_top did not complete in {timeout} cycles")
    return cycles


# ---------------------------------------------------------------------------
# NIST signature extraction
# ---------------------------------------------------------------------------

async def read_bram_field(dut, offset, n_words, n_bytes, big_endian=False):
    raw = bytearray()
    bo = 'big' if big_endian else 'little'
    for w in range(n_words):
        word = await read_sig_word(dut, offset + w)
        raw.extend(word.to_bytes(8, bo))
    return bytes(raw[:n_bytes])


async def extract_nist_signature(dut):
    """Read the full NIST-format signature from the sig BRAM.

    Returns (full_sig_bytes, per_field_dict).
    """
    out = bytearray()
    fields = {}

    for name, offset, n_words, n_bytes, be in _FIELD_DEFS[:3]:
        data = await read_bram_field(dut, offset, n_words, n_bytes, be)
        out += data
        fields[name] = data

    corr_u_all = bytearray()
    for e in range(TAU - 1):
        base = AUX_OFFSET + e * R_ACC_PARTS
        entry = await read_bram_field(dut, base, R_ACC_PARTS, LBYTES, False)
        corr_u_all += entry
    out += corr_u_all
    fields['corr_u'] = bytes(corr_u_all)

    for name, offset, n_words, n_bytes, be in _FIELD_DEFS[3:]:
        data = await read_bram_field(dut, offset, n_words, n_bytes, be)
        out += data
        fields[name] = data

    return bytes(out), fields


# ---------------------------------------------------------------------------
# Split expected NIST signature into per-field slices
# ---------------------------------------------------------------------------

def split_expected_sig(expected):
    fields = {}
    off = 0

    def take(name, n):
        nonlocal off
        fields[name] = expected[off:off + n]
        off += n

    take('global_salt',         LAMBDA_BYTES)
    take('ggm_sibling_path',    T_OPEN * LAMBDA_BYTES)
    take('ggm_hidden_leaf_cmt', TAU * 2 * LAMBDA_BYTES)
    take('corr_u',              (TAU - 1) * LBYTES)
    take('cchk_u',              CCHK_U_BYTES)
    take('circuit_in_pub',      WIT_BYTES)
    take('circuit_cz_pub',      DEGREE * LAMBDA_BYTES)
    take('hash_piop',           2 * LAMBDA_BYTES)
    take('proofow_ctr_reveal',  4)
    return fields


# ---------------------------------------------------------------------------
# Per-KAT-entry DRBG derivation
# ---------------------------------------------------------------------------

def derive_kat_inputs(entry):
    """Re-run NIST DRBG for one KAT entry; return all sign_top inputs.

    The DRBG call sequence is:
        keygen_entropy = randombytes(2 * LAMBDA_BYTES)
        sign_entropy   = randombytes(2 * LAMBDA_BYTES)
        global_salt    = sign_entropy[0 : LAMBDA_BYTES]
        root_seed      = sign_entropy[LAMBDA_BYTES : 2*LAMBDA_BYTES]
    """
    drbg = NistDrbg(entry.seed)
    _keygen = drbg.randombytes(2 * LAMBDA_BYTES)
    sign_entropy = drbg.randombytes(2 * LAMBDA_BYTES)

    global_salt = sign_entropy[0:LAMBDA_BYTES]
    root_seed   = sign_entropy[LAMBDA_BYTES:2 * LAMBDA_BYTES]

    salt_int  = int.from_bytes(global_salt, 'little')
    rseed_int = int.from_bytes(root_seed, 'big')

    skey_seed = entry.sk[0:LAMBDA_BYTES]
    pkey_seed = entry.sk[LAMBDA_BYTES:2 * LAMBDA_BYTES]
    witness   = entry.sk[2 * LAMBDA_BYTES:2 * LAMBDA_BYTES + WIT_BYTES]
    pkey_y    = entry.sk[2 * LAMBDA_BYTES + WIT_BYTES:]

    expected_sig = entry.sm[entry.mlen:]

    return salt_int, rseed_int, skey_seed, pkey_seed, witness, pkey_y, \
        entry.msg, expected_sig


# ---------------------------------------------------------------------------
# Reset helper
# ---------------------------------------------------------------------------

async def reset_dut(dut, salt_int, rseed_int):
    dut.rst_i.value = 1
    dut.fsm_start_i.value = 0
    dut.dbg_mode_i.value = 0
    dut.dbg_var_wr_en_i.value = 0
    dut.dbg_var_a_addr_i.value = 0
    dut.dbg_var_a_data_i.value = 0
    dut.dbg_var_b_addr_i.value = 0
    dut.dbg_var_b_data_i.value = 0
    dut.dbg_sig_rd_en_i.value = 0
    dut.dbg_sig_addr_i.value = 0
    dut.dbg_cache_rd_en_i.value = 0
    dut.dbg_cache_addr_i.value = 0
    dut.dbg_key_wr_en_i.value = 0
    dut.dbg_key_addr_i.value = 0
    dut.dbg_key_data_i.value = 0
    dut.dbg_msg_wr_en_i.value = 0
    dut.dbg_msg_addr_i.value = 0
    dut.dbg_msg_data_i.value = 0
    dut.salt.value = salt_int
    dut.rseed.value = rseed_int
    await Timer(100, unit="ns")
    await RisingEdge(dut.clk_i)
    dut.rst_i.value = 0
    await RisingEdge(dut.clk_i)


# ---------------------------------------------------------------------------
# Progress monitor
# ---------------------------------------------------------------------------

STAGE_NAMES = ["IDLE", "DFS", "WRITE_SALT", "PHASE12", "HLINES",
               "PIOP", "OPEN_RAND_EVAL", "DONE"]


async def progress_monitor(dut, kat_num, stage_cycles):
    """Log stage transitions and count the cycles spent in each stage
    (into stage_cycles, keyed by stage name)."""
    cnt = 0
    prev_stage = -1
    while True:
        await RisingEdge(dut.clk_i)
        cnt += 1
        try:
            cur = int(dut.dbg_stage_o.value)
        except Exception:
            continue
        sname = STAGE_NAMES[cur] if cur < len(STAGE_NAMES) else f"?{cur}"
        stage_cycles[sname] = stage_cycles.get(sname, 0) + 1
        if cur != prev_stage:
            cocotb.log.info(f"  KAT {kat_num} [{cnt/1e6:.1f}M] -> {sname}")
            prev_stage = cur
            if sname == "DONE":
                return
        if cnt % 5_000_000 == 0:
            cocotb.log.info(f"  KAT {kat_num} [{cnt/1e6:.0f}M] stage={sname}")


# ---------------------------------------------------------------------------
# Main test
# ---------------------------------------------------------------------------

@cocotb.test()
async def test_sign_kat(dut):
    """Test sign_top against NIST KAT vectors."""

    if not os.path.exists(RSP_PATH):
        cocotb.log.error(f"KAT file not found: {RSP_PATH}")
        cocotb.log.error("Download the KAT files with scripts/get_kat.sh, or copy "
                         "the KAT directory of the SDitH-v2 round-2 submission "
                         "package to the repository root.")
        assert False, f"KAT .rsp file not found: {RSP_PATH}"

    entries = parse_kat_rsp(RSP_PATH)
    cocotb.log.info(f"Loaded {len(entries)} KAT entries from {os.path.basename(RSP_PATH)}")
    cocotb.log.info(f"SEC_LEVEL={SECURITY_LEVEL}  PARAM_SET={PARAMETER_SET}  "
                    f"LAMBDA={LAMBDA}  TAU={TAU}  KAPPA={KAPPA}  T_OPEN={T_OPEN}")

    if KAT_COUNT == 0:
        end_idx = len(entries)
    else:
        end_idx = min(KAT_START + KAT_COUNT, len(entries))
    targets = entries[KAT_START:end_idx]
    if not targets:
        assert False, (f"No KAT entries in range [{KAT_START}..{end_idx}); "
                       f"file has {len(entries)} entries")
    cocotb.log.info(f"Testing entries {KAT_START}..{end_idx - 1} "
                    f"({len(targets)} of {len(entries)} available)")

    expected_crypto_bytes = len(targets[0].sm) - targets[0].mlen
    nist_total = (LAMBDA_BYTES + T_OPEN * LAMBDA_BYTES + TAU * 2 * LAMBDA_BYTES
                  + (TAU - 1) * LBYTES + CCHK_U_BYTES + WIT_BYTES
                  + DEGREE * LAMBDA_BYTES + 2 * LAMBDA_BYTES + 4)
    cocotb.log.info(f"CRYPTO_BYTES (from KAT): {expected_crypto_bytes}  "
                    f"NIST_TOTAL (from params): {nist_total}")
    if expected_crypto_bytes != nist_total:
        cocotb.log.warning(
            f"Size mismatch! CRYPTO_BYTES={expected_crypto_bytes} vs "
            f"params total={nist_total}.  Per-field comparison may still work.")

    cocotb.start_soon(Clock(dut.clk_i, 10, unit="ns").start())

    n_pass = 0
    for idx, entry in enumerate(targets):
        kat_num = KAT_START + idx
        cocotb.log.info("=" * 60)
        cocotb.log.info(f"KAT {kat_num}: seed={entry.seed[:8].hex()}...  "
                        f"mlen={entry.mlen}")

        (salt_int, rseed_int, skey_seed, pkey_seed,
         witness, pkey_y, message, expected_sig) = derive_kat_inputs(entry)

        cocotb.log.info(f"  salt=0x{salt_int:0{LAMBDA//4}x}")
        cocotb.log.info(f"  rseed=0x{rseed_int:0{LAMBDA//4}x}")

        await reset_dut(dut, salt_int, rseed_int)

        await write_bytes_to_key(dut, SKSEED_KEY_OFFSET, skey_seed, SKSEED_KEY_WORDS)
        await write_bytes_to_key(dut, PKSEED_KEY_OFFSET, pkey_seed, PKSEED_KEY_WORDS)
        await write_bytes_to_key(dut, WIT_OFFSET, witness, WIT_WORDS)
        await write_bytes_to_key(dut, Y_KEY_OFFSET, pkey_y, Y_KEY_WORDS)
        await RisingEdge(dut.clk_i)

        msg_len = len(message)
        await write_msg_word(dut, 0, msg_len)
        for i in range(0, msg_len, 8):
            chunk = message[i:i + 8].ljust(8, b'\x00')
            word = int.from_bytes(chunk, 'little')
            await write_msg_word(dut, 1 + i // 8, word)
        cocotb.log.info(f"  Loaded key({len(skey_seed)+len(pkey_seed)+len(witness)+len(pkey_y)}B) "
                        f"+ msg({msg_len}B)")

        stage_cycles = {}
        mon = cocotb.start_soon(progress_monitor(dut, kat_num, stage_cycles))

        dut.fsm_start_i.value = 1
        await RisingEdge(dut.clk_i)
        dut.fsm_start_i.value = 0

        try:
            total_cycles = await wait_done(dut)
            mon.cancel()
            cocotb.log.info(f"  sign COMPLETED in {total_cycles} cycles")
            cocotb.log.info("  phase cycles: " + " ".join(
                f"{name}={stage_cycles.get(name, 0)}"
                for name in STAGE_NAMES[1:-1]))
        except TimeoutError as e:
            mon.cancel()
            cocotb.log.error(f"  TIMEOUT: {e}")
            cocotb.log.error(f"KAT {kat_num}: FAIL (timeout)")
            continue

        got_sig, got_fields = await extract_nist_signature(dut)
        dut.dbg_sig_rd_en_i.value = 0

        if got_sig == expected_sig:
            cocotb.log.info(f"KAT {kat_num}: PASS")
            n_pass += 1
        else:
            exp_fields = split_expected_sig(expected_sig)
            status_parts = []
            for name in _FIELD_NAMES:
                g = got_fields.get(name, b'')
                e = exp_fields.get(name, b'')
                ok = (g == e)
                tag = 'OK' if ok else 'FAIL'
                status_parts.append(f"{name}={tag}")
                if not ok:
                    show = min(32, len(g), len(e))
                    cocotb.log.error(f"  {name} MISMATCH ({len(g)}B)")
                    cocotb.log.error(f"    got : {g[:show].hex()}")
                    cocotb.log.error(f"    exp : {e[:show].hex()}")
                    for bi, (gb, eb) in enumerate(zip(g, e)):
                        if gb != eb:
                            cocotb.log.error(f"    first diff @ byte {bi}: "
                                             f"got=0x{gb:02x} exp=0x{eb:02x}")
                            break

            cocotb.log.error(f"KAT {kat_num}: FAIL  " + "  ".join(status_parts))

    cocotb.log.info("=" * 60)
    cocotb.log.info(f"KAT SUMMARY: {n_pass}/{len(targets)} passed  "
                    f"(SEC{SECURITY_LEVEL} {'FAST' if PARAMETER_SET else 'SHORT'})")
    cocotb.log.info("=" * 60)
    assert n_pass == len(targets), \
        f"KAT failures: {n_pass}/{len(targets)} passed"
