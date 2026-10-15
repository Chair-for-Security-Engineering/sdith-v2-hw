# SPDX-FileCopyrightText: 2026 Stef Halmans, Niklas Höher
# SPDX-License-Identifier: LicenseRef-RUB-SecEng

"""
NIST KAT parser + AES256-CTR-DRBG for SDitH sign testing.

Usage:
    from kat_to_vectors import parse_kat_rsp, derive_sign_inputs

    entries = parse_kat_rsp("PQCsignKAT_163.rsp")
    inputs = derive_sign_inputs(entries[0], lambda_bytes=16, wit_len=77)

    # inputs.salt_bytes_le  - salt bytes (LE: byte 0 first)
    # inputs.rseed_bytes_be - root seed bytes (BE: byte 0 first, same order as C)
    # inputs.witness        - witness from sk
    # inputs.pkey_seed      - pkey_seed from sk
    # inputs.message        - message bytes
    # inputs.expected_sig   - CRYPTO_BYTES bytes of expected signature from sm

Depends on: pycryptodome (for AES256-ECB)
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

try:
    from Crypto.Cipher import AES
except ImportError as e:
    raise ImportError(
        "pycryptodome is required. Install with: pip install pycryptodome"
    ) from e


# ===========================================================================
# NIST AES256-CTR-DRBG
#   Reference: sw_reference_implementation/sdith_cat1_fast/generator/rng.c
# ===========================================================================

class NistDrbg:
    """Bit-identical port of the NIST KAT DRBG (AES-256 in CTR mode)."""

    def __init__(self, entropy_48: bytes, personalization: bytes | None = None):
        assert len(entropy_48) == 48
        seed = bytearray(entropy_48)
        if personalization is not None:
            assert len(personalization) == 48
            seed = bytearray(a ^ b for a, b in zip(seed, personalization))
        self.key = bytearray(32)    # Key[32] initially zero
        self.V   = bytearray(16)    # V[16]   initially zero
        self._update(bytes(seed))
        self.reseed_counter = 1

    @staticmethod
    def _increment_V(V: bytearray) -> None:
        # Big-endian increment: byte 15 is LSB
        for j in range(15, -1, -1):
            if V[j] == 0xFF:
                V[j] = 0x00
            else:
                V[j] += 1
                return

    def _aes_ecb(self, block_16: bytes) -> bytes:
        return AES.new(bytes(self.key), AES.MODE_ECB).encrypt(block_16)

    def _update(self, provided_data_48: bytes | None) -> None:
        temp = bytearray(48)
        for i in range(3):
            self._increment_V(self.V)
            temp[16*i : 16*(i+1)] = self._aes_ecb(bytes(self.V))
        if provided_data_48 is not None:
            assert len(provided_data_48) == 48
            for i in range(48):
                temp[i] ^= provided_data_48[i]
        self.key = bytearray(temp[:32])
        self.V   = bytearray(temp[32:48])

    def randombytes(self, n: int) -> bytes:
        out = bytearray()
        remaining = n
        while remaining > 0:
            self._increment_V(self.V)
            block = self._aes_ecb(bytes(self.V))
            if remaining >= 16:
                out.extend(block)
                remaining -= 16
            else:
                out.extend(block[:remaining])
                remaining = 0
        self._update(None)
        self.reseed_counter += 1
        return bytes(out)


# ===========================================================================
# KAT .rsp parser
# ===========================================================================

@dataclass
class KatEntry:
    count: int
    seed: bytes       # 48 bytes
    mlen: int
    msg: bytes
    pk: bytes
    sk: bytes
    smlen: int
    sm: bytes         # msg || signature


def parse_kat_rsp(path: str | Path) -> list[KatEntry]:
    """Parse a NIST PQCsignKAT *.rsp file into a list of entries."""
    text = Path(path).read_text()
    # Skip the single header line "# <alg name>"
    entries: list[KatEntry] = []
    fields: dict[str, str] = {}

    def flush() -> None:
        if not fields:
            return
        try:
            entries.append(KatEntry(
                count = int(fields["count"]),
                seed  = bytes.fromhex(fields["seed"]),
                mlen  = int(fields["mlen"]),
                msg   = bytes.fromhex(fields["msg"]),
                pk    = bytes.fromhex(fields["pk"]),
                sk    = bytes.fromhex(fields["sk"]),
                smlen = int(fields["smlen"]),
                sm    = bytes.fromhex(fields["sm"]),
            ))
        except (ValueError, KeyError):
            pass  # skip truncated / malformed entries
        fields.clear()

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"(\w+)\s*=\s*(.*)$", line)
        if not m:
            continue
        key, val = m.group(1), m.group(2).strip()
        if key == "count" and fields:
            flush()
        fields[key] = val
    flush()
    return entries


# ===========================================================================
# Derive sign_top inputs from a KAT entry
# ===========================================================================

@dataclass
class SignInputs:
    salt_bytes_le:  bytes  # for CMD_SET_SALT  (byte 0 over UART is LSB of salt register)
    rseed_bytes_be: bytes  # for CMD_SET_RSEED (byte 0 over UART is MSB of rseed register)
    witness:        bytes  # skey_encoded_solution
    pkey_seed:      bytes  # pk seed from sk
    message:        bytes
    expected_sig:   bytes

    # Retained for debugging / cross-check
    global_salt_bytes: bytes
    root_seed_bytes:   bytes


def derive_sign_inputs(
    entry: KatEntry,
    lambda_bytes: int,
    wit_len: int,
    crypto_bytes: int | None = None,
) -> SignInputs:
    """Run the DRBG for one KAT entry and extract all sign_top inputs.

    Args:
        entry:        KAT entry (with .seed, .sk, .msg, .sm, .mlen)
        lambda_bytes: security param in bytes (16 for SEC1, 24 for SEC3, 32 for SEC5)
        wit_len:      witness byte length = (rsd_w * mux_inputs + 7) // 8
        crypto_bytes: expected CRYPTO_BYTES (for assertion; default = inferred)
    """
    # 1. Re-derive sign_entropy via the DRBG.
    #    Both keygen and sign draw 2*lambda_bytes of entropy
    #    (see sdith_keygen_entropy_bytes / sdith_signature_entropy_bytes).
    drbg = NistDrbg(entry.seed)
    _ = drbg.randombytes(2 * lambda_bytes)         # keygen_entropy (consumed by crypto_sign_keypair)
    sign_entropy = drbg.randombytes(2 * lambda_bytes)  # sign_entropy (consumed by crypto_sign)

    global_salt = sign_entropy[0:lambda_bytes]
    root_seed   = sign_entropy[lambda_bytes:2 * lambda_bytes]

    # 2. Byte ordering for UART transmission.
    # From sdith_signature.c:391-396:
    #   rseed is written to seed_salt.txt in natural order (byte 0 first)
    #   salt  is written in reversed order (byte 15 first)
    # RTL expects:
    #   rseed_i = int.from_bytes(root_seed, 'big')    -> rseed[127:120] = byte 0
    #   salt_i  = int.from_bytes(global_salt, 'little') -> salt[7:0]     = byte 0
    #
    # When SET_SALT receives bytes over UART, controller shifts them into
    # salt_reg starting at the LSB (byte 0 at LSB), so UART transmits salt
    # byte 0 first (LE order).
    # For SET_RSEED, controller shifts bytes into rseed_reg starting at the
    # MSB, so UART transmits byte 0 first but fills MSB first - the byte
    # stream itself is natural order (BE in the sense of "MSB first").
    #
    # In both cases, byte 0 is transmitted first over UART. The difference is
    # only in which end of the register it lands.
    salt_bytes_le  = global_salt  # lambda_bytes bytes, byte 0 first -> LSB of salt_reg
    rseed_bytes_be = root_seed    # lambda_bytes bytes, byte 0 first -> MSB of rseed_reg

    # 3. Extract sk fields
    pkey_seed = entry.sk[lambda_bytes : 2*lambda_bytes]
    witness   = entry.sk[2*lambda_bytes : 2*lambda_bytes + wit_len]

    # 4. Expected signature = sm[mlen:]
    expected_sig = entry.sm[entry.mlen:]
    if crypto_bytes is not None:
        assert len(expected_sig) == crypto_bytes, (
            f"Expected {crypto_bytes} bytes, got {len(expected_sig)}"
        )

    return SignInputs(
        salt_bytes_le    = salt_bytes_le,
        rseed_bytes_be   = rseed_bytes_be,
        witness          = witness,
        pkey_seed        = pkey_seed,
        message          = entry.msg,
        expected_sig     = expected_sig,
        global_salt_bytes= global_salt,
        root_seed_bytes  = root_seed,
    )


# ===========================================================================
# Helpers used by the host test script
# ===========================================================================

def bytes_to_words_le(data: bytes, n_words: int | None = None) -> list[int]:
    """Pack bytes into 64-bit little-endian words (zero-padded to n_words)."""
    if n_words is None:
        n_words = (len(data) + 7) // 8
    padded = data + b"\x00" * max(0, n_words * 8 - len(data))
    return [int.from_bytes(padded[i*8:(i+1)*8], "little") for i in range(n_words)]


def word_le_to_bytes(word: int) -> bytes:
    return word.to_bytes(8, "little")


# ===========================================================================
# CLI entry point - dump a summary of an entry (for debugging)
# ===========================================================================

if __name__ == "__main__":
    import argparse, sys

    ap = argparse.ArgumentParser(description="KAT parser / DRBG driver")
    ap.add_argument("--rsp",   required=True, help="Path to PQCsignKAT_*.rsp")
    ap.add_argument("--count", type=int, default=0, help="KAT index (0..99)")
    ap.add_argument("--lambda-bytes", type=int, default=16)
    ap.add_argument("--wit-len",      type=int, default=77)
    ap.add_argument("--crypto-bytes", type=int, default=None)
    args = ap.parse_args()

    entries = parse_kat_rsp(args.rsp)
    entry   = entries[args.count]
    inp     = derive_sign_inputs(entry, args.lambda_bytes, args.wit_len, args.crypto_bytes)

    def hx(b: bytes) -> str:
        return b.hex()

    print(f"count = {entry.count}")
    print(f"seed  = {hx(entry.seed)}")
    print(f"mlen  = {entry.mlen}")
    print(f"msg   = {hx(entry.msg)}")
    print(f"--- derived ---")
    print(f"global_salt = {hx(inp.global_salt_bytes)}")
    print(f"root_seed   = {hx(inp.root_seed_bytes)}")
    print(f"pkey_seed   = {hx(inp.pkey_seed)}")
    print(f"witness     = {hx(inp.witness)} ({len(inp.witness)} B)")
    print(f"expected_sig (first 32B): {hx(inp.expected_sig[:32])}...")
    print(f"expected_sig len         : {len(inp.expected_sig)} B")
