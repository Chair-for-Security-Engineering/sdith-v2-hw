<!--
SPDX-FileCopyrightText: 2026 Stef Halmans, Niklas Höher
SPDX-License-Identifier: LicenseRef-RUB-SecEng
-->

# Storing Less in-the-Head: SDitH-v2 Signing Hardware

Artifact for the Asiacrypt 2026 paper *Storing Less in-the-Head: An
Area-Efficient Hardware Architecture for SDitH-v2*.

It contains a SystemVerilog implementation of signing for SDitH-v2, the
version of the SDitH signature scheme submitted to round 2 of the NIST
process for additional post-quantum signatures ([sdith.org](https://sdith.org/)).
It also contains a simulation testbench that checks the signatures against
the official NIST known-answer tests (KATs), and the Vivado flow for the
area results. All 12 configurations of the paper are built from the same
code: security level 1, 3 or 5, fast or short parameter set, and PIOP
variant HP0 or HP1.

## Repository structure

```
rtl/sdith_params_pkg.sv   design parameters
rtl/common/               AES/Rijndael, SHAKE/Keccak, GF multiplier, memories
rtl/sign/                 signing pipeline
rtl/sign/tb/              cocotb testbench and Makefile
synth/                    Vivado flow
scripts/                  KAT download, KAT test driver and KAT parser
KAT/                      official SDitH-v2 KAT files (downloaded, see below)
shell.nix                 simulation environment
LICENSES/                 licence texts (see Licence)
```

The top level is `rtl/sign/sign_top.sv`. It contains the signing pipeline,
the two AES cores, the SHAKE core and the internal memories, and reads the
key, message and signature from external memories. `rtl/sign/sign.sv`
sequences the signing phases and shares the cores and memories between
them. All sizes are derived from `rtl/sdith_params_pkg.sv`.

The testbench (`rtl/sign/tb/test_sign.sv` and `test_test_sign_kat.py`)
loads the secret key and message of a KAT entry into the testbench
memories, runs `sign_top` and compares the signature with the one in the
KAT file. The random salt and seed that the reference implementation used
for that signature are recomputed from the entry's seed with the random
number generator of the NIST KAT generator (AES-256 CTR-DRBG, in
`scripts/kat_to_vectors.py`).

## Requirements

**Simulation:** [Nix](https://nixos.org/download/). `shell.nix` pins all
tools (Verilator 5.044, Python 3.13, cocotb 2.0.1, pycryptodome 3.23, GCC
15.2), so nothing else is needed. To use them, run

```
nix-shell
```

in the artifact folder. The first call downloads the tools. It opens a
shell in which they are available (the prompt starts with `[nix-shell:`);
run the simulation commands below in this shell and leave it with `exit`.
A single command can also be run directly, e.g.
`nix-shell --run 'scripts/run_kat.sh sec1_fast_hp0'`.

**KAT files:** the official KAT files are not included. Download them once
with

```
scripts/get_kat.sh
```

This fetches the SDitH-v2 submission package of round 2 of the NIST
additional signatures process from the NIST website, extracts the six
`PQCsignKAT_*.rsp` files into `KAT/` and checks their SHA-256 checksums. If
the download no longer works, copy the `KAT` folder of the round-2 package
into the artifact root by hand, so that the files end up as
`KAT/sdith_cat<1|3|5>_<fast|short>/PQCsignKAT_*.rsp`. Packages of later rounds
may use different KAT files.

**Synthesis (optional):** AMD Vivado 2024.2. The free ML Standard edition
supports the target FPGA (Artix-7 xc7a100tcsg324-3). Vivado is not part of
the Nix environment.

Tested on x86_64 Linux.

## Configurations

Both scripts below take configuration names of the form
`sec<1|3|5>_<fast|short>_hp<0|1>`, e.g. `sec3_short_hp1`, or `all` for all
12. A name sets the following compile-time defines of
`rtl/sdith_params_pkg.sv`:

| Define | Values |
|---|---|
| `SEC_LEVEL` | 1, 3, 5 |
| `PARAM_SET` | 0 = short, 1 = fast |
| `HALF_POLY` | 0 = HP0, 1 = HP1 |

Two further defines can be set as Make variables (`make sign_kat ...
CACHE_DEPTH=10`) or as environment variables for the scripts
(`CACHE_DEPTH=10 synth/run_synth.sh sec1_fast_hp0`):

- `CACHE_DEPTH`: depth of the GGM tree cache, default 8 for level 1 and 7
  for levels 3 and 5.
- `HCOM_IN_PHASE12=1`: hashes the GGM leaf commitments in the order of the
  specification (the leaf order of BLC.Commit) instead of the order of the
  reference implementation. This removes the separate depth-first pass over
  the tree, but the signatures no longer match the KAT files, which follow
  the reference implementation, so the KAT test reports them as failing.
  Default 0.

## Simulation and KAT tests

The simulation gives the correctness and latency results of the paper
(Table *area-perf*, latency column, and Table *latency-breakdown*). Run
inside `nix-shell`:

```
scripts/run_kat.sh sec1_fast_hp0          # first KAT entry of one configuration
scripts/run_kat.sh --jobs 12 all          # first KAT entry of all 12 configurations, 12 in parallel
scripts/run_kat.sh --start 10 --count 5 sec3_short_hp1   # KAT entries 10 to 14
```

`--count all` simulates all 100 KAT entries. Logs go to `results/kat/`.
The summary at the end shows per configuration how many KAT entries passed,
the latency in Mcycles and the cycles spent in each signing phase. The
latency differs between KAT entries, because the number of
proof-of-work attempts in the last phase depends on the input.

Simulation time for one KAT entry, measured on one CPU core:

| | fast HP0 | fast HP1 | short HP0 | short HP1 |
|---|---|---|---|---|
| Level 1 | 6 min | 5 min | 27 min | 19 min |
| Level 3 | 15 min | 13 min | 1.9 h | 1.3 h |
| Level 5 | 24 min | 21 min | 2.7 h | 1.9 h |

The testbench can also be run with Make directly:

```
cd rtl/sign/tb
make sign_kat SEC_LEVEL=3 PARAM_SET=1 HALF_POLY=0 KAT_COUNT=1
```

Without `KAT_COUNT` all 100 entries are simulated. `WAVES=1` writes an FST
waveform, `make clean` removes build output.

## Synthesis (Vivado)

The synthesis gives the area results of the paper (Table *area-perf*, LUT
to slices, and Table *area-breakdown*). Run it in a normal shell, outside
the Nix shell. Vivado must be on `PATH`, or set `VIVADO` to its executable.

```
source /tools/Xilinx/Vivado/2024.2/settings64.sh   # puts vivado on PATH (adjust to your install)
synth/run_synth.sh sec1_fast_hp0                    # one configuration
synth/run_synth.sh --jobs 4 all                     # all 12 configurations, 4 in parallel
```

Each configuration takes 10-20 minutes and about 8 GB of RAM. Reports are
written to `synth/results/<config>/`. The summary at the end lists LUT, FF,
BRAM, DSP and estimated slices of `sign_top`, followed by the area per
submodule. The flow places and routes the design with retiming, at the
clock constraint used for the paper. The key, message and signature
memories are not counted.

Options of `synth/run_synth.sh`:

| Option | Effect |
|---|---|
| `--jobs N` | run N configurations in parallel (default 1) |
| `--threads N` | Vivado threads per run (default 2) |
| `--out DIR` | results folder (default `synth/results`) |
| `--period NS` | use this clock constraint for all configurations |
| `--synth-only` | stop after synthesis, without place and route (faster) |

## Licence

Every file states its copyright holders and licence in an SPDX header; the
full licence texts are in `LICENSES/`.

`rtl/common/rijndael/` is based on
[rijndael-sv](https://github.com/nhoeher/rijndael-sv).

## AI acknowledgement

Generative AI tools were used to assist with parts of the proof-of-concept
implementation. All code was reviewed by the authors and verified by
simulation against the official KATs.
