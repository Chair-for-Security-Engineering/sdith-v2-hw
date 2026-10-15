#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Stef Halmans, Niklas Höher
# SPDX-License-Identifier: LicenseRef-RUB-SecEng
# run_kat.sh - simulate sign_top against the NIST KAT files and report the
# latency in clock cycles. Run inside the Nix shell (nix-shell).
#
# Usage:
#   scripts/run_kat.sh [options] [CONFIG ...]
#
# CONFIG is sec<1|3|5>_<fast|short>_hp<0|1> (e.g. sec1_fast_hp0) or "all"
# for the 12 configurations of the paper. Default: sec1_fast_hp0.
#
# Options:
#   --count N    number of KAT entries per config, or "all" for 100
#                (default 1)
#   --start S    first KAT entry (default 0)
#   --jobs J     configurations simulated in parallel (default 1)
#   --out DIR    log directory (default results/kat)
#
# Each run writes <out>/<config>_k<start>_n<count>.log; a summary is printed
# at the end (scripts/summarize_kat.py).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

COUNT=1
START=0
JOBS=1
OUT="$ROOT/results/kat"
CONFIGS=()

ALL_CONFIGS=(
    sec1_fast_hp0 sec1_fast_hp1 sec1_short_hp0 sec1_short_hp1
    sec3_fast_hp0 sec3_fast_hp1 sec3_short_hp0 sec3_short_hp1
    sec5_fast_hp0 sec5_fast_hp1 sec5_short_hp0 sec5_short_hp1
)

usage() { sed -n '4,22p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --count) COUNT="$2"; shift 2 ;;
        --start) START="$2"; shift 2 ;;
        --jobs)  JOBS="$2"; shift 2 ;;
        --out)   OUT="$2"; shift 2 ;;
        -h|--help) usage 0 ;;
        all) CONFIGS+=("${ALL_CONFIGS[@]}"); shift ;;
        sec[135]_fast_hp[01]|sec[135]_short_hp[01]) CONFIGS+=("$1"); shift ;;
        *) echo "unknown argument: $1" >&2; usage 1 ;;
    esac
done
[ ${#CONFIGS[@]} -eq 0 ] && CONFIGS=(sec1_fast_hp0)
[ "$COUNT" = "all" ] && COUNT=0          # KAT_COUNT=0 selects every entry

for tool in verilator cocotb-config python3; do
    if ! command -v "$tool" >/dev/null; then
        echo "ERROR: $tool not found. Run this script inside the Nix shell:" >&2
        echo "  nix-shell --run 'scripts/run_kat.sh $*'" >&2
        exit 1
    fi
done

if ! ls "$ROOT"/KAT/sdith_cat*/PQCsignKAT_*.rsp >/dev/null 2>&1; then
    echo "ERROR: KAT files not found. Download them first with scripts/get_kat.sh" >&2
    exit 1
fi

# Verilator multithreading does not speed this design up, so every simulation
# runs on one core.
SIM_THREADS=1

mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

run_one() {
    local cfg="$1"
    local sec="${cfg:3:1}"
    local par; [[ "$cfg" == *_fast_* ]] && par=1 || par=0
    local hp="${cfg: -1}"
    local n; [ "$COUNT" = 0 ] && n=all || n="$COUNT"
    local log="$OUT/${cfg}_k${START}_n${n}.log"
    echo "[$(date +%H:%M:%S)] start $cfg (KAT $START, count $n) -> $log"
    if make -C "$ROOT/rtl/sign/tb" sign_kat \
            SEC_LEVEL="$sec" PARAM_SET="$par" HALF_POLY="$hp" \
            KAT_START="$START" KAT_COUNT="$COUNT" SIM_THREADS="$SIM_THREADS" \
            > "$log" 2>&1; then
        echo "[$(date +%H:%M:%S)] done  $cfg"
    else
        echo "[$(date +%H:%M:%S)] FAILED $cfg (see $log)"
        return 1
    fi
}
export -f run_one
export ROOT OUT COUNT START SIM_THREADS

echo "Configs: ${CONFIGS[*]}"
status=0
printf '%s\n' "${CONFIGS[@]}" | xargs -P "$JOBS" -I{} bash -c 'run_one {}' || status=1

echo
python3 "$ROOT/scripts/summarize_kat.py" "$OUT" || status=1
exit $status
