#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Stef Halmans, Niklas Höher
# SPDX-License-Identifier: LicenseRef-RUB-SecEng
# run_synth.sh - run the Vivado area flow for one or more configurations.
#
# Usage:
#   synth/run_synth.sh [options] [CONFIG ...]
#
# CONFIG is sec<1|3|5>_<fast|short>_hp<0|1> (e.g. sec1_fast_hp0) or "all"
# for the 12 configurations of the paper. Default: sec1_fast_hp0.
#
# Options:
#   --synth-only     stop after synthesis (faster; post-synthesis numbers,
#                    the paper reports post-place-and-route numbers)
#   --period NS      clock constraint in ns for every config (default: the
#                    per-config constraint of the paper's runs, see below)
#   --threads N      Vivado threads per run (default 2)
#   --jobs N         Vivado runs in parallel (default 1, ~6-8 GB RAM each)
#   --out DIR        results directory (default synth/results)
#
# Vivado is taken from $VIVADO if set, otherwise from `vivado` on PATH
# (e.g. after `source <Vivado install>/settings64.sh`).
#
# Reports land in <out>/<config>/; a summary is printed at the end
# (synth/summarize_area.py).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAPER_VIVADO="2024.2"

MODE=impl
PERIOD=
THREADS=2
JOBS=1
OUT="$SCRIPT_DIR/results"
CONFIGS=()

ALL_CONFIGS=(
    sec1_fast_hp0 sec1_fast_hp1 sec1_short_hp0 sec1_short_hp1
    sec3_fast_hp0 sec3_fast_hp1 sec3_short_hp0 sec3_short_hp1
    sec5_fast_hp0 sec5_fast_hp1 sec5_short_hp0 sec5_short_hp1
)

# Clock constraint (ns) of the runs that produced the paper's area numbers.
# Utilisation depends slightly on the constraint (about 1% in LUTs).
declare -A PAPER_PERIOD=(
    [sec1_fast_hp0]=6.88  [sec1_fast_hp1]=7.7   [sec1_short_hp0]=8.36  [sec1_short_hp1]=7.691
    [sec3_fast_hp0]=7.361 [sec3_fast_hp1]=8.21  [sec3_short_hp0]=6.98  [sec3_short_hp1]=8.317
    [sec5_fast_hp0]=7.893 [sec5_fast_hp1]=8.72  [sec5_short_hp0]=8.02  [sec5_short_hp1]=8.5
)

usage() { sed -n '4,25p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --synth-only) MODE=synth; shift ;;
        --period)     PERIOD="$2"; shift 2 ;;
        --threads)    THREADS="$2"; shift 2 ;;
        --jobs)       JOBS="$2"; shift 2 ;;
        --out)        OUT="$2"; shift 2 ;;
        -h|--help)    usage 0 ;;
        all)          CONFIGS+=("${ALL_CONFIGS[@]}"); shift ;;
        sec[135]_fast_hp[01]|sec[135]_short_hp[01]) CONFIGS+=("$1"); shift ;;
        *) echo "unknown argument: $1" >&2; usage 1 ;;
    esac
done
[ ${#CONFIGS[@]} -eq 0 ] && CONFIGS=(sec1_fast_hp0)


# Locate Vivado.
VIVADO="${VIVADO:-$(command -v vivado || true)}"
if [ -z "$VIVADO" ]; then
    cat >&2 <<EOF
ERROR: Vivado not found.
  Either source the Vivado environment first, e.g.
      source /tools/Xilinx/Vivado/$PAPER_VIVADO/settings64.sh
  or point VIVADO at the executable:
      VIVADO=/path/to/Vivado/$PAPER_VIVADO/bin/vivado $0 ...
EOF
    exit 1
fi
VERSION="$("$VIVADO" -version 2>/dev/null | sed -n 's/^\(Vivado\|vivado\) v\([0-9.]*\).*/\2/p' | head -1)"
echo "Vivado: $VIVADO (version ${VERSION:-unknown})"
if [ "${VERSION#"$PAPER_VIVADO"}" = "$VERSION" ]; then
    echo "NOTE: the paper used Vivado $PAPER_VIVADO; other versions give slightly different numbers."
fi

mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

run_one() {
    local cfg="$1"
    local sec="${cfg:3:1}"
    local par; [[ "$cfg" == *_fast_* ]] && par=1 || par=0
    local hp="${cfg: -1}"
    local period="${PERIOD:-$(period_for "$cfg")}"
    local dir="$OUT/$cfg"
    mkdir -p "$dir"
    echo "[$(date +%H:%M:%S)] start $cfg (clock $period ns)"
    # Run inside the output directory so Vivado's journal/log files land there.
    if (cd "$dir" && "$VIVADO" -mode batch -nojournal -log vivado.log \
            -source "$SCRIPT_DIR/synth_area.tcl" \
            -tclargs "$sec" "$par" "$hp" "$dir" "$MODE" "$period" "$THREADS" \
            > stdout.log 2>&1); then
        echo "[$(date +%H:%M:%S)] done  $cfg"
    else
        echo "[$(date +%H:%M:%S)] FAILED $cfg (see $dir/vivado.log)"
        return 1
    fi
}
# Associative arrays cannot be exported to the xargs subshells, so pass the
# period table as a string.
PERIOD_TABLE="$(for k in "${!PAPER_PERIOD[@]}"; do echo "$k=${PAPER_PERIOD[$k]}"; done)"
period_for() { echo "$PERIOD_TABLE" | sed -n "s/^$1=//p"; }
export -f run_one period_for
export VIVADO OUT MODE PERIOD THREADS SCRIPT_DIR PERIOD_TABLE

echo "Configs: ${CONFIGS[*]}"
echo "Mode: $MODE, clock: ${PERIOD:-paper per-config}, $JOBS parallel run(s)"
status=0
printf '%s\n' "${CONFIGS[@]}" | xargs -P "$JOBS" -I{} bash -c 'run_one {}' || status=1

echo
python3 "$SCRIPT_DIR/summarize_area.py" "$OUT" || status=1
exit $status
