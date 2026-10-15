# SPDX-FileCopyrightText: 2026 Stef Halmans, Niklas Höher
# SPDX-License-Identifier: LicenseRef-RUB-SecEng

# synth_area.tcl - Vivado non-project batch flow for the area results.
#
# Runs synthesis and (by default) place-and-route at a fixed clock constraint
# and writes utilisation reports scoped to the sign_top instance. The flow
# (retiming, multicycle constraints, S-box ROMs in LUTs) is the one used for
# the paper's numbers.
# Normally called through run_synth.sh, which also supplies the
# per-configuration clock constraint used in the paper.
#
# Usage:
#   vivado -mode batch -source synth_area.tcl -tclargs \
#          <SEC_LEVEL> <PARAM_SET> <HALF_POLY> <OUTDIR> \
#          [MODE=impl] [PERIOD_NS=10.0] [THREADS=2]
#
#   SEC_LEVEL : 1, 3 or 5
#   PARAM_SET : 0 (short) or 1 (fast)
#   HALF_POLY : 0 (HP0) or 1 (HP1)
#   OUTDIR    : output directory for reports
#   MODE      : impl (synthesis + place and route, as in the paper) or
#               synth (stop after synthesis; faster, post-synthesis numbers)
#   PERIOD_NS : clock constraint in ns
#   THREADS   : Vivado threads

if {[llength $argv] < 4} {
    puts "ERROR: usage: vivado -mode batch -source synth_area.tcl -tclargs\
          <SEC_LEVEL> <PARAM_SET> <HALF_POLY> <OUTDIR> \[MODE\] \[PERIOD_NS\] \[THREADS\]"
    exit 1
}

set SEC_LEVEL [lindex $argv 0]
set PARAM_SET [lindex $argv 1]
set HALF_POLY [lindex $argv 2]
set OUTDIR    [file normalize [lindex $argv 3]]
set MODE      [expr {[llength $argv] >= 5 ? [lindex $argv 4] : "impl"}]
set PERIOD    [expr {[llength $argv] >= 6 ? double([lindex $argv 5]) : 10.0}]
set THREADS   [expr {[llength $argv] >= 7 ? [lindex $argv 6] : 2}]

if {$MODE ne "impl" && $MODE ne "synth"} {
    puts "ERROR: MODE must be 'impl' or 'synth', got '$MODE'"
    exit 1
}
set TOP       area_wrapper
set SIGN_CELL u_dut/u_sign

set PART xc7a100tcsg324-3

set SCRIPT_DIR [file dirname [file normalize [info script]]]
set RTL_ROOT   [file normalize "$SCRIPT_DIR/../rtl"]

puts "=========================================="
puts " SDitH sign_top area run"
puts "   SEC_LEVEL = $SEC_LEVEL  PARAM_SET = $PARAM_SET  HALF_POLY = $HALF_POLY"
puts "   MODE      = $MODE"
puts "   PERIOD    = $PERIOD ns"
puts "   PART      = $PART"
puts "   OUTDIR    = $OUTDIR"
puts "   Vivado    = [version -short]"
puts "=========================================="

file mkdir $OUTDIR

create_project -in_memory -part $PART
set_param general.maxThreads $THREADS
catch {set_param general.usePosixSpawnForFork 1}
# WebTalk and host-info collection can crash Vivado 2024+ on recent Linux
# distributions after route_design; none of it is needed here.
catch {config_webtalk -user off}
catch {config_webtalk -install off}
catch {set_param general.enableWebtalk 0}
catch {set_param labtools.enable_cs_server false}

read_verilog -library xil_defaultlib -sv [list \
    "$RTL_ROOT/sdith_params_pkg.sv" \
    "$RTL_ROOT/sdith_helpers_pkg.sv" \
    "$RTL_ROOT/sign/sign_top.sv" \
    "$RTL_ROOT/sign/sign.sv" \
    "$RTL_ROOT/sign/implement_sign_top.sv" \
    "$RTL_ROOT/sign/blc_commit_phase12.sv" \
    "$RTL_ROOT/sign/blc_commit_phase12_hcom.sv" \
    "$RTL_ROOT/sign/blc_commit_hlines.sv" \
    "$RTL_ROOT/sign/blc_racc_combined.sv" \
    "$RTL_ROOT/sign/gen_rbase.sv" \
    "$RTL_ROOT/sign/get_leaf_combined.sv" \
    "$RTL_ROOT/sign/get_leaf_combined_nohcom.sv" \
    "$RTL_ROOT/sign/generate_pwit_chunk.sv" \
    "$RTL_ROOT/sign/generate_pwit_half.sv" \
    "$RTL_ROOT/sign/transpose_pwit.sv" \
    "$RTL_ROOT/sign/process_pwit.sv" \
    "$RTL_ROOT/sign/piop.sv" \
    "$RTL_ROOT/sign/open_rand_eval/blc_open_rand_eval.sv" \
    "$RTL_ROOT/sign/open_rand_eval/estimate_topen.sv" \
    "$RTL_ROOT/sign/open_rand_eval/full_ggm_tree_get_leaf_seed_commit.sv" \
    "$RTL_ROOT/sign/open_rand_eval/insertion_sort.sv" \
    "$RTL_ROOT/common/rijndael/rijndael_encrypt.sv" \
    "$RTL_ROOT/common/rijndael/rijndael_round.sv" \
    "$RTL_ROOT/common/rijndael/rijndael_addroundkey.sv" \
    "$RTL_ROOT/common/rijndael/rijndael_subbytes.sv" \
    "$RTL_ROOT/common/rijndael/rijndael_sbox.sv" \
    "$RTL_ROOT/common/rijndael/rijndael_shiftrows.sv" \
    "$RTL_ROOT/common/rijndael/rijndael_mixcolumns.sv" \
    "$RTL_ROOT/common/rijndael/rijndael_keyschedule.sv" \
    "$RTL_ROOT/common/rijndael/rijndael_keyschedulestep.sv" \
    "$RTL_ROOT/common/var_bram.sv" \
    "$RTL_ROOT/common/gf/gf_mul_serial.sv" \
    "$SCRIPT_DIR/area_wrapper.sv" \
]

read_verilog -library xil_defaultlib [list \
    "$RTL_ROOT/common/mem_single.v" \
    "$RTL_ROOT/common/mem_dual.v" \
    "$RTL_ROOT/common/shake/shake_top.v" \
    "$RTL_ROOT/common/shake/keccak_top.v" \
    "$RTL_ROOT/common/shake/keccak_round.v" \
    "$RTL_ROOT/common/shake/keccak_round_constants_gen.v" \
]

# CACHE_DEPTH and HCOM_IN_PHASE12 keep their package defaults (paper setting)
# unless overridden through the environment.
set defs "SEC_LEVEL=$SEC_LEVEL PARAM_SET=$PARAM_SET HALF_POLY=$HALF_POLY"
if {[info exists ::env(CACHE_DEPTH)] && $::env(CACHE_DEPTH) ne ""} {
    append defs " CACHE_DEPTH=$::env(CACHE_DEPTH)"
}
if {[info exists ::env(HCOM_IN_PHASE12)] && $::env(HCOM_IN_PHASE12) ne ""} {
    append defs " HCOM_IN_PHASE12=$::env(HCOM_IN_PHASE12)"
}
set_property verilog_define $defs [current_fileset]
puts "Defines: $defs"

# Constraints: clock, AES S-box ROMs in LUTs (not BRAM), no I/O timing.
# The ROM_STYLE line is needed during synthesis: without it Vivado maps some
# key-schedule S-boxes to BRAM despite the attribute in rijndael_sbox.sv.
# When the constraints are re-applied after synthesis the ROM cells no longer
# exist, which produces one expected CRITICAL WARNING [Common 17-55].
set xdc_file "$OUTDIR/area.xdc"
set fp [open $xdc_file w]
puts $fp "create_clock -period $PERIOD -name clk \[get_ports clk_i\]"
puts $fp {set_property ROM_STYLE distributed [get_cells -hierarchical *sbox_lut*]}
puts $fp {set_false_path -from [all_inputs]}
puts $fp {set_false_path -to [all_outputs]}
close $fp
read_xdc $xdc_file

synth_design -top $TOP -part $PART -retiming

# Multicycle constraints. The AES retry mechanism in get_leaf_combined
# guarantees that paths from the listed control/index registers to the AES
# state registers have two clock cycles (the index registers settle during the
# retry cycle, the AES then fires from the registered values). Patterns use
# '*' before state_reg to match Vivado's FSM encoding renames; only flip-flop
# primitives are selected.
set mcp_srcs [list \
    *leaf_base_reg* \
    *u_hlines/*state_reg* \
    *u_phase12/*state_reg* \
    *u_piop/*state_reg* \
    *u_piop/*pair_cnt_reg* \
    *u_piop/*acc_half_reg* \
    *u_piop/*e_cnt_reg* \
    *u_piop/*acc_w_reg* \
    *u_piop/*scat_idx_reg* \
    *u_gen_rbase/*state_reg* \
    *u_gen_rbase/leaf_acc_reg* \
    *u_gen_rbase/racc_prefired_reg* \
    *u_gen_rbase/i_reg* \
    *u_hlines/pr_row_r_reg* \
    *u_piop/*col_reg_reg* \
    *u_piop/*clr_cnt_reg* \
]
set mcp_dsts [list \
    *rijndael_state_reg* \
    *round_counter_reg* \
    gen_aes*/*FSM*state_reg* \
    *keyschedule/keystate_reg* \
]
set mcp_count 0
foreach src_pat $mcp_srcs {
    set src_cells [get_cells -hier -filter "NAME =~ $src_pat && REF_NAME =~ FD*" -quiet]
    if {[llength $src_cells] == 0} { continue }
    foreach dst_pat $mcp_dsts {
        set dst_cells [get_cells -hier -filter "NAME =~ $dst_pat && REF_NAME =~ FD*" -quiet]
        if {[llength $dst_cells] == 0} { continue }
        set dst_pins [get_pins -of $dst_cells -filter "DIRECTION == IN && !IS_CLOCK" -quiet]
        if {[llength $dst_pins] == 0} { continue }
        set_multicycle_path 2 -setup -from $src_cells -to $dst_pins
        set_multicycle_path 1 -hold  -from $src_cells -to $dst_pins
        incr mcp_count
    }
}
puts "Applied $mcp_count multicycle constraints"

if {$MODE eq "impl"} {
    opt_design
    place_design
    phys_opt_design
    phys_opt_design -retime
    route_design
}

set sign_cell [get_cells -quiet $SIGN_CELL]
if {[llength $sign_cell] == 0} {
    puts "ERROR: cell $SIGN_CELL not found in the netlist"
    exit 1
}

report_utilization -cells $sign_cell \
    -file "$OUTDIR/sign_top_utilization.rpt"
report_utilization -cells $sign_cell -hierarchical -hierarchical_depth 1 \
    -file "$OUTDIR/sign_top_utilization_hier_top.rpt"
report_utilization -cells $sign_cell -hierarchical \
    -file "$OUTDIR/sign_top_utilization_hier_full.rpt"
report_utilization -file "$OUTDIR/full_design_utilization.rpt"

set fp [open "$OUTDIR/run_info.txt" w]
puts $fp "vivado=[version -short]"
puts $fp "part=$PART"
puts $fp "sec_level=$SEC_LEVEL"
puts $fp "param_set=$PARAM_SET"
puts $fp "half_poly=$HALF_POLY"
puts $fp "mode=$MODE"
puts $fp "period_ns=$PERIOD"
puts $fp "defines=$defs"
close $fp

puts "=========================================="
puts " DONE. Reports in $OUTDIR"
puts "=========================================="
exit 0
