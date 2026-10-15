# SPDX-FileCopyrightText: 2026 Stef Halmans, Niklas Höher
# SPDX-License-Identifier: LicenseRef-RUB-SecEng

export TOPLEVEL_LANG = verilog
export SIM = verilator
WAVES ?= 0
export WAVES
MAKEFLAGS += -j8

# Security level and parameter set overrides (optional)
# Usage: make sign_kat SEC_LEVEL=3 PARAM_SET=0 HALF_POLY=1 KAT_COUNT=1
SEC_LEVEL ?=
PARAM_SET ?=
HCOM_IN_PHASE12 ?=
HALF_POLY ?=
CACHE_DEPTH ?=

# Verilator uses spin-waiting for --threads, so parallel runs will
# starve each other. Use SIM_THREADS=1 when running multiple configs.
SIM_THREADS ?= 8

EXTRA_ARGS = --threads $(SIM_THREADS) \
             --output-split 20000 \
             --output-split-cfuncs 5000 \
             -Wno-WIDTH -Wno-UNOPTFLAT -Wno-UNSIGNED -Wno-UNDRIVEN \
             -Wno-PINMISSING -Wno-CASEINCOMPLETE -Wno-CASEOVERLAP \
             -Wno-LATCH -Wno-UNOPTTHREADS

ifdef SEC_LEVEL
EXTRA_ARGS += -DSEC_LEVEL=$(SEC_LEVEL)
export SEC_LEVEL
endif
ifdef PARAM_SET
EXTRA_ARGS += -DPARAM_SET=$(PARAM_SET)
export PARAM_SET
endif
ifdef HCOM_IN_PHASE12
EXTRA_ARGS += -DHCOM_IN_PHASE12=$(HCOM_IN_PHASE12)
export HCOM_IN_PHASE12
endif
ifdef HALF_POLY
EXTRA_ARGS += -DHALF_POLY=$(HALF_POLY)
export HALF_POLY
endif
ifdef CACHE_DEPTH
EXTRA_ARGS += -DCACHE_DEPTH=$(CACHE_DEPTH)
export CACHE_DEPTH
endif

# Build directory suffix incorporating parameter overrides
_SEC_TAG = $(if $(SEC_LEVEL),_s$(SEC_LEVEL),)
_PAR_TAG = $(if $(PARAM_SET),_p$(PARAM_SET),)
_HC_TAG  = $(if $(HCOM_IN_PHASE12),_h$(HCOM_IN_PHASE12),)
_HP_TAG  = $(if $(HALF_POLY),_hp$(HALF_POLY),)
_CD_TAG  = $(if $(CACHE_DEPTH),_cd$(CACHE_DEPTH),)
_KS_TAG  = $(if $(KAT_START),_k$(KAT_START),)
_CFG_TAG = $(_SEC_TAG)$(_PAR_TAG)$(_HC_TAG)$(_HP_TAG)$(_CD_TAG)$(_KS_TAG)

BUILD_ARGS = OPT_FAST="-O1 -fstrict-aliasing"

ifeq ($(WAVES),1)
EXTRA_ARGS += --trace --trace-fst --trace-structs \
              --trace-depth 10 --trace-max-array 10 \
              --trace-threads 1
endif

SOURCES = \
    $(shell find ../../common/rijndael -name "*.sv" -o -name "*.svh" -o -name "*.v") \
    $(shell find ../../common/shake    -name "*.sv" -o -name "*.svh" -o -name "*.v") \
    ../../sdith_params_pkg.sv \
    ../../sdith_helpers_pkg.sv \
    ../../common/mem_dual.v \
    ../../common/mem_single.v \
    ../../common/var_bram.sv \
    ../../common/gf/gf_mul_serial.sv \
    ../get_leaf_combined.sv \
    ../get_leaf_combined_nohcom.sv \
    ../blc_racc_combined.sv \
    ../blc_commit_phase12.sv \
    ../blc_commit_phase12_hcom.sv \
    ../blc_commit_hlines.sv \
    ../sign.sv \
    ../generate_pwit_chunk.sv \
    ../generate_pwit_half.sv \
    ../transpose_pwit.sv \
    ../process_pwit.sv \
    ../piop.sv \
    ../open_rand_eval/blc_open_rand_eval.sv \
    ../open_rand_eval/full_ggm_tree_get_leaf_seed_commit.sv \
    ../open_rand_eval/estimate_topen.sv \
    ../open_rand_eval/insertion_sort.sv \
    ../gen_rbase.sv \
    ../sign_top.sv \
    ../implement_sign_top.sv \
    ./test_sign.sv

# sign_kat: reuse test_sign.sv wrapper with KAT-based cocotb test
CUSTOM_TOPLEVEL_sign_kat = test_sign

# KAT test configuration (pass through to cocotb env)
KAT_COUNT ?=
KAT_START ?=
ifdef KAT_COUNT
export KAT_COUNT
endif
ifdef KAT_START
export KAT_START
endif

TARGETS = sign_kat

# Helper: resolve module name (use custom if defined, else default pattern)
module_for = $(or $(CUSTOM_MODULE_$1),test_test_$1)
# Helper: resolve toplevel name
toplevel_for = $(or $(CUSTOM_TOPLEVEL_$1),test_$1)

.PHONY: all $(TARGETS) clean

all: sign_kat

$(TARGETS):
	@mkdir -p logs
	$(MAKE) \
	    TOPLEVEL=$(call toplevel_for,$@) \
	    MODULE=$(call module_for,$@) \
	    SIM_BUILD=sim_build_$@$(_CFG_TAG) \
	    COCOTB_RESULTS_FILE=results_$@$(_CFG_TAG).xml \
	    SIM_ARGS="$(if $(filter 1,$(WAVES)),--trace-file dump_$@$(_CFG_TAG).fst)" \
	    BUILD_ARGS='$(BUILD_ARGS)' \
	    EXTRA_ARGS="$(EXTRA_ARGS)" \
	    VERILOG_SOURCES="$(SOURCES)" \
	    -f $(shell cocotb-config --makefiles)/Makefile.sim

clean:
	rm -rf sim_build_*/ \
	       obj_dir/ \
	       __pycache__/ \
	       results.xml results_*.xml \
	       *.vcd *.fst \
	       *.log *.out \
	       .verilator* \
	       coverage.dat
