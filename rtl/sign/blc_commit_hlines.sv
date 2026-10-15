// SPDX-FileCopyrightText: 2026 Stef Halmans, Niklas Höher
// SPDX-License-Identifier: LicenseRef-RUB-SecEng

import sdith_params_pkg::*;
import sdith_helpers_pkg::*;

// blc_commit_hlines
//
// BLC.Commit.Hlines ("BLC phase 3"): second pass of the BLC commit split,
// producing alpha_plain, alpha_base, P_0, dwit, and h_lines.
//
// Per repetition e, gen_rbase rebuilds the r_base columns (Haux shadow
// copies skipped), then:
//   - P0: CZ slices accumulate straight into the P_alpha sig slots (no P_rnd storage)
//   - xi multiply as Horner shift-XOR: gf_mul_x per column, gf_mul_xK per repetition
//   - ProcessRbase: row inner products with r_base -> alpha_base (row-major in scratchpad)
//   - M re-expanded from SHAKE(h_aux) every repetition instead of stored
//   - e=0 pass also folds u into alpha_plain (cchk_u), saving one M expansion
//   - dwit = wit XOR u_wit (circuit_in_pub), key memory -> signature
//
// h_lines = SHAKE(0x03 || h_aux || alpha_plain || alpha_base || dwit)
// is squeezed into hlines_o for the PIOP stage.

module blc_commit_hlines (
    input logic clk_i,
    input logic rst_i,
    input logic var_stall_i,
    input logic fsm_enable_i,

    // haux read from var BRAM at HAUX_VAR_OFFSET

    output logic fsm_done_o,
    output logic [2*LAMBDA-1:0] hlines_o,

    // Gen_rbase control (to external gen_rbase via sign.sv mux)
    output logic                                  gr_start_o,
    output logic [$clog2(TAU+1)-1:0]              gr_e_o,
    output logic [VAR_ADDR_WIDTH_COMBINED-1:0]    gr_rbase_base_o,
    output logic [BRAM_ADDR_SIZE:0]               gr_slot_offset_o,
    output logic                                  gr_build_rbase_o,
    input  logic                                  gr_done_i,

    // SHAKE
    output logic        shake_start_o,
    output logic        shake_mode_o,
    output logic        shake_seed_from_output_o,
    output logic [63:0] shake_din_o,
    output logic        shake_din_valid_o,
    output logic        shake_last_din_o,
    output logic [ 3:0] shake_last_din_byte_o,
    output logic        shake_dout_ready_o,
    input  logic        shake_din_ready_i,
    input  logic [63:0] shake_dout_i,
    input  logic        shake_dout_valid_i,

    // Signature memory
    input  logic [63:0]              sig_data_i,
    output logic [63:0]              sig_data_o,
    output logic [SIG_ADDR_WIDTH-1:0] sig_addr_o,
    output logic                     sig_wr_en_o,

    // Dual-port variable memory
    input  logic [VAR_DATA_WIDTH_COMBINED-1:0] var_a_data_i,
    output logic [VAR_DATA_WIDTH_COMBINED-1:0] var_a_data_o,
    output logic [VAR_ADDR_WIDTH_COMBINED-1:0] var_a_addr_o,
    output logic                               var_a_wr_en_o,

    input  logic [VAR_DATA_WIDTH_COMBINED-1:0] var_b_data_i,
    output logic [VAR_DATA_WIDTH_COMBINED-1:0] var_b_data_o,
    output logic [VAR_ADDR_WIDTH_COMBINED-1:0] var_b_addr_o,
    output logic                               var_b_wr_en_o,

    // Raw BRAM read data (bypasses overflow mux, for identity reads during stall)
    input  logic [VAR_DATA_WIDTH_COMBINED-1:0] var_a_data_bram_i,
    input  logic [VAR_DATA_WIDTH_COMBINED-1:0] var_b_data_bram_i,

    // Key memory (read-only, for wit)
    input  logic [63:0]              key_data_i,
    output logic [BRAM_ADDR_SIZE:0]  key_addr_o,

    // Cache BRAM (for rbase[KAPPA-1], haux when USE_CACHE_OVERFLOW)
    input  logic [63:0]             cache_data_i,
    output logic [63:0]             cache_data_o,
    output logic [CACHE_ADDR_WIDTH-1:0] cache_addr_o,
    output logic                    cache_wr_en_o,
    output logic                    cache_active_o  // 1 = this module owns cache (not leaf_combined)
);
  // Local parameters

  localparam CAN_DUAL = CAN_DUAL_COMBINED;
  localparam USE_CACHE = USE_CACHE_OVERFLOW;

  // Dwit extraction from u vector (at var memory slot 0)
  // wit portion starts after cchk and cz pairs: u[cchk+cz : cchk+cz+wit]
  localparam DWIT_START_BIT       = NUM_CCHK_PAIRS + NUM_CZ_PAIRS;
  localparam DWIT_START_WORD      = DWIT_START_BIT / 64;
  localparam DWIT_BIT_OFFSET      = DWIT_START_BIT % 64;
  localparam WIT_WORDS            = (WIT_SIZE + 63) / 64;
  localparam WIT_BYTES            = (WIT_SIZE + 7) / 8;
  localparam WIT_LAST_VALID_BITS  = WIT_SIZE - (WIT_WORDS - 1) * 64;
  localparam [63:0] WIT_LAST_MASK = (WIT_LAST_VALID_BITS == 64) ?
      64'hFFFFFFFF_FFFFFFFF : ((64'h1 << WIT_LAST_VALID_BITS) - 1);
  localparam WIT_LAST_WORD_BYTES  = (WIT_BYTES % 8 == 0) ? 8 : (WIT_BYTES % 8);

  // Alpha column geometry
  localparam ALPHA_LAST_BITS      = ALPHA_COL_BITS - (ALPHA_COL_WORDS - 1) * 64;
  localparam ALPHA_LAST_BYTES     = ALPHA_LAST_BITS / 8;
  localparam ALPHA_COL_BYTES      = ALPHA_COL_BITS / 8;

  // Row-major alpha_base geometry
  localparam ALPHA_BASE_COLS          = TAU * KAPPA;
  localparam ALPHA_BASE_WORDS_PER_ROW = (ALPHA_BASE_COLS + 63) / 64;
  localparam ALPHA_BASE_TOTAL_WORDS   = ALPHA_COL_BITS * ALPHA_BASE_WORDS_PER_ROW;
  localparam ALPHA_BASE_VAR_OFFSET    = ALPHA_VAR_OFFSET;
  localparam ALPHA_TOTAL_WORDS        = ALPHA_BASE_TOTAL_WORDS;
  localparam ALPHA_BASE_LAST_COL_BITS = ALPHA_BASE_COLS % 64;
  localparam ALPHA_BASE_LAST_COL_BYTES = (ALPHA_BASE_LAST_COL_BITS == 0) ? 8 :
      (ALPHA_BASE_LAST_COL_BITS + 7) / 8;

  // Gen_rbase offset storage parameters
  localparam ALPHA_COL_BITS_L = LAMBDA + B;
  localparam M_WORD_OFFSET    = ALPHA_COL_BITS_L / 64;
  localparam M_BIT_OFFSET     = ALPHA_COL_BITS_L % 64;
  localparam RBASE_PARTS_OFFSET_L = R_ACC_PARTS + 1;

  // Alpha data lives in var memory after the rbase columns stored in var.
  // When USE_CACHE: rbase[KAPPA-1] is in cache BRAM, so only RBASE_VAR_COLS columns in var.
  localparam ALPHA_VAR_OFFSET = RBASE_OFFSET + RBASE_VAR_COLS * RBASE_PARTS_OFFSET_L;

  // Precomputed rbase: shadow base offset per e value
  localparam PRECOMP = NUM_PRECOMP_E;

  // Process_rbase parameters
  // Use byte-rounded R_ACC_SIZE to match C reference (par.L = mult of 8)
  localparam ELL              = R_ACC_SIZE_ROUND - ALPHA_COL_BITS_L;
  localparam ELL_WORDS        = (ELL + 63) / 64;
  localparam ELL_LAST_BITS    = ELL - (ELL_WORDS - 1) * 64;
  localparam [63:0] ELL_LAST_MASK = (ELL_LAST_BITS == 64) ?
      64'hFFFFFFFF_FFFFFFFF : ((64'h1 << ELL_LAST_BITS) - 1);
  localparam M_WORD_OFFSET_OS = M_WORD_OFFSET + 1;
  localparam BUF_WIDTH        = 128;
  localparam PREV_WORD_BITS   = 64 - M_BIT_OFFSET;

  // hash_lines total absorbed bytes = 1 (prefix) + 2*LAMBDA/8 (haux) +
  //   ALPHA_COL_BITS/8 (cchk_u/alpha_plain) + ALPHA_COL_BITS * LAMBDA/8 (cchk_res_v) + WIT_BYTES (circuit_in_pub)
  localparam HLINES_CCHK_U_BYTES  = ALPHA_COL_BITS / 8;
  localparam HLINES_CCHK_V_BYTES  = ALPHA_COL_BITS * (LAMBDA / 8);
  localparam HLINES_TOTAL_BYTES   = 1 + 2*(LAMBDA/8) + HLINES_CCHK_U_BYTES + HLINES_CCHK_V_BYTES + WIT_BYTES;
  localparam HLINES_LAST_DIN_BYTE = (HLINES_TOTAL_BYTES % 8 == 0) ? 4'd8 : 4'(HLINES_TOTAL_BYTES % 8);

  // P0 parameters
  localparam P0_LW         = (LAMBDA + 63) / 64;   // words per GF element
  localparam P0_NS         = DEGREE - 1;            // 3 CZ slices
  // P0 stored in sig_mem at PALPHA_SIG_OFFSET in CST order: cst[k] = P0[DEGREE-1-k]
  // CZ slices are word-aligned in shifted rbase layout: start at word M_WORD_OFFSET+1
  localparam P0_CZ_WORD_START = M_WORD_OFFSET + 1;  // = 3 for SEC1
  // Scratchpad helpers (bswap64, phys_a, phys_b, split_a, split_b from sdith_helpers_pkg)

  // Combine dual-port var reads into one 64-bit logical word
  function automatic [63:0] combine_ab;
    if (CAN_DUAL) return 64'(var_a_data_i);
    else          return {var_b_data_i, var_a_data_i};
  endfunction

  // Raw BRAM combine (bypasses overflow mux, for identity reads during RAMB18 stall)
  function automatic [63:0] combine_ab_bram;
    if (CAN_DUAL) return 64'(var_a_data_bram_i);
    else          return {var_b_data_bram_i, var_a_data_bram_i};
  endfunction

  // For CAN_DUAL=0 bit-level writes: physical addr of the 32-bit half holding bit_idx
  function automatic [VAR_ADDR_WIDTH_COMBINED-1:0] phys_half(
      input [VAR_ADDR_WIDTH_COMBINED-1:0] logical_addr, input [5:0] bit_idx);
    if (CAN_DUAL) return VAR_ADDR_WIDTH_COMBINED'(logical_addr);
    else          return VAR_ADDR_WIDTH_COMBINED'({logical_addr, bit_idx[5]});
  endfunction

  // State definition

  typedef enum logic [5:0] {
    S_IDLE,
    // Gen_rbase wait state (external gen_rbase module)
    S_WAIT_GR,
    // Process_rbase states
    S_PR_SHAKE_START,
    S_PR_SHAKE_ABSORB,
    S_PR_SHAKE_PRIME,
    S_PR_INIT_ALPHA,
    S_PR_PRIME_U_RD,
    S_PR_PRIME_U_LATCH,
    S_PR_SQUEEZE_CHUNK,
    S_PR_PROCESS_COL,
    S_PR_BATCH_ID_RD,
    S_PR_BATCH_ALPHA_WR,
    S_PR_WRITE_U_RD,
    S_PR_WRITE_U_LATCH,
    S_PR_WRITE_U_WR,
    // P0 multiply states
    S_P0_INIT,       // initialize P0 in sig_mem (e=0 only)
    S_P0_RD,         // read CZ word from rbase column (Horner)
    S_P0_ACC,        // Horner accumulate: gf_mul_x(acc) ^ cz
    S_P0_SHIFT,      // sequential gf_mul_xK shift (e times)
    S_P0_P0RD,       // read P0[sj][w] from sig_mem
    S_P0_P0WR,       // XOR shifted result + write P0[sj][w] to sig_mem
    // Dwit states
    S_DWIT_PRIME,
    S_DWIT_RD,
    S_DWIT_COMPUTE,
    // Hash states
    S_HASH_START,
    S_HASH_HAUX,
    S_HASH_HAUX_PRIME,
    S_HASH_PLAIN_PRIME,
    S_HASH_PLAIN_FEED,
    S_HASH_BASE_PRIME,
    S_HASH_BASE_FEED,
    S_HASH_DWIT_PRIME,
    S_HASH_DWIT_FEED,
    S_HASH_DRAIN,
    S_HASH_SQUEEZE,
    // Done
    S_DONE
  } fsm_state_t;

  fsm_state_t state, next_state;
  // Registers: outer loop

  localparam E_WIDTH = $clog2(TAU + 1);
  logic [E_WIDTH-1:0] e, next_e;
  // e_times_kappa: registered product to avoid runtime multiply in pr_alpha_col
  logic [$clog2(ALPHA_BASE_COLS)-1:0] e_times_kappa, next_e_times_kappa;
  // rbase_base: base address for rbase columns (RBASE_OFFSET or shadow offset)
  logic [VAR_ADDR_WIDTH_COMBINED-1:0] rbase_base, next_rbase_base;
  // Registers: gen_rbase interface (shared with P0 Horner computation)

  logic [$clog2(KAPPA)-1:0] gr_j_reg, next_gr_j_reg;
  logic [VAR_ADDR_WIDTH_COMBINED-1:0] gr_j_col_base, next_gr_j_col_base;
  logic [$clog2(RBASE_PARTS_OFFSET_L+1)-1:0] gr_w, next_gr_w;
  logic [1:0] gr_xor_phase, next_gr_xor_phase;
  logic [63:0] gr_r_acc_val, next_gr_r_acc_val;

  // Dual-purpose: P0 Horner accumulator (upper half of hlines_o)
  logic [LAMBDA-1:0] leaf_buf, next_leaf_buf;
  logic              leaf_buf_valid, next_leaf_buf_valid;
  // Registers: process_rbase (inlined)

  logic [$clog2(ALPHA_COL_BITS_L+1)-1:0] pr_row_r, next_pr_row_r;
  logic [4:0]                       pr_chunk_c,   next_pr_chunk_c;
  logic [VAR_ADDR_WIDTH_COMBINED-1:0] pr_chunk_offset_r;
  logic [$clog2(KAPPA+2)-1:0]      pr_col_k,     next_pr_col_k;
  logic [VAR_ADDR_WIDTH_COMBINED-1:0] pr_col_base_addr_r, next_pr_col_base_addr_r;
  logic [$clog2(2*LAMBDA_DIV_64+1)-1:0] pr_absorb_w, next_pr_absorb_w;  // widened to share with haux_w/squeeze_w
  logic [$clog2(ALPHA_TOTAL_WORDS+1)-1:0] pr_init_ctr, next_pr_init_ctr;
  logic [PREV_WORD_BITS-1:0]       pr_prev_word_u, next_pr_prev_word_u;
  logic [63:0]                      pr_m_chunk, next_pr_m_chunk;
  logic [KAPPA:0]                   pr_acc, next_pr_acc;
  logic [BUF_WIDTH-1:0]            pr_shake_buf, next_pr_shake_buf;
  logic [$clog2(BUF_WIDTH+1)-1:0]  pr_buf_valid, next_pr_buf_valid;
  // Registers: dwit

  // dwit_k aliased to pr_init_ctr - non-overlapping phases (e=0 init vs dwit after all e)
  wire [$clog2(WIT_WORDS+1)-1:0] dwit_k = pr_init_ctr[$clog2(WIT_WORDS+1)-1:0];
  // prev_u aliased to pr_m_chunk - non-overlapping phases (process_rbase vs dwit), both 64 bits
  wire [63:0] prev_u = pr_m_chunk;
  // Registers: hash

  // haux_w aliased to pr_absorb_w - non-overlapping phases (hash vs process_rbase)
  wire [$clog2(2*LAMBDA_DIV_64+1)-1:0] haux_w = pr_absorb_w;
  localparam HASH_AW_MAX = (ALPHA_COL_WORDS > ALPHA_BASE_WORDS_PER_ROW) ?
      ALPHA_COL_WORDS : ALPHA_BASE_WORDS_PER_ROW;
  logic [$clog2(ALPHA_COL_BITS+1)-1:0] hash_vec, next_hash_vec;
  logic [$clog2(HASH_AW_MAX+1)-1:0]  hash_aw,  next_hash_aw;
  logic [$clog2(WIT_WORDS+1)-1:0]        hash_dw,  next_hash_dw;
  // hash_pack_buf/cnt aliased to pr_shake_buf/pr_buf_valid (non-overlapping phases, saves 60 FFs)
  wire [55:0] hash_pack_buf = pr_shake_buf[55:0];
  wire [3:0]  hash_pack_cnt = pr_buf_valid[3:0];
  // squeeze_w aliased to pr_absorb_w - non-overlapping phases (hash vs process_rbase)
  wire [$clog2(2*LAMBDA_DIV_64+1)-1:0] squeeze_w = pr_absorb_w;
  // hlines_reg halved: lower LAMBDA bits for working data / CZ assembly.
  // leaf_buf serves as Horner accumulator during P0 and upper squeeze target during hash.
  logic [LAMBDA-1:0] hlines_reg, next_hlines_reg;
  assign hlines_o = {leaf_buf, hlines_reg};
  // P0: GF(2^LAMBDA) sequential shift-multiply functions

  // Multiply by x (shift left 1, reduce). 1 LUT level, ~8 active bits.
  function automatic logic [LAMBDA-1:0] gf_mul_x(input logic [LAMBDA-1:0] v);
    return (v << 1) ^ (v[LAMBDA-1] ? LAMBDA'(GF_POLY) : '0);
  endfunction

  // Multiply by x^KAPPA (shift left KAPPA, reduce). ~2 LUT levels, ~22 active bits.
  function automatic logic [LAMBDA-1:0] gf_mul_xK(input logic [LAMBDA-1:0] v);
    logic [KAPPA-1:0] overflow;
    logic [KAPPA+GF_POLY_DEGREE-1:0] prod;
    overflow = v[LAMBDA-1:LAMBDA-KAPPA];
    prod = '0;
    for (int b = 0; b <= GF_POLY_DEGREE; b++) begin
      if (GF_POLY[b])
        prod = prod ^ ({GF_POLY_DEGREE'(0), overflow} << b);
    end
    // KAPPA+GF_POLY_DEGREE <= 22 < LAMBDA: no second-level reduction needed
    return {v[LAMBDA-KAPPA-1:0], KAPPA'(0)} ^ LAMBDA'(prod);
  endfunction

  // Pre-computed Horner step (shared across S_P0_ACC branches)
  wire [LAMBDA-1:0] p0_horner_step = gf_mul_x(leaf_buf) ^ hlines_reg;

  // P0: address helpers (reuse gr_j_reg as column, gr_xor_phase as slice, gr_w as word)
  wire [VAR_ADDR_WIDTH_COMBINED-1:0] p0_cz_addr =
      gr_j_col_base + VAR_ADDR_WIDTH_COMBINED'(
                               P0_CZ_WORD_START + gr_xor_phase * P0_LW + gr_w);
  // P0 sig_mem address: hardware P0 is STD order (leading first), signature
  // needs CST order (constant first), so mirror: cst[k] = std[DEGREE-1-k].
  // During RMW, gr_xor_phase=slice index (0..2) maps to P0[slice].
  wire [SIG_ADDR_WIDTH-1:0] p0_sig_addr =
      (SIG_ADDR_WIDTH)'(PALPHA_SIG_OFFSET + (DEGREE - 1 - gr_xor_phase) * P0_LW + gr_w);
  // During S_P0_INIT, flat gr_w spans all DEGREE*P0_LW words.
  // element = gr_w / P0_LW, word_in_elem = gr_w % P0_LW.
  // Mirrored sig address: PALPHA_SIG_OFFSET + (DEGREE-1-element)*P0_LW + word_in_elem.
  wire [31:0] p0_init_elem_w   = 32'(gr_w) / 32'(P0_LW);
  wire [31:0] p0_init_word_w   = 32'(gr_w) - p0_init_elem_w * 32'(P0_LW);
  wire [SIG_ADDR_WIDTH-1:0] p0_init_sig_addr =
      (SIG_ADDR_WIDTH)'(PALPHA_SIG_OFFSET + (32'(DEGREE) - 32'd1 - p0_init_elem_w) * 32'(P0_LW)
                        + p0_init_word_w);
  // Process_rbase: helpers

  logic [$clog2(KAPPA+2)-1:0] pr_n_vecs;
  assign pr_n_vecs = (e == 0) ? ($clog2(KAPPA+2))'(KAPPA + 1)
                               : ($clog2(KAPPA+2))'(KAPPA);

  logic [63:0] pr_shake_word_le;
  assign pr_shake_word_le = bswap64(shake_dout_i);

  // Pre-computed SHAKE prefetch (shared barrel shifter across 7 process_rbase states)
  // Byte-aligned shift: pr_buf_valid is always a multiple of 8 during process_rbase
  wire shake_pf_ok = (pr_buf_valid <= ($clog2(BUF_WIDTH+1))'(64));
  wire [BUF_WIDTH-1:0] shake_pf_buf = pr_shake_buf
      | (BUF_WIDTH'(pr_shake_word_le) << {pr_buf_valid[$clog2(BUF_WIDTH+1)-1:3], 3'b0});
  wire [$clog2(BUF_WIDTH+1)-1:0] shake_pf_valid = pr_buf_valid
      + ($clog2(BUF_WIDTH+1))'(64);

  // Base address for rbase column pr_col_k (registered - breaks carry chain on critical path)
  wire [VAR_ADDR_WIDTH_COMBINED-1:0] pr_col_base_addr = pr_col_base_addr_r;

  logic pr_is_u_vec;
  assign pr_is_u_vec = (pr_col_k >= ($clog2(KAPPA+2))'(KAPPA));

  // Shadow rbase: disable dual-column reads only when the shadow's last column
  // extends into the non-dual-port upper BRAM region. Shadows fully within the
  // dual-pair region get normal dual-column speed.
  localparam VAR_DUAL_PORT_DEPTH = (VAR_DATA_WIDTH_COMBINED == 32)
      ? BRAM_TDP_DEPTH_32 : (VAR_NUM_BRAMS_COMBINED / 2) * BRAM_TDP_DEPTH_32;
  wire shadow_active = (PRECOMP > 0)
      && (rbase_base != VAR_ADDR_WIDTH_COMBINED'(RBASE_OFFSET))
      && ((rbase_base + VAR_ADDR_WIDTH_COMBINED'(RBASE_SHADOW_STRIDE))
          > VAR_ADDR_WIDTH_COMBINED'(VAR_DUAL_PORT_DEPTH));

  // Pre-computed comparison flags for S_PR_PROCESS_COL (avoids repeated comparisons)
  wire pr_col_k_lt_kappa   = (pr_col_k < ($clog2(KAPPA+2))'(KAPPA));
  wire pr_col_k_all_done   = (pr_col_k >= ($clog2(KAPPA+2))'(pr_n_vecs));
  wire pr_can_dual_pair    = CAN_DUAL && !shadow_active && (pr_col_k >= 2)
                           && !pr_col_k[0]
                           && (pr_col_k - 2 < ($clog2(KAPPA+2))'(KAPPA))
                           && (pr_col_k - 1 < ($clog2(KAPPA+2))'(KAPPA));
  wire pr_prev_col_lt_kappa = (pr_col_k >= 1) && (pr_col_k - 1 < ($clog2(KAPPA+2))'(KAPPA));

  // When USE_CACHE, rbase column KAPPA-1 is in cache BRAM at CACHE_RBASE_OFFSET
  wire pr_col_in_cache = USE_CACHE && (pr_col_k == ($clog2(KAPPA+2))'(KAPPA - 1));

  // Previous column was the cached one (pr_col_k already advanced past KAPPA-1)
  wire pr_prev_col_in_cache = USE_CACHE && (pr_col_k == ($clog2(KAPPA+2))'(KAPPA));
  // Factored m-data read for the previous column: cache when it was KAPPA-1, else var
  wire [63:0] pr_prev_col_rd = pr_prev_col_in_cache ? cache_data_i : combine_ab();

  // M-chunk address (var BRAM) - not used when pr_col_in_cache
  logic [VAR_ADDR_WIDTH_COMBINED-1:0] pr_m_chunk_addr;
  always_comb begin
    if (pr_is_u_vec)
      pr_m_chunk_addr = pr_chunk_offset_r;
    else
      pr_m_chunk_addr = pr_col_base_addr + pr_chunk_offset_r;
  end

  // Cache addresses for rbase[KAPPA-1] identity and m-data
  wire [CACHE_ADDR_WIDTH-1:0] pr_cache_identity_addr =
      (CACHE_ADDR_WIDTH)'(CACHE_RBASE_OFFSET + (pr_row_r >> 6));
  wire [CACHE_ADDR_WIDTH-1:0] pr_cache_m_chunk_addr =
      (CACHE_ADDR_WIDTH)'(CACHE_RBASE_OFFSET + M_WORD_OFFSET_OS + pr_chunk_c);

  // Identity word address and bit (var BRAM) - not used when pr_col_in_cache
  logic [VAR_ADDR_WIDTH_COMBINED-1:0] pr_identity_addr;
  logic [5:0]              pr_identity_bit_idx;
  always_comb begin
    pr_identity_addr    = pr_col_base_addr + VAR_ADDR_WIDTH_COMBINED'(pr_row_r >> 6);
    pr_identity_bit_idx = pr_row_r[5:0];
  end

  // SHAKE squeeze needed for current chunk
  logic [$clog2(BUF_WIDTH+1)-1:0] pr_squeeze_needed;
  assign pr_squeeze_needed = (pr_chunk_c == ELL_WORDS - 1)
      ? ($clog2(BUF_WIDTH+1))'(ELL_LAST_BITS)
      : ($clog2(BUF_WIDTH+1))'(64);

  // Row-major alpha_base addressing
  // Row = pr_row_r (0..ALPHA_COL_BITS-1)
  // Column = e * KAPPA + pr_col_k (0..TAU*KAPPA-1) for alpha_base
  logic [$clog2(ALPHA_BASE_COLS)-1:0] pr_alpha_col;
  logic [VAR_ADDR_WIDTH_COMBINED-1:0] pr_alpha_base_addr;
  logic [5:0]                         pr_alpha_base_bit;

  always_comb begin
    pr_alpha_col = ($clog2(ALPHA_BASE_COLS))'(e_times_kappa + pr_col_k);
    pr_alpha_base_addr = VAR_ADDR_WIDTH_COMBINED'(
        ALPHA_BASE_VAR_OFFSET + pr_row_r * ALPHA_BASE_WORDS_PER_ROW + (pr_alpha_col >> 6));
    pr_alpha_base_bit = pr_alpha_col[5:0];
  end

  // Alpha_plain addressing (column-wise, stored in sig BRAM at SIG_CCHK_U_OFFSET)
  logic [SIG_ADDR_WIDTH-1:0] pr_alpha_plain_sig_addr;
  logic [5:0] pr_alpha_plain_bit;
  assign pr_alpha_plain_sig_addr = SIG_ADDR_WIDTH'(SIG_CCHK_U_OFFSET + (pr_row_r >> 6));
  assign pr_alpha_plain_bit = pr_row_r[5:0];

  // Batch alpha_base write addressing (KAPPA bits starting at column e*KAPPA)
  wire [5:0] batch_first_bit = e_times_kappa[5:0];
  wire [VAR_ADDR_WIDTH_COMBINED-1:0] batch_alpha_addr0 = VAR_ADDR_WIDTH_COMBINED'(
      ALPHA_BASE_VAR_OFFSET + pr_row_r * ALPHA_BASE_WORDS_PER_ROW + (e_times_kappa >> 6));
  wire [VAR_ADDR_WIDTH_COMBINED-1:0] batch_alpha_addr1 = batch_alpha_addr0 + 1;
  wire batch_spans = ({1'b0, batch_first_bit} + KAPPA > 64);

  logic [63:0] batch_word0_mask, batch_word1_mask;
  always_comb begin
    batch_word0_mask = 64'(pr_acc[KAPPA-1:0]) << batch_first_bit;
    batch_word1_mask = (batch_first_bit != 0)
        ? (64'(pr_acc[KAPPA-1:0]) >> (7'd64 - {1'b0, batch_first_bit}))
        : '0;
  end

  // Dwit alignment

  logic [63:0] u_aligned;
  generate
    if (DWIT_BIT_OFFSET > 0) begin : g_dwit_shift
      assign u_aligned = (prev_u >> DWIT_BIT_OFFSET)
                        | (combine_ab() << (64 - DWIT_BIT_OFFSET));
    end else begin : g_dwit_no_shift
      assign u_aligned = combine_ab();
    end
  endgenerate
  
  logic [63:0] combined_synt;
  assign combined_synt = combine_ab();

  // Pre-computed hash packing (shared case mux across 4 hash feed states)
  // Each state selects hash_new_data; the case mux is computed once here.
  logic [63:0] hash_new_data;  // set in FSM per state
  logic [119:0] hash_combined;
  always_comb begin
    case (hash_pack_cnt)
      0: hash_combined = {hash_new_data, 56'd0};
      1: hash_combined = {hash_pack_buf[55:48], hash_new_data, 48'd0};
      2: hash_combined = {hash_pack_buf[55:40], hash_new_data, 40'd0};
      3: hash_combined = {hash_pack_buf[55:32], hash_new_data, 32'd0};
      4: hash_combined = {hash_pack_buf[55:24], hash_new_data, 24'd0};
      5: hash_combined = {hash_pack_buf[55:16], hash_new_data, 16'd0};
      6: hash_combined = {hash_pack_buf[55:8],  hash_new_data,  8'd0};
      7: hash_combined = {hash_pack_buf[55:0],  hash_new_data       };
      default: hash_combined = {hash_new_data, 56'd0};
    endcase
  end
  // Internal var memory bus signals (before port assignment)

  logic [63:0]             int_var_a_data, int_var_b_data;
  logic [VAR_ADDR_WIDTH_COMBINED-1:0] int_var_a_addr, int_var_b_addr;
  logic                    int_var_a_wr, int_var_b_wr;

  // Port assignment (translate 64-bit logical to physical)
  always_comb begin
    var_a_data_o  = split_a(int_var_a_data);
    var_a_addr_o  = phys_a(int_var_a_addr);
    var_a_wr_en_o = int_var_a_wr;
    var_b_data_o  = split_b(int_var_b_data);
    var_b_addr_o  = phys_b(int_var_b_addr);
    var_b_wr_en_o = int_var_b_wr;
  end
  // Temporary variables used in FSM combinational logic
  // (declared outside always_comb for Verilator compatibility)

  logic [63:0] _m_chunk_comb, _rbase_chunk, _rbase_chunk2;
  logic        _result_bit;
  logic [63:0] _id_word, _alpha_word;
  logic [63:0] _dwit_word;
  // FSM: Next-state and datapath logic

  always_comb begin
    // Hold all registers by default
    next_state        = state;
    next_e            = e;
    next_e_times_kappa = e_times_kappa;
    next_rbase_base   = rbase_base;

    // Gen_rbase / P0 shared registers
    next_gr_j_reg       = gr_j_reg;
    next_gr_j_col_base  = gr_j_col_base;
    next_gr_w           = gr_w;
    next_gr_xor_phase   = gr_xor_phase;
    next_gr_r_acc_val   = gr_r_acc_val;
    next_leaf_buf       = leaf_buf;
    next_leaf_buf_valid = leaf_buf_valid;

    // Process_rbase registers
    next_pr_row_r       = pr_row_r;
    next_pr_chunk_c     = pr_chunk_c;
    next_pr_col_k       = pr_col_k;
    next_pr_col_base_addr_r = pr_col_base_addr_r;
    next_pr_absorb_w    = pr_absorb_w;
    next_pr_init_ctr    = pr_init_ctr;
    next_pr_m_chunk     = pr_m_chunk;
    next_pr_acc         = pr_acc;
    next_pr_shake_buf   = pr_shake_buf;
    next_pr_buf_valid   = pr_buf_valid;
    next_pr_prev_word_u = pr_prev_word_u;

    // Dwit / hash registers (aliases: see decls)
    next_hash_vec     = hash_vec;
    next_hash_aw      = hash_aw;
    next_hash_dw      = hash_dw;
    next_hlines_reg   = hlines_reg;

    // Control defaults
    fsm_done_o      = 1'b0;
    // Gen_rbase interface
    gr_start_o       = 1'b0;
    gr_e_o           = '0;
    gr_rbase_base_o  = '0;
    gr_slot_offset_o = '0;
    gr_build_rbase_o = 1'b0;

    // SHAKE defaults
    shake_start_o            = 1'b0;
    shake_mode_o             = 1'b0;  // default hash mode; M-generation overrides to XOF
    shake_seed_from_output_o = 1'b0;
    shake_din_o              = 64'b0;
    shake_din_valid_o        = 1'b0;
    shake_last_din_o         = 1'b0;
    shake_last_din_byte_o    = 4'd0;
    shake_dout_ready_o       = 1'b0;

    // Hash pack data default
    hash_new_data = 64'b0;

    // Sig memory defaults
    sig_data_o    = 64'b0;
    sig_addr_o    = '0;
    sig_wr_en_o   = 1'b0;

    // Internal var memory defaults
    int_var_a_data = 64'b0;
    int_var_a_addr = '0;
    int_var_a_wr   = 1'b0;
    int_var_b_data = 64'b0;
    int_var_b_addr = '0;
    int_var_b_wr   = 1'b0;

    // Key memory
    key_addr_o    = '0;

    // Cache BRAM defaults
    cache_data_o  = 64'b0;
    cache_addr_o  = '0;
    cache_wr_en_o = 1'b0;
    // cache_active_o: high when this module needs the cache port
    // During S_WAIT_GR, gen_rbase handles its own cache writes via sign.sv
    cache_active_o = (state != S_IDLE && state != S_WAIT_GR &&
                      state != S_DONE) ? 1'b1 : 1'b0;

    case (state)

      // ========================================================
      S_IDLE: begin
        if (fsm_enable_i) begin
          next_e     = '0;
          next_e_times_kappa = '0;
          next_rbase_base = VAR_ADDR_WIDTH_COMBINED'(RBASE_OFFSET);
          next_gr_w  = 0;
          next_leaf_buf_valid = 1'b0;
          next_state = S_P0_INIT;  // init P0 from u (r_acc slot 0)
        end
      end

      // ========================================================
      // WAIT_GR: Wait for external gen_rbase to complete
      // ========================================================
      S_WAIT_GR: begin
        if (gr_done_i) begin
          // Initialize P0 Horner entry
          next_gr_j_reg     = ($clog2(KAPPA))'(KAPPA - 1);
          next_gr_j_col_base = rbase_base + VAR_ADDR_WIDTH_COMBINED'((KAPPA - 1) * RBASE_PARTS_OFFSET_L);
          next_gr_xor_phase = 0;
          next_gr_w         = 0;
          next_hlines_reg   = '0;
          next_leaf_buf     = '0;
          next_state = S_P0_RD;
        end
      end

      // ========================================================
      // P0: Initialize P0 in signature memory at PALPHA_SIG_OFFSET
      // (e=0 only, before gen_rbase)
      // P0[0]=0, P0[1..3]=CZ slices from u vector in r_acc slot 0.
      // CZ data starts at bit M_BIT_OFFSET within word M_WORD_OFFSET
      // of r_acc slot 0 (written by phase12), requiring extraction:
      //   cz_word = (lo >> M_BIT_OFFSET) | (hi << (64-M_BIT_OFFSET))
      // Writes go to sig_mem; var_bram reads extract CZ from r_acc.
      // ========================================================
      S_P0_INIT: begin
        if (gr_w < ($clog2(RBASE_PARTS_OFFSET_L+1))'(P0_LW)) begin
          // P0[0] = zero -> write to sig_mem (mirrored to CST position DEGREE-1)
          sig_addr_o  = p0_init_sig_addr;
          sig_data_o  = '0;
          sig_wr_en_o = 1'b1;
          next_gr_w = gr_w + 1;
        end else if (CAN_DUAL) begin
          // CAN_DUAL=1 (SEC3/SEC5): read lo+hi from var_bram, write CZ to sig_mem
          case (gr_xor_phase)
            2'd0: begin
              // Read: Port A = lo word, Port B = hi word from r_acc slot 0
              int_var_a_addr = VAR_ADDR_WIDTH_COMBINED'(
                  M_WORD_OFFSET + gr_w - P0_LW);
              int_var_b_addr = VAR_ADDR_WIDTH_COMBINED'(
                  M_WORD_OFFSET + gr_w - P0_LW + 1);
              next_gr_xor_phase = 2'd1;
            end
            2'd1: begin
              // Combine and write CZ word to sig_mem (mirrored to CST order)
              begin
                logic [63:0] cz_word;
                cz_word = (64'(var_a_data_i) >> M_BIT_OFFSET)
                        | (64'(var_b_data_i) << (64 - M_BIT_OFFSET));
                sig_addr_o  = p0_init_sig_addr;
                sig_data_o  = cz_word;
                sig_wr_en_o = 1'b1;
              end
              next_gr_xor_phase = 2'd0;
              if (gr_w == ($clog2(RBASE_PARTS_OFFSET_L+1))'(DEGREE * P0_LW - 1)) begin
                next_gr_w = 0;
                // Skip gen_rbase for e=0 (rbase already built by phase12)
                // Go directly to P0 Horner
                next_gr_j_reg = ($clog2(KAPPA))'(KAPPA - 1);
                next_gr_j_col_base = rbase_base + VAR_ADDR_WIDTH_COMBINED'((KAPPA - 1) * RBASE_PARTS_OFFSET_L);
                next_gr_xor_phase = 0;
                next_hlines_reg = '0;
                next_leaf_buf = '0;
                next_state = S_P0_RD;
              end else
                next_gr_w = gr_w + 1;
            end
            default: ;
          endcase
        end else begin
          // CAN_DUAL=0 (SEC1): sequential read lo, read hi, write CZ to sig_mem
          case (gr_xor_phase)
            2'd0: begin
              // Read lo word from r_acc slot 0
              int_var_a_addr = VAR_ADDR_WIDTH_COMBINED'(
                  M_WORD_OFFSET + gr_w - P0_LW);
              int_var_b_addr = int_var_a_addr;
              next_gr_xor_phase = 2'd1;
            end
            2'd1: begin
              // Buffer lo word, read hi word
              next_gr_r_acc_val = combine_ab();
              int_var_a_addr = VAR_ADDR_WIDTH_COMBINED'(
                  M_WORD_OFFSET + gr_w - P0_LW + 1);
              int_var_b_addr = int_var_a_addr;
              next_gr_xor_phase = 2'd2;
            end
            2'd2: begin
              // Combine and write CZ word to sig_mem (mirrored to CST order)
              begin
                logic [63:0] cz_word;
                cz_word = (gr_r_acc_val >> M_BIT_OFFSET)
                        | (combine_ab() << (64 - M_BIT_OFFSET));
                sig_addr_o  = p0_init_sig_addr;
                sig_data_o  = cz_word;
                sig_wr_en_o = 1'b1;
              end
              next_gr_xor_phase = 2'd0;
              if (gr_w == ($clog2(RBASE_PARTS_OFFSET_L+1))'(DEGREE * P0_LW - 1)) begin
                next_gr_w = 0;
                // Skip gen_rbase for e=0 (rbase already built by phase12)
                // Go directly to P0 Horner
                next_gr_j_reg = ($clog2(KAPPA))'(KAPPA - 1);
                next_gr_j_col_base = rbase_base + VAR_ADDR_WIDTH_COMBINED'((KAPPA - 1) * RBASE_PARTS_OFFSET_L);
                next_gr_xor_phase = 0;
                next_hlines_reg = '0;
                next_leaf_buf = '0;
                next_state = S_P0_RD;
              end else
                next_gr_w = gr_w + 1;
            end
            default: ;
          endcase
        end
      end

      // ========================================================
      // P0: Read CZ slice word from rbase column (Horner scheme)
      // gr_j_reg=column (KAPPA-1 down to 0), gr_xor_phase=slice, gr_w=word
      // Lower half of hlines_reg: CZ assembly
      // Horner accumulator is in leaf_buf; hlines_reg is CZ assembly (LAMBDA bits)
      // ========================================================
      S_P0_RD: begin
        // P0 CZ read: from cache for rbase[KAPPA-1] when USE_CACHE, else from var
        if (USE_CACHE && gr_j_reg == ($clog2(KAPPA))'(KAPPA - 1)) begin
          cache_addr_o = (CACHE_ADDR_WIDTH)'(
              CACHE_RBASE_OFFSET + P0_CZ_WORD_START + gr_xor_phase * P0_LW + gr_w);
        end else begin
          int_var_a_addr = p0_cz_addr;
          int_var_b_addr = p0_cz_addr;
        end
        if (gr_w == 0) begin
          // Clear CZ assembly; Horner accumulator (leaf_buf) preserved
          next_hlines_reg = '0;
          next_gr_w = 1;
        end else begin
          // Assemble BRAM data into hlines_reg (CZ slice)
          begin
            logic [63:0] _cz_data;
            _cz_data = (USE_CACHE && gr_j_reg == ($clog2(KAPPA))'(KAPPA - 1))
                ? cache_data_i : combine_ab();
            next_hlines_reg = hlines_reg | (LAMBDA'(_cz_data) << ((gr_w - 1) * 64));
          end

          if (gr_w == ($clog2(RBASE_PARTS_OFFSET_L+1))'(P0_LW)) begin
            // CZ slice assembled -> Horner accumulate
            next_gr_w = 0;
            next_state = S_P0_ACC;
          end else
            next_gr_w = gr_w + 1;
        end
      end

      // ========================================================
      // P0: Horner accumulate - acc = gf_mul_x(acc) XOR cz_assembled
      // Processes columns KAPPA-1 down to 0 (Horner evaluation order)
      // ========================================================
      S_P0_ACC: begin
        // Horner step: acc = gf_mul_x(leaf_buf) ^ hlines_reg (CZ assembly)
        if (gr_j_reg == 0) begin
          // Last column: result goes to hlines_reg for shift/RMW
          next_hlines_reg = p0_horner_step;
          next_leaf_buf   = p0_horner_step;
          if (e == 0) begin
            // e=0: no shift needed, go directly to P0 read-modify-write
            next_gr_w = 0;
            next_state = S_P0_P0RD;
          end else begin
            // Shift by e*KAPPA using e sequential gf_mul_xK steps
            next_gr_w = ($clog2(RBASE_PARTS_OFFSET_L+1))'(e);
            next_state = S_P0_SHIFT;
          end
        end else begin
          // More columns: update accumulator (leaf_buf), clear CZ assembly
          next_leaf_buf   = p0_horner_step;
          next_hlines_reg = '0;
          next_gr_j_reg = gr_j_reg - 1;
          next_gr_j_col_base = gr_j_col_base - VAR_ADDR_WIDTH_COMBINED'(RBASE_PARTS_OFFSET_L);
          next_gr_w = 0;
          next_state = S_P0_RD;
        end
      end

      // ========================================================
      // P0: Sequential gf_mul_xK - shift lower half by KAPPA each cycle
      // gr_w counts remaining shifts (e down to 1)
      // ========================================================
      S_P0_SHIFT: begin
        next_hlines_reg = gf_mul_xK(hlines_reg);
        if (gr_w == ($clog2(RBASE_PARTS_OFFSET_L+1))'(1)) begin
          next_gr_w = 0;
          next_state = S_P0_P0RD;
        end else begin
          next_gr_w = gr_w - 1;
        end
      end

      // ========================================================
      // P0: Read P0[sj][w] from signature memory
      // ========================================================
      S_P0_P0RD: begin
        sig_addr_o = p0_sig_addr;
        next_state = S_P0_P0WR;
      end

      // ========================================================
      // P0: XOR shifted result + write P0[sj][w] to signature memory
      // ========================================================
      S_P0_P0WR: begin
        sig_addr_o  = p0_sig_addr;
        sig_data_o  = sig_data_i ^ hlines_reg[(gr_w * 64) +: 64];
        sig_wr_en_o = 1'b1;

        if (gr_w == ($clog2(RBASE_PARTS_OFFSET_L+1))'(P0_LW - 1)) begin
          next_gr_w = 0;
          // Advance slice
          if (gr_xor_phase == 2'd2) begin
            // All 3 slices done for this e -> process_rbase
            next_gr_xor_phase = 0;
            next_state = S_PR_SHAKE_START;
          end else begin
            // Next slice: reset Horner accumulator (leaf_buf) and working reg
            next_gr_xor_phase = gr_xor_phase + 1;
            next_gr_j_reg = ($clog2(KAPPA))'(KAPPA - 1);
            next_gr_j_col_base = rbase_base + VAR_ADDR_WIDTH_COMBINED'((KAPPA - 1) * RBASE_PARTS_OFFSET_L);
            next_hlines_reg = '0;
            next_leaf_buf = '0;
            next_state = S_P0_RD;
          end
        end else begin
          next_gr_w = gr_w + 1;
          next_state = S_P0_P0RD;
        end
      end

      // ========================================================
      // PROCESS_RBASE: SHAKE start
      // ========================================================
      S_PR_SHAKE_START: begin
        shake_start_o    = 1'b1;
        shake_mode_o     = 1'b1;  // XOF mode for M-generation
        next_pr_absorb_w = 0;
        // Prime read for first haux word (cache or var)
        if (USE_CACHE) begin
          cache_addr_o = (CACHE_ADDR_WIDTH)'(CACHE_HAUX_OFFSET);
        end else begin
          int_var_a_addr = VAR_ADDR_WIDTH_COMBINED'(HAUX_VAR_OFFSET);
          int_var_b_addr = VAR_ADDR_WIDTH_COMBINED'(HAUX_VAR_OFFSET);
        end
        next_state       = S_PR_SHAKE_ABSORB;
      end

      // ========================================================
      // PROCESS_RBASE: SHAKE absorb h_aux
      // ========================================================
      S_PR_SHAKE_ABSORB: begin
        // Keep address stable for stall tolerance
        if (USE_CACHE) begin
          cache_addr_o = (CACHE_ADDR_WIDTH)'(CACHE_HAUX_OFFSET + pr_absorb_w);
        end else begin
          int_var_a_addr = VAR_ADDR_WIDTH_COMBINED'(HAUX_VAR_OFFSET + pr_absorb_w);
          int_var_b_addr = VAR_ADDR_WIDTH_COMBINED'(HAUX_VAR_OFFSET + pr_absorb_w);
        end

        shake_mode_o      = 1'b1;  // XOF mode for M-generation
        shake_din_o       = USE_CACHE ? cache_data_i : combine_ab();
        shake_din_valid_o = 1'b1;
        if (pr_absorb_w == 2*LAMBDA_DIV_64 - 1) begin
          shake_last_din_o      = 1'b1;
          shake_last_din_byte_o = 4'd8;
        end

        if (shake_din_ready_i) begin
          if (pr_absorb_w == 2*LAMBDA_DIV_64 - 1) begin
            next_pr_shake_buf = '0;
            next_pr_buf_valid = 0;
            next_pr_row_r     = 0;

            if (e == 0) begin
              next_pr_init_ctr = 0;
              next_state       = S_PR_INIT_ALPHA;
            end else begin
              next_pr_chunk_c = 0;
              next_pr_col_k   = 0;
              next_pr_col_base_addr_r = rbase_base;
              next_pr_acc     = '0;
              next_state      = S_PR_SQUEEZE_CHUNK;
            end
          end else begin
            next_pr_absorb_w = pr_absorb_w + 1;
            next_state       = S_PR_SHAKE_PRIME;
          end
        end
      end

      // ========================================================
      // PROCESS_RBASE: Prime var BRAM for next haux word
      // ========================================================
      S_PR_SHAKE_PRIME: begin
        shake_mode_o = 1'b1;
        if (USE_CACHE) begin
          cache_addr_o = (CACHE_ADDR_WIDTH)'(CACHE_HAUX_OFFSET + pr_absorb_w);
        end else begin
          int_var_a_addr = VAR_ADDR_WIDTH_COMBINED'(HAUX_VAR_OFFSET + pr_absorb_w);
          int_var_b_addr = VAR_ADDR_WIDTH_COMBINED'(HAUX_VAR_OFFSET + pr_absorb_w);
        end
        next_state = S_PR_SHAKE_ABSORB;
      end

      // ========================================================
      // PROCESS_RBASE: Zero alpha words (e==0 only)
      //   Phase 1: pr_init_ctr < SIG_CCHK_U_WORDS  -> zero alpha_plain in sig BRAM
      //   Phase 2: pr_init_ctr >= SIG_CCHK_U_WORDS  -> zero alpha_base in var BRAM
      // ========================================================
      S_PR_INIT_ALPHA: begin
        shake_mode_o = 1'b1;  // XOF for M-generation

        if (pr_init_ctr < SIG_CCHK_U_WORDS) begin
          sig_addr_o  = SIG_ADDR_WIDTH'(SIG_CCHK_U_OFFSET + pr_init_ctr);
          sig_data_o  = 64'b0;
          sig_wr_en_o = 1'b1;
        end else begin
          int_var_a_addr = VAR_ADDR_WIDTH_COMBINED'(ALPHA_BASE_VAR_OFFSET)
                         + VAR_ADDR_WIDTH_COMBINED'(pr_init_ctr - SIG_CCHK_U_WORDS);
          int_var_b_addr = int_var_a_addr;
          int_var_a_data = 64'b0;
          int_var_b_data = 64'b0;
          int_var_a_wr   = 1'b1;
          int_var_b_wr   = 1'b1;
        end

        if (pr_init_ctr == SIG_CCHK_U_WORDS + ALPHA_TOTAL_WORDS - 1)
          next_state = S_PR_PRIME_U_RD;
        else
          next_pr_init_ctr = pr_init_ctr + 1;

        // SHAKE pre-fetch (shared barrel shifter via pre-computed wires)
        if (shake_pf_ok) begin
          shake_dout_ready_o = 1'b1;
          if (shake_dout_valid_i) begin
            next_pr_shake_buf = shake_pf_buf;
            next_pr_buf_valid = shake_pf_valid;
          end
        end
      end

      // ========================================================
      // PROCESS_RBASE: Prime u (e==0 only)
      // ========================================================
      S_PR_PRIME_U_RD: begin
        shake_mode_o = 1'b1;
        int_var_a_addr = VAR_ADDR_WIDTH_COMBINED'(M_WORD_OFFSET);
        int_var_b_addr = VAR_ADDR_WIDTH_COMBINED'(M_WORD_OFFSET);
        next_state     = S_PR_PRIME_U_LATCH;

        // SHAKE pre-fetch (shared barrel shifter via pre-computed wires)
        if (shake_pf_ok) begin
          shake_dout_ready_o = 1'b1;
          if (shake_dout_valid_i) begin
            next_pr_shake_buf = shake_pf_buf;
            next_pr_buf_valid = shake_pf_valid;
          end
        end
      end

      S_PR_PRIME_U_LATCH: begin
        shake_mode_o = 1'b1;
        next_pr_prev_word_u = combine_ab() >> M_BIT_OFFSET;
        next_pr_chunk_c     = 0;
        next_pr_col_k       = 0;
        next_pr_col_base_addr_r = rbase_base;
        next_pr_acc         = '0;
        next_state          = S_PR_SQUEEZE_CHUNK;

        // SHAKE pre-fetch (shared barrel shifter via pre-computed wires)
        if (shake_pf_ok) begin
          shake_dout_ready_o = 1'b1;
          if (shake_dout_valid_i) begin
            next_pr_shake_buf = shake_pf_buf;
            next_pr_buf_valid = shake_pf_valid;
          end
        end
      end

      // ========================================================
      // PROCESS_RBASE: Squeeze M-row chunk
      // ========================================================
      S_PR_SQUEEZE_CHUNK: begin
        shake_mode_o = 1'b1;
        if (pr_buf_valid >= pr_squeeze_needed) begin
          if (pr_chunk_c == ELL_WORDS - 1) begin
            _m_chunk_comb   = pr_shake_buf[63:0] & ELL_LAST_MASK;
            next_pr_m_chunk   = _m_chunk_comb;
            next_pr_shake_buf = pr_shake_buf >> ELL_LAST_BITS;
            next_pr_buf_valid = pr_buf_valid - ($clog2(BUF_WIDTH+1))'(ELL_LAST_BITS);

            // u vector last chunk: handled in S_PR_PROCESS_COL (cross-word extraction)

            // Issue first column read(s)
            int_var_a_addr = rbase_base + pr_chunk_offset_r;
            if (CAN_DUAL && KAPPA >= 2 && !shadow_active) begin
              int_var_b_addr = rbase_base + VAR_ADDR_WIDTH_COMBINED'(RBASE_PARTS_OFFSET_L) + pr_chunk_offset_r;
              next_pr_col_k = 2;
              next_pr_col_base_addr_r = rbase_base + VAR_ADDR_WIDTH_COMBINED'(2 * RBASE_PARTS_OFFSET_L);
            end else begin
              int_var_b_addr = int_var_a_addr;
              next_pr_col_k = 1;
              next_pr_col_base_addr_r = rbase_base + VAR_ADDR_WIDTH_COMBINED'(RBASE_PARTS_OFFSET_L);
            end
            next_state    = S_PR_PROCESS_COL;
          end else begin
            next_pr_m_chunk   = pr_shake_buf[63:0];
            next_pr_shake_buf = pr_shake_buf >> 64;
            next_pr_buf_valid = pr_buf_valid - ($clog2(BUF_WIDTH+1))'(64);

            int_var_a_addr = rbase_base + pr_chunk_offset_r;
            if (CAN_DUAL && KAPPA >= 2 && !shadow_active) begin
              int_var_b_addr = rbase_base + VAR_ADDR_WIDTH_COMBINED'(RBASE_PARTS_OFFSET_L) + pr_chunk_offset_r;
              next_pr_col_k = 2;
              next_pr_col_base_addr_r = rbase_base + VAR_ADDR_WIDTH_COMBINED'(2 * RBASE_PARTS_OFFSET_L);
            end else begin
              int_var_b_addr = int_var_a_addr;
              next_pr_col_k = 1;
              next_pr_col_base_addr_r = rbase_base + VAR_ADDR_WIDTH_COMBINED'(RBASE_PARTS_OFFSET_L);
            end
            next_state    = S_PR_PROCESS_COL;
          end
        end else begin
          // Need more SHAKE data - squeeze into buffer (uses shared barrel shifter)
          shake_dout_ready_o = 1'b1;
          if (shake_dout_valid_i) begin
            next_pr_shake_buf = shake_pf_buf;
            next_pr_buf_valid = shake_pf_valid;
          end
        end
      end

      // ========================================================
      // PROCESS_RBASE: Process columns (parity computation)
      // ========================================================
      S_PR_PROCESS_COL: begin
        shake_mode_o = 1'b1;
        if (pr_col_k < pr_n_vecs) begin

          // ==== DUAL-COLUMN PATH (CAN_DUAL=1, 2 rbase cols per cycle) ====
          if (pr_can_dual_pair) begin

            // Process TWO columns: Port A = col[k-2], Port B = col[k-1]
            if (pr_chunk_c == ELL_WORDS - 1) begin
              _rbase_chunk  = 64'(var_a_data_i) & ELL_LAST_MASK;
              _rbase_chunk2 = 64'(var_b_data_i) & ELL_LAST_MASK;
            end else begin
              _rbase_chunk  = 64'(var_a_data_i);
              _rbase_chunk2 = 64'(var_b_data_i);
            end
            next_pr_acc[pr_col_k-2] = pr_acc[pr_col_k-2] ^ (^(pr_m_chunk & _rbase_chunk));
            next_pr_acc[pr_col_k-1] = pr_acc[pr_col_k-1] ^ (^(pr_m_chunk & _rbase_chunk2));

            // Decide next reads
            if (pr_col_k_all_done) begin
              // All columns done - transition to next chunk or write phase
              if (pr_chunk_c < ELL_WORDS - 1) begin
                next_pr_chunk_c = pr_chunk_c + 1;
                next_pr_col_k   = 0;
                next_pr_col_base_addr_r = rbase_base;
                next_state       = S_PR_SQUEEZE_CHUNK;
              end else begin
                next_pr_col_k = 0;
                next_pr_col_base_addr_r = rbase_base;
                next_state    = S_PR_BATCH_ID_RD;
              end
            end else if (pr_col_k + 1 < ($clog2(KAPPA+2))'(KAPPA)) begin
              // Two more rbase columns - issue dual reads
              int_var_a_addr = pr_col_base_addr + pr_chunk_offset_r;
              int_var_b_addr = pr_col_base_addr + VAR_ADDR_WIDTH_COMBINED'(RBASE_PARTS_OFFSET_L) + pr_chunk_offset_r;
              next_pr_col_k = pr_col_k + 2;
              next_pr_col_base_addr_r = (pr_col_k + 2 < ($clog2(KAPPA+2))'(KAPPA)) ?
                  (pr_col_base_addr_r + VAR_ADDR_WIDTH_COMBINED'(2 * RBASE_PARTS_OFFSET_L)) : '0;
            end else begin
              // One or zero rbase columns left - fall to single read
              if (pr_col_in_cache) begin
                cache_addr_o = pr_cache_m_chunk_addr;
              end else if (pr_col_k_lt_kappa) begin
                int_var_a_addr = pr_col_base_addr + pr_chunk_offset_r;
              end else begin
                int_var_a_addr = pr_chunk_offset_r;
              end
              int_var_b_addr = int_var_a_addr;
              next_pr_col_k = pr_col_k + 1;
              next_pr_col_base_addr_r = (pr_col_k + 1 < ($clog2(KAPPA+2))'(KAPPA)) ?
                  (pr_col_base_addr_r + VAR_ADDR_WIDTH_COMBINED'(RBASE_PARTS_OFFSET_L)) : '0;
            end

          end else begin
            // ==== SINGLE-COLUMN PATH (CAN_DUAL=0, or transition columns) ====

            // Compute parity for col_k-1
            if (pr_prev_col_lt_kappa) begin
              if (pr_chunk_c == ELL_WORDS - 1)
                _rbase_chunk = pr_prev_col_rd & ELL_LAST_MASK;
              else
                _rbase_chunk = pr_prev_col_rd;
              next_pr_acc[pr_col_k-1] = pr_acc[pr_col_k-1] ^ (^(pr_m_chunk & _rbase_chunk));

            end

            // Issue read for current col_k
            if (pr_col_in_cache) begin
              // rbase[KAPPA-1] m-data from cache
              cache_addr_o = pr_cache_m_chunk_addr;
            end else if (pr_col_k_lt_kappa) begin
              int_var_a_addr = pr_col_base_addr + pr_chunk_offset_r;
              int_var_b_addr = int_var_a_addr;
            end else begin
              int_var_a_addr = pr_chunk_offset_r;
              int_var_b_addr = int_var_a_addr;
            end
            next_pr_col_k = pr_col_k + 1;
            next_pr_col_base_addr_r = (pr_col_k + 1 < ($clog2(KAPPA+2))'(KAPPA)) ?
                (pr_col_base_addr_r + VAR_ADDR_WIDTH_COMBINED'(RBASE_PARTS_OFFSET_L)) : '0;
          end

        end else begin
          // Last column(s): compute parity

          // Dual-column last pair: process both col[k-2] and col[k-1]
          if (pr_can_dual_pair) begin
            if (pr_chunk_c == ELL_WORDS - 1) begin
              _rbase_chunk  = 64'(var_a_data_i) & ELL_LAST_MASK;
              _rbase_chunk2 = 64'(var_b_data_i) & ELL_LAST_MASK;
            end else begin
              _rbase_chunk  = 64'(var_a_data_i);
              _rbase_chunk2 = 64'(var_b_data_i);
            end
            next_pr_acc[pr_col_k-2] = pr_acc[pr_col_k-2] ^ (^(pr_m_chunk & _rbase_chunk));
            next_pr_acc[pr_col_k-1] = pr_acc[pr_col_k-1] ^ (^(pr_m_chunk & _rbase_chunk2));

          end else if (pr_prev_col_lt_kappa) begin
            if (pr_chunk_c == ELL_WORDS - 1)
              _rbase_chunk = pr_prev_col_rd & ELL_LAST_MASK;
            else
              _rbase_chunk = pr_prev_col_rd;
            next_pr_acc[pr_col_k-1] = pr_acc[pr_col_k-1] ^ (^(pr_m_chunk & _rbase_chunk));
          end else begin
            // u vector (natural layout): cross-word extraction
            _rbase_chunk = {combined_synt[M_BIT_OFFSET-1:0], pr_prev_word_u};
            if (pr_chunk_c == ELL_WORDS - 1)
              _rbase_chunk = _rbase_chunk & ELL_LAST_MASK;
            next_pr_acc[pr_col_k-1] = pr_acc[pr_col_k-1] ^ (^(pr_m_chunk & _rbase_chunk));
            next_pr_prev_word_u = combine_ab() >> M_BIT_OFFSET;
          end

          if (pr_chunk_c < ELL_WORDS - 1) begin
            next_pr_chunk_c = pr_chunk_c + 1;
            next_pr_col_k   = 0;
            next_pr_col_base_addr_r = rbase_base;
            next_state       = S_PR_SQUEEZE_CHUNK;
          end else begin
            next_pr_col_k = 0;
            next_pr_col_base_addr_r = rbase_base;
            next_state    = S_PR_BATCH_ID_RD;
          end
        end

        // SHAKE pre-fetch (shared barrel shifter via pre-computed wires)
        if (shake_pf_ok) begin
          shake_dout_ready_o = 1'b1;
          if (shake_dout_valid_i) begin
            next_pr_shake_buf = shake_pf_buf;
            next_pr_buf_valid = shake_pf_valid;
          end
        end
      end

      // ========================================================
      // BATCH WRITE: Read identity words, XOR into pr_acc
      // ========================================================
      S_PR_BATCH_ID_RD: begin
        shake_mode_o = 1'b1;

        // --- XOR identity bit(s) into pr_acc from previous cycle's read ---
        if (CAN_DUAL && !shadow_active) begin
          if (pr_col_k >= 2) begin
            _id_word = 64'(var_a_data_i);
            next_pr_acc[pr_col_k-2] = pr_acc[pr_col_k-2] ^ _id_word[pr_identity_bit_idx];
            if (pr_col_k - 1 < ($clog2(KAPPA+2))'(KAPPA)) begin
              _id_word = 64'(var_b_data_i);
              next_pr_acc[pr_col_k-1] = pr_acc[pr_col_k-1] ^ _id_word[pr_identity_bit_idx];
            end
          end
        end else begin
          if (pr_col_k >= 1) begin
            _id_word = (USE_CACHE && pr_col_k == ($clog2(KAPPA+2))'(KAPPA))
                       ? cache_data_i : combine_ab_bram();
            next_pr_acc[pr_col_k-1] = pr_acc[pr_col_k-1] ^ _id_word[pr_identity_bit_idx];
          end
        end

        // --- Issue next read or transition to alpha write ---
        if (pr_col_k < ($clog2(KAPPA+2))'(KAPPA)) begin
          if (CAN_DUAL && !shadow_active) begin
            int_var_a_addr = pr_col_base_addr + VAR_ADDR_WIDTH_COMBINED'(pr_row_r >> 6);
            int_var_b_addr = pr_col_base_addr + VAR_ADDR_WIDTH_COMBINED'(RBASE_PARTS_OFFSET_L)
                           + VAR_ADDR_WIDTH_COMBINED'(pr_row_r >> 6);
            next_pr_col_k = pr_col_k + 2;
            next_pr_col_base_addr_r = pr_col_base_addr_r
                + VAR_ADDR_WIDTH_COMBINED'(2 * RBASE_PARTS_OFFSET_L);
          end else begin
            if (pr_col_in_cache)
              cache_addr_o = pr_cache_identity_addr;
            else begin
              int_var_a_addr = pr_col_base_addr + VAR_ADDR_WIDTH_COMBINED'(pr_row_r >> 6);
              int_var_b_addr = int_var_a_addr;
            end
            next_pr_col_k = pr_col_k + 1;
            next_pr_col_base_addr_r = (pr_col_k + 1 < ($clog2(KAPPA+2))'(KAPPA))
                ? (pr_col_base_addr_r + VAR_ADDR_WIDTH_COMBINED'(RBASE_PARTS_OFFSET_L))
                : '0;
          end
        end else begin
          // All identity bits collected - issue alpha_base read, go to write
          if (CAN_DUAL && batch_spans) begin
            int_var_a_addr = batch_alpha_addr0;
            int_var_b_addr = batch_alpha_addr1;
          end else begin
            int_var_a_addr = batch_alpha_addr0;
            int_var_b_addr = batch_alpha_addr0;
          end
          next_pr_col_k = 0;
          next_state = S_PR_BATCH_ALPHA_WR;
        end

        // SHAKE pre-fetch
        if (shake_pf_ok) begin
          shake_dout_ready_o = 1'b1;
          if (shake_dout_valid_i) begin
            next_pr_shake_buf = shake_pf_buf;
            next_pr_buf_valid = shake_pf_valid;
          end
        end
      end

      // ========================================================
      // BATCH WRITE: Read-modify-write alpha_base word(s)
      // pr_col_k reused as phase counter for CAN_DUAL=0 spanning
      // ========================================================
      S_PR_BATCH_ALPHA_WR: begin
        shake_mode_o = 1'b1;

        if (CAN_DUAL) begin
          if (batch_spans) begin
            int_var_a_addr = batch_alpha_addr0;
            int_var_a_data = 64'(var_a_data_i) | batch_word0_mask;
            int_var_a_wr   = 1'b1;
            int_var_b_addr = batch_alpha_addr1;
            int_var_b_data = 64'(var_b_data_i) | batch_word1_mask;
            int_var_b_wr   = 1'b1;
          end else begin
            int_var_b_addr = batch_alpha_addr0;
            int_var_b_data = 64'(var_a_data_i) | batch_word0_mask;
            int_var_b_wr   = 1'b1;
          end
        end else begin
          case (pr_col_k[$clog2(KAPPA+2)-1:0])
            0: begin
              int_var_a_addr = batch_alpha_addr0;
              int_var_b_addr = batch_alpha_addr0;
              int_var_a_data = combine_ab() | batch_word0_mask;
              int_var_b_data = int_var_a_data;
              int_var_a_wr   = 1'b1;
              int_var_b_wr   = 1'b1;
              if (batch_spans)
                next_pr_col_k = 1;
            end
            1: begin
              int_var_a_addr = batch_alpha_addr1;
              int_var_b_addr = batch_alpha_addr1;
              next_pr_col_k = 2;
            end
            2: begin
              int_var_a_addr = batch_alpha_addr1;
              int_var_b_addr = batch_alpha_addr1;
              int_var_a_data = combine_ab() | batch_word1_mask;
              int_var_b_data = int_var_a_data;
              int_var_a_wr   = 1'b1;
              int_var_b_wr   = 1'b1;
            end
            default: ;
          endcase
        end

        // Exit when alpha_base write is complete
        if ( (CAN_DUAL) ||
             (!CAN_DUAL && pr_col_k == 0 && !batch_spans) ||
             (!CAN_DUAL && pr_col_k == 2) ) begin

          if (e == 0) begin
            next_pr_col_k = ($clog2(KAPPA+2))'(KAPPA);
            next_pr_col_base_addr_r = '0;
            next_state = S_PR_WRITE_U_RD;
          end else if (pr_row_r < ALPHA_COL_BITS_L - 1) begin
            next_pr_row_r   = pr_row_r + 1;
            next_pr_col_k   = 0;
            next_pr_col_base_addr_r = rbase_base;
            next_pr_chunk_c = 0;
            next_pr_acc     = '0;
            next_state = S_PR_SQUEEZE_CHUNK;
          end else begin
            if (e < TAU - 1) begin
              next_e   = e + 1;
              next_e_times_kappa = e_times_kappa + ($clog2(ALPHA_BASE_COLS))'(KAPPA);
              if (PRECOMP > 0 && (e + 1) <= E_WIDTH'(PRECOMP)) begin
                next_rbase_base = VAR_ADDR_WIDTH_COMBINED'(
                    SHADOW_RBASE_BASE + e * RBASE_SHADOW_STRIDE);
                next_gr_j_reg     = ($clog2(KAPPA))'(KAPPA - 1);
                next_gr_j_col_base = VAR_ADDR_WIDTH_COMBINED'(
                    SHADOW_RBASE_BASE + e * RBASE_SHADOW_STRIDE
                    + (KAPPA - 1) * RBASE_PARTS_OFFSET_L);
                next_gr_xor_phase = 0;
                next_gr_w         = 0;
                next_hlines_reg   = '0;
                next_leaf_buf     = '0;
                next_state = S_P0_RD;
              end else begin
                next_rbase_base = VAR_ADDR_WIDTH_COMBINED'(RBASE_OFFSET);
                next_leaf_buf_valid = 1'b0;
                gr_start_o       = 1'b1;
                gr_e_o           = ($clog2(TAU+1))'(e + 1);
                gr_rbase_base_o  = VAR_ADDR_WIDTH_COMBINED'(RBASE_OFFSET);
                gr_slot_offset_o = '0;
                gr_build_rbase_o = 1'b1;
                next_state = S_WAIT_GR;
              end
            end else begin
              next_state = S_HASH_START;
            end
          end
        end

        // SHAKE pre-fetch
        if (shake_pf_ok) begin
          shake_dout_ready_o = 1'b1;
          if (shake_dout_valid_i) begin
            next_pr_shake_buf = shake_pf_buf;
            next_pr_buf_valid = shake_pf_valid;
          end
        end
      end

      // ========================================================
      // U VECTOR: Read identity (+ alpha_plain for CAN_DUAL=1)
      // Only entered when e=0
      // ========================================================
      S_PR_WRITE_U_RD: begin
        shake_mode_o = 1'b1;
        sig_addr_o = pr_alpha_plain_sig_addr;
        if (CAN_DUAL) begin
          int_var_a_addr = VAR_ADDR_WIDTH_COMBINED'(pr_row_r >> 6);
          next_state = S_PR_WRITE_U_WR;
        end else begin
          int_var_a_addr = VAR_ADDR_WIDTH_COMBINED'(pr_row_r >> 6);
          int_var_b_addr = int_var_a_addr;
          next_state = S_PR_WRITE_U_LATCH;
        end

        if (shake_pf_ok) begin
          shake_dout_ready_o = 1'b1;
          if (shake_dout_valid_i) begin
            next_pr_shake_buf = shake_pf_buf;
            next_pr_buf_valid = shake_pf_valid;
          end
        end
      end

      // ========================================================
      // U VECTOR: Latch identity bit, read alpha_plain (CAN_DUAL=0)
      // ========================================================
      S_PR_WRITE_U_LATCH: begin
        shake_mode_o = 1'b1;
        _id_word = combine_ab_bram();
        next_pr_acc[KAPPA] = pr_acc[KAPPA] ^ _id_word[pr_identity_bit_idx];
        sig_addr_o = pr_alpha_plain_sig_addr;
        next_state = S_PR_WRITE_U_WR;
      end

      // ========================================================
      // U VECTOR: Write alpha_plain, advance row
      // ========================================================
      S_PR_WRITE_U_WR: begin
        shake_mode_o = 1'b1;
        if (CAN_DUAL) begin
          // CAN_DUAL=1: identity on var port A, alpha_plain from sig
          _id_word    = 64'(var_a_data_i);
          _alpha_word = sig_data_i;
          _result_bit = pr_acc[KAPPA] ^ _id_word[pr_identity_bit_idx];
        end else begin
          // CAN_DUAL=0: pr_acc[KAPPA] already XORed in U_LATCH, alpha_plain from sig
          _alpha_word = sig_data_i;
          _result_bit = pr_acc[KAPPA];
        end
        sig_addr_o  = pr_alpha_plain_sig_addr;
        sig_data_o  = _alpha_word | (64'(_result_bit) << pr_alpha_plain_bit);
        sig_wr_en_o = 1'b1;

        if (pr_row_r < ALPHA_COL_BITS_L - 1) begin
          next_pr_row_r   = pr_row_r + 1;
          next_pr_col_k   = 0;
          next_pr_col_base_addr_r = rbase_base;
          next_pr_chunk_c = 0;
          next_pr_acc     = '0;
          next_state = S_PR_PRIME_U_RD;
        end else begin
          next_pr_init_ctr = 0;
          next_state = S_DWIT_PRIME;
        end

        if (shake_pf_ok) begin
          shake_dout_ready_o = 1'b1;
          if (shake_dout_valid_i) begin
            next_pr_shake_buf = shake_pf_buf;
            next_pr_buf_valid = shake_pf_valid;
          end
        end
      end

      // ========================================================
      // DWIT: Prime shift register
      // ========================================================
      S_DWIT_PRIME: begin
        int_var_a_addr = VAR_ADDR_WIDTH_COMBINED'(DWIT_START_WORD);
        int_var_b_addr = VAR_ADDR_WIDTH_COMBINED'(DWIT_START_WORD);
        next_state     = S_DWIT_RD;
      end

      // ========================================================
      // DWIT: Latch prime, issue first reads
      // ========================================================
      S_DWIT_RD: begin
        if (DWIT_BIT_OFFSET > 0) begin
          next_pr_m_chunk    = combine_ab();
          int_var_a_addr = VAR_ADDR_WIDTH_COMBINED'(DWIT_START_WORD + 1);
          int_var_b_addr = VAR_ADDR_WIDTH_COMBINED'(DWIT_START_WORD + 1);
          key_addr_o     = (BRAM_ADDR_SIZE+1)'(WIT_OFFSET);
        end else begin
          int_var_a_addr = VAR_ADDR_WIDTH_COMBINED'(DWIT_START_WORD);
          int_var_b_addr = VAR_ADDR_WIDTH_COMBINED'(DWIT_START_WORD);
          key_addr_o     = (BRAM_ADDR_SIZE+1)'(WIT_OFFSET);
        end
        next_state = S_DWIT_COMPUTE;
      end

      // ========================================================
      // DWIT: Compute XOR, write sig
      // ========================================================
      S_DWIT_COMPUTE: begin
        _dwit_word = u_aligned ^ key_data_i;
        if (dwit_k == WIT_WORDS - 1)
          _dwit_word = _dwit_word & WIT_LAST_MASK;

        sig_data_o  = _dwit_word;
        sig_addr_o  = (SIG_ADDR_WIDTH)'(DWIT_SIG_OFFSET + dwit_k);
        sig_wr_en_o = 1'b1;

        next_pr_m_chunk = combine_ab();

        if (dwit_k < WIT_WORDS - 1) begin
          next_pr_init_ctr = dwit_k + 1;
          if (DWIT_BIT_OFFSET > 0) begin
            int_var_a_addr = VAR_ADDR_WIDTH_COMBINED'(DWIT_START_WORD + dwit_k + 2);
            int_var_b_addr = VAR_ADDR_WIDTH_COMBINED'(DWIT_START_WORD + dwit_k + 2);
          end else begin
            int_var_a_addr = VAR_ADDR_WIDTH_COMBINED'(DWIT_START_WORD + dwit_k + 1);
            int_var_b_addr = VAR_ADDR_WIDTH_COMBINED'(DWIT_START_WORD + dwit_k + 1);
          end
          key_addr_o = (BRAM_ADDR_SIZE+1)'(WIT_OFFSET + dwit_k + 1);
        end else begin
          // DWIT done. If more e-groups: start gen_rbase/P0 for e=1.
          if (TAU > 1) begin
            next_e   = E_WIDTH'(1);
            next_e_times_kappa = ($clog2(ALPHA_BASE_COLS))'(KAPPA);
            if (PRECOMP > 0) begin
              // e=1 is precomputed: skip gen_rbase, read shadow rbase
              next_rbase_base = VAR_ADDR_WIDTH_COMBINED'(SHADOW_RBASE_BASE);
              next_gr_j_reg     = ($clog2(KAPPA))'(KAPPA - 1);
              next_gr_j_col_base = VAR_ADDR_WIDTH_COMBINED'(
                  SHADOW_RBASE_BASE + (KAPPA - 1) * RBASE_PARTS_OFFSET_L);
              next_gr_xor_phase = 0;
              next_gr_w         = 0;
              next_hlines_reg   = '0;
              next_leaf_buf     = '0;
              next_state = S_P0_RD;
            end else begin
              next_rbase_base = VAR_ADDR_WIDTH_COMBINED'(RBASE_OFFSET);
              next_leaf_buf_valid = 1'b0;
              // Fire external gen_rbase
              gr_start_o       = 1'b1;
              gr_e_o           = ($clog2(TAU+1))'(1);
              gr_rbase_base_o  = VAR_ADDR_WIDTH_COMBINED'(RBASE_OFFSET);
              gr_slot_offset_o = '0;
              gr_build_rbase_o = 1'b1;
              next_state = S_WAIT_GR;
            end
          end else begin
            next_state = S_HASH_START;
          end
        end
      end

      // ========================================================
      // HASH: Start SHAKE, load prefix 0x03 into pack buffer
      // ========================================================
      S_HASH_START: begin
        shake_start_o      = 1'b1;
        next_pr_absorb_w        = 0;
        next_pr_buf_valid  = ($clog2(BUF_WIDTH+1))'(1);
        next_pr_shake_buf  = BUF_WIDTH'({HASH_LINES_PREFIX, 48'd0});
        // Prime read for first haux word (cache or var)
        if (USE_CACHE) begin
          cache_addr_o = (CACHE_ADDR_WIDTH)'(CACHE_HAUX_OFFSET);
        end else begin
          int_var_a_addr = VAR_ADDR_WIDTH_COMBINED'(HAUX_VAR_OFFSET);
          int_var_b_addr = VAR_ADDR_WIDTH_COMBINED'(HAUX_VAR_OFFSET);
        end
        next_state         = S_HASH_HAUX;
      end

      // ========================================================
      // HASH: Feed haux words through packing buffer (from cache or var)
      // ========================================================
      S_HASH_HAUX: begin
        // Keep address stable for stall tolerance
        if (USE_CACHE) begin
          cache_addr_o = (CACHE_ADDR_WIDTH)'(CACHE_HAUX_OFFSET + haux_w);
        end else begin
          int_var_a_addr = VAR_ADDR_WIDTH_COMBINED'(HAUX_VAR_OFFSET + haux_w);
          int_var_b_addr = VAR_ADDR_WIDTH_COMBINED'(HAUX_VAR_OFFSET + haux_w);
        end
        begin
          logic [3:0]   total;

          // haux: no bswap (SHAKE output is already MSB-first per word)
          hash_new_data = USE_CACHE ? cache_data_i : combine_ab();
          total = hash_pack_cnt + 4'd8;

          // total is always >= 8 (pack_cnt <= 7, adding 8)
          shake_din_o       = hash_combined[119:56];
          shake_din_valid_o = 1'b1;

          if (shake_din_ready_i) begin
            next_pr_shake_buf  = BUF_WIDTH'(hash_combined[55:0]);
            next_pr_buf_valid  = ($clog2(BUF_WIDTH+1))'(total - 4'd8);

            if (haux_w == 2 * LAMBDA_DIV_64 - 1) begin
              next_hash_aw = 0;
              next_state   = S_HASH_PLAIN_PRIME;
            end else begin
              next_pr_absorb_w = haux_w + 1;
              next_state       = S_HASH_HAUX_PRIME;
            end
          end
        end
      end

      // ========================================================
      // HASH: Prime var BRAM for next haux word
      // ========================================================
      S_HASH_HAUX_PRIME: begin
        if (USE_CACHE) begin
          cache_addr_o = (CACHE_ADDR_WIDTH)'(CACHE_HAUX_OFFSET + haux_w);
        end else begin
          int_var_a_addr = VAR_ADDR_WIDTH_COMBINED'(HAUX_VAR_OFFSET + haux_w);
          int_var_b_addr = VAR_ADDR_WIDTH_COMBINED'(HAUX_VAR_OFFSET + haux_w);
        end
        next_state = S_HASH_HAUX;
      end

      // ========================================================
      // HASH: Prime var memory read for alpha_plain word
      // ========================================================
      S_HASH_PLAIN_PRIME: begin
        sig_addr_o = SIG_ADDR_WIDTH'(SIG_CCHK_U_OFFSET + hash_aw);
        next_state = S_HASH_PLAIN_FEED;
      end

      // ========================================================
      // HASH: Pack alpha_plain word into packing buffer
      // ========================================================
      S_HASH_PLAIN_FEED: begin
        begin
          logic [3:0]   new_bytes;
          logic         is_last_word;
          logic [3:0]   total;

          hash_new_data = bswap64(sig_data_i);
          is_last_word = (hash_aw == ($clog2(HASH_AW_MAX+1))'(ALPHA_COL_WORDS - 1));
          new_bytes    = is_last_word ? 4'(ALPHA_LAST_BYTES) : 4'd8;

          total = hash_pack_cnt + new_bytes;

          if (total >= 4'd8) begin
            shake_din_o       = hash_combined[119:56];
            shake_din_valid_o = 1'b1;

            if (shake_din_ready_i) begin
              next_pr_shake_buf  = BUF_WIDTH'(hash_combined[55:0]);
              next_pr_buf_valid  = ($clog2(BUF_WIDTH+1))'(total - 4'd8);

              if (is_last_word) begin
                next_hash_vec = 0;
                next_hash_aw  = 0;
                next_state    = S_HASH_BASE_PRIME;
              end else begin
                next_hash_aw = hash_aw + 1;
                next_state   = S_HASH_PLAIN_PRIME;
              end
            end
          end else begin
            next_pr_shake_buf  = BUF_WIDTH'(hash_combined[119:64]);
            next_pr_buf_valid  = ($clog2(BUF_WIDTH+1))'(total);

            if (is_last_word) begin
              next_hash_vec = 0;
              next_hash_aw  = 0;
              next_state    = S_HASH_BASE_PRIME;
            end else begin
              next_hash_aw = hash_aw + 1;
              next_state   = S_HASH_PLAIN_PRIME;
            end
          end
        end
      end

      // ========================================================
      // HASH: Prime var memory read for alpha_base row word
      // ========================================================
      S_HASH_BASE_PRIME: begin
        int_var_a_addr = VAR_ADDR_WIDTH_COMBINED'(
            ALPHA_BASE_VAR_OFFSET + hash_vec * ALPHA_BASE_WORDS_PER_ROW + hash_aw);
        int_var_b_addr = int_var_a_addr;
        next_state     = S_HASH_BASE_FEED;
      end

      // ========================================================
      // HASH: Pack alpha_base row word into packing buffer
      // Valid bytes per word: 8 (LAMBDA is always multiple of 64,
      // so all ALPHA_BASE_WORDS_PER_ROW=LAMBDA_DIV_64 words are full)
      // ========================================================
      S_HASH_BASE_FEED: begin
        begin
          logic [3:0]   new_bytes;
          logic [3:0]   total;

          hash_new_data = bswap64(combine_ab());
          new_bytes = 4'd8;

          total = hash_pack_cnt + new_bytes;

          // total is always >= 8 (adding 8 bytes)
          shake_din_o       = hash_combined[119:56];
          shake_din_valid_o = 1'b1;

          if (shake_din_ready_i) begin
            next_pr_shake_buf  = BUF_WIDTH'(hash_combined[55:0]);
            next_pr_buf_valid  = ($clog2(BUF_WIDTH+1))'(total - 4'd8);

            if (hash_aw == ($clog2(HASH_AW_MAX+1))'(ALPHA_BASE_WORDS_PER_ROW - 1)) begin
              // End of row
              next_hash_aw = 0;
              if (hash_vec == ($clog2(ALPHA_COL_BITS+1))'(ALPHA_COL_BITS - 1)) begin
                // All rows done -> dwit
                next_hash_dw = 0;
                next_state   = S_HASH_DWIT_PRIME;
              end else begin
                next_hash_vec = hash_vec + 1;
                next_state    = S_HASH_BASE_PRIME;
              end
            end else begin
              next_hash_aw = hash_aw + 1;
              next_state   = S_HASH_BASE_PRIME;
            end
          end
        end
      end

      // ========================================================
      // HASH: Prime sig memory read for dwit word
      // ========================================================
      S_HASH_DWIT_PRIME: begin
        sig_addr_o = (SIG_ADDR_WIDTH)'(DWIT_SIG_OFFSET + hash_dw);
        next_state = S_HASH_DWIT_FEED;
      end

      // ========================================================
      // HASH: Pack dwit word into packing buffer
      // ========================================================
      S_HASH_DWIT_FEED: begin
        begin
          logic [3:0]   new_bytes;
          logic         is_last_word;
          logic [3:0]   total;

          hash_new_data = bswap64(sig_data_i);
          is_last_word = (hash_dw == ($clog2(WIT_WORDS+1))'(WIT_WORDS - 1));
          new_bytes    = is_last_word ?
                         ((WIT_BYTES % 8 == 0) ? 4'd8 : 4'(WIT_BYTES % 8))
                         : 4'd8;

          total = hash_pack_cnt + new_bytes;

          if (total >= 4'd8) begin
            shake_din_o       = hash_combined[119:56];
            shake_din_valid_o = 1'b1;

            if (is_last_word && total == 4'd8) begin
              shake_last_din_o      = 1'b1;
              shake_last_din_byte_o = 4'd8;
            end

            if (shake_din_ready_i) begin
              next_pr_shake_buf  = BUF_WIDTH'(hash_combined[55:0]);
              next_pr_buf_valid  = ($clog2(BUF_WIDTH+1))'(total - 4'd8);

              if (is_last_word) begin
                if ((total - 4'd8) > 4'd0)
                  next_state = S_HASH_DRAIN;
                else begin
                  next_pr_absorb_w  = 0;
                  next_hlines_reg = '0;
                  next_leaf_buf   = '0;  // clear upper squeeze target
                  next_state      = S_HASH_SQUEEZE;
                end
              end else begin
                next_hash_dw = hash_dw + 1;
                next_state   = S_HASH_DWIT_PRIME;
              end
            end
          end else begin
            // total < 8: accumulate without emitting
            next_pr_shake_buf  = BUF_WIDTH'(hash_combined[119:64]);
            next_pr_buf_valid  = ($clog2(BUF_WIDTH+1))'(total);

            if (is_last_word)
              next_state = S_HASH_DRAIN;
            else begin
              next_hash_dw = hash_dw + 1;
              next_state   = S_HASH_DWIT_PRIME;
            end
          end
        end
      end

      // ========================================================
      // HASH: Drain remaining pack buffer bytes as last SHAKE word
      // ========================================================
      S_HASH_DRAIN: begin
        if (hash_pack_cnt > 4'd0) begin
          shake_din_o           = {hash_pack_buf, 8'd0};
          shake_din_valid_o     = 1'b1;
          shake_last_din_o      = 1'b1;
          shake_last_din_byte_o = hash_pack_cnt;

          if (shake_din_ready_i) begin
            next_pr_buf_valid  = '0;
            next_pr_absorb_w     = 0;
            next_hlines_reg    = '0;
            next_leaf_buf      = '0;  // clear upper squeeze target
            next_state         = S_HASH_SQUEEZE;
          end
        end else begin
          // shouldn't happen
          next_pr_absorb_w  = 0;
          next_hlines_reg = '0;
          next_leaf_buf   = '0;  // clear upper squeeze target
          next_state      = S_HASH_SQUEEZE;
        end
      end

      // ========================================================
      // HASH: Squeeze output
      // ========================================================
      S_HASH_SQUEEZE: begin
        shake_dout_ready_o = 1'b1;
        if (shake_dout_valid_i) begin
          // Lower LAMBDA bits -> hlines_reg, upper LAMBDA bits -> leaf_buf
          if (squeeze_w < LAMBDA_DIV_64)
            next_hlines_reg = hlines_reg | (LAMBDA'(shake_dout_i) << (squeeze_w * 64));
          else
            next_leaf_buf = leaf_buf | (LAMBDA'(shake_dout_i) << ((squeeze_w - LAMBDA_DIV_64) * 64));
          if (squeeze_w == 2 * LAMBDA_DIV_64 - 1)
            next_state = S_DONE;
          else
            next_pr_absorb_w = squeeze_w + 1;
        end
      end

      // ========================================================
      S_DONE: begin
        fsm_done_o = 1'b1;
        next_state = S_IDLE;
      end

      default: ;
    endcase
  end
  // Sequential logic

  always_ff @(posedge clk_i or posedge rst_i) begin
    if (rst_i) begin
      state            <= S_IDLE;
      e                <= '0;
      e_times_kappa    <= '0;
      rbase_base       <= VAR_ADDR_WIDTH_COMBINED'(RBASE_OFFSET);

      // Gen_rbase / P0 shared
      gr_j_reg         <= 0;
      gr_j_col_base    <= '0;
      gr_w             <= 0;
      gr_xor_phase     <= 2'd0;
      gr_r_acc_val     <= 64'd0;
      leaf_buf         <= '0;
      leaf_buf_valid   <= 1'b0;

      // Process_rbase
      pr_row_r         <= 0;
      pr_chunk_c       <= 0;
      pr_chunk_offset_r <= VAR_ADDR_WIDTH_COMBINED'(M_WORD_OFFSET_OS);
      pr_col_base_addr_r <= '0;
      pr_col_k         <= 0;
      pr_absorb_w      <= 0;
      pr_init_ctr      <= 0;
      pr_m_chunk       <= 64'b0;
      pr_acc           <= '0;
      pr_shake_buf     <= '0;
      pr_buf_valid     <= 0;
      pr_prev_word_u   <= '0;

      // Dwit / hash (aliases: see decls)
      hash_vec         <= 0;
      hash_aw          <= 0;
      hash_dw          <= 0;
      hlines_reg       <= '0;
    end else if (!var_stall_i) begin
      state            <= next_state;
      e                <= next_e;
      e_times_kappa    <= next_e_times_kappa;
      rbase_base       <= next_rbase_base;

      // Gen_rbase / P0 shared
      gr_j_reg         <= next_gr_j_reg;
      gr_j_col_base    <= next_gr_j_col_base;
      gr_w             <= next_gr_w;
      gr_xor_phase     <= next_gr_xor_phase;
      gr_r_acc_val     <= next_gr_r_acc_val;
      leaf_buf         <= next_leaf_buf;
      leaf_buf_valid   <= next_leaf_buf_valid;

      // Process_rbase
      pr_row_r         <= next_pr_row_r;
      pr_chunk_c       <= next_pr_chunk_c;
      pr_chunk_offset_r <= VAR_ADDR_WIDTH_COMBINED'(M_WORD_OFFSET_OS + next_pr_chunk_c);
      pr_col_k         <= next_pr_col_k;
      pr_col_base_addr_r <= next_pr_col_base_addr_r;
      pr_absorb_w      <= next_pr_absorb_w;
      pr_init_ctr      <= next_pr_init_ctr;
      pr_m_chunk       <= next_pr_m_chunk;
      pr_acc           <= next_pr_acc;
      pr_shake_buf     <= next_pr_shake_buf;
      pr_buf_valid     <= next_pr_buf_valid;
      pr_prev_word_u   <= next_pr_prev_word_u;

      // Dwit / hash (aliases: see decls)
      hash_vec         <= next_hash_vec;
      hash_aw          <= next_hash_aw;
      hash_dw          <= next_hash_dw;
      hlines_reg       <= next_hlines_reg;
    end
  end

endmodule
