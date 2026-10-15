// SPDX-FileCopyrightText: 2026 Stef Halmans, Niklas Höher
// SPDX-License-Identifier: LicenseRef-RUB-SecEng

import sdith_params_pkg::*;
import sdith_helpers_pkg::*;

// blc_commit_phase12_hcom
//
// Variant of blc_commit_phase12 for the alternative hcom path
// (HCOM_IN_PHASE12=1, not KAT-faithful). Computes h_com in specification
// order (outer e, inner i) using the commit AES, then continues with the
// standard haux flow. gen_rbase is external, controlled via the gr_*
// ports.

module blc_commit_phase12_hcom (
    input logic clk_i,
    input logic rst_i,
    input logic var_stall_i,
    input logic fsm_enable_i,

    output logic fsm_done_o,

    // Gen_rbase control (to external gen_rbase via sign.sv mux)
    output logic                                  gr_start_o,
    output logic [$clog2(TAU+1)-1:0]              gr_e_o,
    output logic [VAR_ADDR_WIDTH_COMBINED-1:0]    gr_rbase_base_o,
    output logic [BRAM_ADDR_SIZE:0]               gr_slot_offset_o,
    output logic                                  gr_build_rbase_o,
    input  logic                                  gr_done_i,

    // Leaf handshake (to get_leaf_combined_nohcom via top mux)
    output logic get_next_leaf_o,
    input  logic leaf_done_i,
    input  logic [LAMBDA-1:0] leaf_i,
    output logic [GGM_TREE_DEPTH:0] leaf_idx_o,
    output logic [GGM_TREE_DEPTH:0] leaf_idx2_o,
    input  logic [LAMBDA-1:0] leaf2_i,

    // Commit AES interface (drives top-level AES0/AES1 during commit states)
    output logic                     commit_owns_aes0_o,
    output logic                     commit_owns_aes1_o,
    output logic [ENC_KEYSIZE-1:0]   aes0_key_o,
    output logic [ENC_BLOCKSIZE-1:0] aes0_plaintext_o,
    input  logic [ENC_BLOCKSIZE-1:0] aes0_ciphertext_i,
    output logic                     aes0_enable_o,
    input  logic                     aes0_ready_i,
    input  logic                     aes0_valid_i,
    output logic [ENC_KEYSIZE-1:0]   aes1_key_o,
    output logic [ENC_BLOCKSIZE-1:0] aes1_plaintext_o,
    input  logic [ENC_BLOCKSIZE-1:0] aes1_ciphertext_i,
    output logic                     aes1_enable_o,
    input  logic                     aes1_ready_i,
    input  logic                     aes1_valid_i,

    input  logic [LAMBDA-1:0]        salt_i,

    // SHAKE (active during haux computation)
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

    // Signature memory (single-port, 64-bit)
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

    // Cache BRAM (for rbase[KAPPA-1] and haux when USE_CACHE_OVERFLOW)
    input  logic [63:0]             cache_data_i,
    output logic [63:0]             cache_data_o,
    output logic [CACHE_ADDR_WIDTH-1:0] cache_addr_o,
    output logic                    cache_wr_en_o,
    // Cache active: haux squeeze only (gen_rbase cache writes handled externally)
    output logic                    cache_active_o
);
  // Local parameters

  localparam CAN_DUAL = CAN_DUAL_COMBINED;

  // Total hcom words to feed
  localparam HCOM_WORDS = 2 * LAMBDA_DIV_64;
  // Total squeeze words for haux
  localparam HAUX_SQUEEZE_WORDS = 2 * LAMBDA_DIV_64;
  // Combine dual-port var read data into a 64-bit logical word
  // (bswap64, phys_a, phys_b, split_a, split_b come from sdith_helpers_pkg)
  function automatic [63:0] combine_ab;
    if (CAN_DUAL) return 64'(var_a_data_i);
    else          return {var_b_data_i, var_a_data_i};
  endfunction

  // Whether to write rbase[KAPPA-1] and haux to cache BRAM
  localparam USE_CACHE = USE_CACHE_OVERFLOW;

  // Precomp count (needed for S_NEXT_E gen_rbase config)
  localparam PRECOMP = NUM_PRECOMP_E;

  // Slot offset for racc temp (needed for gen_rbase slot offset and S_AUX_RD addressing)
  localparam RACC_TEMP_OFFSET = HCOM_VAR_OFFSET + HCOM_WORDS;

  // State definition

  typedef enum logic [4:0] {
    S_IDLE,
    S_HCOM_START,        // alt: pulse SHAKE start, push prefix 0x01
    S_GET_LEAF,
    // Commit states (alt path only)
    S_COMMIT_FIRE_A,     // fire AES0(leaf1, salt^2*idx1+0), AES1(leaf2, salt^2*idx2+0)
    S_COMMIT_WAIT_A,     // latch lo halves + fire offset=1 in same cycle
    S_COMMIT_WAIT_B,     // latch hi halves, then fire gen_rbase + parallel hash feed
    S_WAIT_GR,           // wait for external gen_rbase to complete
    S_AUX_RD,
    S_AUX_RD2,           // CAN_DUAL=0 only: read slot 1
    S_AUX_WR,
    S_NEXT_E,
    // hcom finalize+squeeze (after last e, before haux)
    S_HCOM_DRAIN,        // drain remaining pack_buf as last SHAKE word
    S_HCOM_SQUEEZE,      // write 2*LAMBDA bits of hcom to var BRAM
    // haux computation states
    S_HAUX_START,
    S_HAUX_HCOM,
    S_HAUX_HCOM_PRIME,
    S_HAUX_AUX_PRIME,
    S_HAUX_AUX_FEED,
    S_HAUX_DRAIN,
    S_HAUX_SQUEEZE,
    S_DONE
  } fsm_state_t;

  fsm_state_t state, next_state;
  // Loop counters

  localparam E_WIDTH = $clog2(TAU + 1);
  logic [E_WIDTH-1:0] e, next_e;
  logic [$clog2(R_ACC_PARTS):0] aux_w, next_aux_w;

  // Running accumulators to avoid multiplies (eliminates DSP inference)
  // sig_aux_base = AUX_OFFSET + (e-1)*R_ACC_PARTS (incremented by R_ACC_PARTS per e)
  logic [SIG_ADDR_WIDTH-1:0] sig_aux_base, next_sig_aux_base;
  // leaf_base = i*TAU + e (maintained by FSM)
  logic [GGM_TREE_DEPTH:0] leaf_base, next_leaf_base;
  // Leaf buffering

  logic [LAMBDA-1:0] leaf_buf, next_leaf_buf;
  logic leaf_buf_valid, next_leaf_buf_valid;
  // Aux latch (CAN_DUAL=0: need to store r_acc[0] word)

  logic [63:0] aux_r0, next_aux_r0;
  // Commit + hcom registers (alt path)

  // Latched leaves and tree-indices for the commit AES
  logic [LAMBDA-1:0]       commit_leaf1_r, next_commit_leaf1_r;
  logic [LAMBDA-1:0]       commit_leaf2_r, next_commit_leaf2_r;
  logic [GGM_TREE_DEPTH:0] commit_idx1_r,  next_commit_idx1_r;
  logic [GGM_TREE_DEPTH:0] commit_idx2_r,  next_commit_idx2_r;
  logic                    need_commit_for_pair, next_need_commit_for_pair;

  // Commit output halves (lo = offset_bit=0, hi = offset_bit=1)
  // Slicing matches get_leaf_combined
  logic [LAMBDA-1:0] commit1_lo_r, next_commit1_lo_r;
  logic [LAMBDA-1:0] commit1_hi_r, next_commit1_hi_r;
  logic [LAMBDA-1:0] commit2_lo_r, next_commit2_lo_r;
  logic [LAMBDA-1:0] commit2_hi_r, next_commit2_hi_r;

  // hcom feed iterators: which leaf, which half, which 64-bit word
  localparam LAMBDA_DIV_64_BITS = $clog2(LAMBDA_DIV_64 + 1);
  logic                       hcom_which_leaf, next_hcom_which_leaf;
  logic                       hcom_which_half, next_hcom_which_half;
  logic [LAMBDA_DIV_64_BITS-1:0] hcom_word_in_half, next_hcom_word_in_half;
  // hash feed runs in parallel with gen_rbase. Set when a pair's commits are
  // ready to hash, cleared when all 4 halves have been absorbed into SHAKE.
  logic                       hcom_feed_active,  next_hcom_feed_active;

  // hcom squeeze counter
  localparam HCOM_SQ_BITS = $clog2(HCOM_WORDS + 1);
  logic [HCOM_SQ_BITS-1:0] hcom_squeeze_w, next_hcom_squeeze_w;

  // Commit AES plaintext synthesis (mirrors get_leaf_combined)
  function automatic [ENC_BLOCKSIZE-1:0] commit_pt(
      input logic [GGM_TREE_DEPTH:0] tree_idx,
      input logic                    offset_bit
  );
    logic [ENC_BLOCKSIZE-1:0] salt_shifted;
    logic [ENC_BLOCKSIZE-1:0] xor_val;
    logic [ENC_BLOCKSIZE-1:0] pre;
    salt_shifted = (ENC_BLOCKSIZE)'(salt_i)
                 << (SECURITY_LEVEL == 3 ? 64 : 0);
    xor_val = (ENC_BLOCKSIZE)'({tree_idx, 1'b0});  // 2 * tree_idx
    pre = (salt_shifted ^ xor_val) + (ENC_BLOCKSIZE)'(offset_bit);
    commit_pt = {<<8{pre}};
  endfunction

  // Slicing functions matching get_leaf_combined SEC3 convention.
  function automatic [LAMBDA-1:0] commit_lo_slice(
      input logic [ENC_BLOCKSIZE-1:0] ct);
    return (LAMBDA)'(ct);
  endfunction
  function automatic [LAMBDA-1:0] commit_hi_slice(
      input logic [ENC_BLOCKSIZE-1:0] ct);
    if (SECURITY_LEVEL == 3) commit_hi_slice = ct[ENC_BLOCKSIZE-1:64];
    else                     commit_hi_slice = (LAMBDA)'(ct);
  endfunction

  // Currently-feeding 64-bit word (MSB-first within the selected half)
  logic [LAMBDA-1:0] hcom_active_half;
  always_comb begin
    case ({hcom_which_leaf, hcom_which_half})
      2'b00: hcom_active_half = commit1_lo_r;
      2'b01: hcom_active_half = commit1_hi_r;
      2'b10: hcom_active_half = commit2_lo_r;
      2'b11: hcom_active_half = commit2_hi_r;
      default: hcom_active_half = '0;
    endcase
  end
  // Extract MSB-first 64-bit word at position hcom_word_in_half.
  // word 0 = bits [LAMBDA-1 -: 64], word 1 = bits [LAMBDA-65 -: 64], etc.
  logic [63:0] hcom_word;
  always_comb begin
    hcom_word = hcom_active_half[(LAMBDA-1) - hcom_word_in_half*64 -: 64];
  end
  // Leaf index (accumulator-based, no multiply)

  // leaf_base = i*TAU + e (maintained by FSM)
  assign leaf_idx_o  = leaf_base;
  assign leaf_idx2_o = leaf_base + (GGM_TREE_DEPTH+1)'(TAU);
  // haux registers

  // hash_w: word counter, sized for max(HCOM_WORDS, R_ACC_PARTS)
  localparam HASH_W_MAX = (HCOM_WORDS > R_ACC_PARTS) ? HCOM_WORDS : R_ACC_PARTS;
  logic [$clog2(HASH_W_MAX+1)-1:0] hash_w, next_hash_w;
  logic [$clog2(HAUX_SQUEEZE_WORDS+1)-1:0] squeeze_w, next_squeeze_w;

  // Packing buffer for haux SHAKE feeding.
  logic [55:0] pack_buf, next_pack_buf;
  logic [3:0]  pack_cnt, next_pack_cnt;  // 0..7
  // Var memory: always output int_var_* (gen_rbase owns memory externally)

  logic [63:0]             int_var_a_data, int_var_b_data;
  logic [VAR_ADDR_WIDTH_COMBINED-1:0] int_var_a_addr, int_var_b_addr;
  logic                    int_var_a_wr, int_var_b_wr;

  assign var_a_data_o  = split_a(int_var_a_data);
  assign var_a_addr_o  = phys_a(int_var_a_addr);
  assign var_a_wr_en_o = int_var_a_wr;
  assign var_b_data_o  = split_b(int_var_b_data);
  assign var_b_addr_o  = phys_b(int_var_b_addr);
  assign var_b_wr_en_o = int_var_b_wr;
  // FSM

  always_comb begin
    next_state     = state;
    next_e         = e;
    next_aux_w     = aux_w;
    next_sig_aux_base = sig_aux_base;
    next_leaf_base = leaf_base;
    next_leaf_buf  = leaf_buf;
    next_leaf_buf_valid = leaf_buf_valid;
    next_aux_r0    = aux_r0;
    next_hash_w    = hash_w;
    next_squeeze_w = squeeze_w;
    next_pack_buf       = pack_buf;
    next_pack_cnt       = pack_cnt;

    next_commit_leaf1_r       = commit_leaf1_r;
    next_commit_leaf2_r       = commit_leaf2_r;
    next_commit_idx1_r        = commit_idx1_r;
    next_commit_idx2_r        = commit_idx2_r;
    next_need_commit_for_pair = need_commit_for_pair;
    next_commit1_lo_r         = commit1_lo_r;
    next_commit1_hi_r         = commit1_hi_r;
    next_commit2_lo_r         = commit2_lo_r;
    next_commit2_hi_r         = commit2_hi_r;
    next_hcom_which_leaf      = hcom_which_leaf;
    next_hcom_which_half      = hcom_which_half;
    next_hcom_word_in_half    = hcom_word_in_half;
    next_hcom_feed_active     = hcom_feed_active;
    next_hcom_squeeze_w       = hcom_squeeze_w;

    fsm_done_o      = 1'b0;
    get_next_leaf_o = 1'b0;

    // Gen_rbase defaults
    gr_start_o       = 1'b0;
    gr_e_o           = '0;
    gr_rbase_base_o  = '0;
    gr_slot_offset_o = '0;
    gr_build_rbase_o = 1'b0;

    // Commit AES defaults
    commit_owns_aes0_o = 1'b0;
    commit_owns_aes1_o = 1'b0;
    aes0_key_o         = '0;
    aes0_plaintext_o   = '0;
    aes0_enable_o      = 1'b0;
    aes1_key_o         = '0;
    aes1_plaintext_o   = '0;
    aes1_enable_o      = 1'b0;

    // SHAKE defaults
    shake_start_o            = 1'b0;
    shake_mode_o             = 1'b0;   // hash mode
    shake_seed_from_output_o = 1'b0;
    shake_din_o              = 64'b0;
    shake_din_valid_o        = 1'b0;
    shake_last_din_o         = 1'b0;
    shake_last_din_byte_o    = 4'd0;
    shake_dout_ready_o       = 1'b0;

    // Sig memory defaults
    sig_data_o  = 64'b0;
    sig_addr_o  = '0;
    sig_wr_en_o = 1'b0;

    // Var memory defaults
    int_var_a_data = 64'b0;
    int_var_a_addr = '0;
    int_var_a_wr   = 1'b0;
    int_var_b_data = 64'b0;
    int_var_b_addr = '0;
    int_var_b_wr   = 1'b0;

    // Cache BRAM defaults
    cache_data_o  = 64'b0;
    cache_addr_o  = '0;
    cache_wr_en_o = 1'b0;
    // Cache active: haux squeeze only (gen_rbase cache writes handled externally)
    cache_active_o = (state == S_HAUX_SQUEEZE);

    case (state)

      // ========================================================
      S_IDLE: begin
        if (fsm_enable_i) begin
          next_e = '0;
          next_leaf_base = '0;
          next_sig_aux_base = (SIG_ADDR_WIDTH)'(AUX_OFFSET);
          next_leaf_buf_valid = 1'b0;
          next_pack_buf  = '0;
          next_pack_cnt  = '0;
          next_state = S_HCOM_START;       // alt path: prime SHAKE before fetching leaves
        end
      end

      // ========================================================
      // Pulse SHAKE start, push HASH_BAVC_PREFIX (0x01) into packing
      // buffer. SHAKE is now fresh in hash mode and will absorb commits.
      // ========================================================
      S_HCOM_START: begin
        shake_start_o            = 1'b1;
        shake_mode_o             = 1'b0;
        shake_seed_from_output_o = 1'b0;
        next_pack_buf            = {HASH_BAVC_PREFIX, 48'd0};
        next_pack_cnt            = 4'd1;
        next_state               = S_GET_LEAF;
      end

      // ========================================================
      // Get leaf: use buffered leaf or dual-fetch
      // ========================================================
      S_GET_LEAF: begin
        if (leaf_buf_valid) begin
          // unreachable: gen_rbase fetches all leaves per e
          next_leaf_buf_valid = 1'b0;
          next_state          = S_WAIT_GR;
        end else begin
          // Fresh dual fetch: leaf_idx_o = i*TAU+e, leaf_idx2_o = (i+1)*TAU+e
          get_next_leaf_o = 1'b1;
          if (leaf_done_i) begin
            // latch leaf1 for commit before gen_rbase
            next_commit_leaf1_r = leaf_i;
            next_commit_idx1_r  = leaf_base + (GGM_TREE_DEPTH+1)'(GGM_TREE_SIZE);
            next_need_commit_for_pair = 1'b0;  // single leaf for commit in this model
            next_state = S_COMMIT_FIRE_A;
          end
        end
      end

      // ========================================================
      // fire commit AES for leaf1 (offset_bit=0, lo half)
      // ========================================================
      S_COMMIT_FIRE_A: begin
        commit_owns_aes0_o = 1'b1;
        commit_owns_aes1_o = need_commit_for_pair;
        aes0_key_o         = (ENC_KEYSIZE)'(commit_leaf1_r);
        aes0_plaintext_o   = commit_pt(commit_idx1_r, 1'b0);
        aes1_key_o         = (ENC_KEYSIZE)'(commit_leaf2_r);
        aes1_plaintext_o   = commit_pt(commit_idx2_r, 1'b0);
        if (aes0_ready_i && (!need_commit_for_pair || aes1_ready_i)) begin
          aes0_enable_o = 1'b1;
          aes1_enable_o = need_commit_for_pair;
          next_state    = S_COMMIT_WAIT_A;
        end
      end

      // S_COMMIT_WAIT_A -- wait for offset=0 ciphertexts. In the same cycle
      // that aes_valid arrives, we latch the lo halves AND fire the offset=1 encryption.
      S_COMMIT_WAIT_A: begin
        commit_owns_aes0_o = 1'b1;
        commit_owns_aes1_o = need_commit_for_pair;
        if (aes0_valid_i && (!need_commit_for_pair || aes1_valid_i)) begin
          next_commit1_lo_r = commit_lo_slice(aes0_ciphertext_i);
          if (need_commit_for_pair)
            next_commit2_lo_r = commit_lo_slice(aes1_ciphertext_i);
          // Directly fire offset=1 (AES is simultaneously ready in IDLE).
          aes0_key_o       = (ENC_KEYSIZE)'(commit_leaf1_r);
          aes0_plaintext_o = commit_pt(commit_idx1_r, 1'b1);
          aes1_key_o       = (ENC_KEYSIZE)'(commit_leaf2_r);
          aes1_plaintext_o = commit_pt(commit_idx2_r, 1'b1);
          aes0_enable_o    = 1'b1;
          aes1_enable_o    = need_commit_for_pair;
          next_state       = S_COMMIT_WAIT_B;
        end else begin
          // Keep offset=0 plaintext/key stable while waiting.
          aes0_key_o       = (ENC_KEYSIZE)'(commit_leaf1_r);
          aes0_plaintext_o = commit_pt(commit_idx1_r, 1'b0);
          aes1_key_o       = (ENC_KEYSIZE)'(commit_leaf2_r);
          aes1_plaintext_o = commit_pt(commit_idx2_r, 1'b0);
        end
      end

      // S_COMMIT_WAIT_B -- wait for offset=1 ciphertexts. On valid, latch
      // the hi halves, fire gen_rbase, and kick off parallel hash feed.
      // The hash feed runs INSIDE S_WAIT_GR (using SHAKE which gen_rbase doesn't touch).
      S_COMMIT_WAIT_B: begin
        commit_owns_aes0_o = 1'b1;
        commit_owns_aes1_o = need_commit_for_pair;
        aes0_key_o       = (ENC_KEYSIZE)'(commit_leaf1_r);
        aes0_plaintext_o = commit_pt(commit_idx1_r, 1'b1);
        aes1_key_o       = (ENC_KEYSIZE)'(commit_leaf2_r);
        aes1_plaintext_o = commit_pt(commit_idx2_r, 1'b1);
        if (aes0_valid_i && (!need_commit_for_pair || aes1_valid_i)) begin
          next_commit1_hi_r = commit_hi_slice(aes0_ciphertext_i);
          if (need_commit_for_pair)
            next_commit2_hi_r = commit_hi_slice(aes1_ciphertext_i);
          // Initialize hcom feed iterator: leaf1.lo, word 0
          next_hcom_which_leaf   = 1'b0;
          next_hcom_which_half   = 1'b0;
          next_hcom_word_in_half = '0;
          next_hcom_feed_active  = 1'b1;
          // Fire gen_rbase for this e
          gr_start_o = 1'b1;
          gr_e_o     = e;
          if (e == 0) begin
            // e=0: full rbase build
            gr_rbase_base_o  = VAR_ADDR_WIDTH_COMBINED'(RBASE_OFFSET);
            gr_slot_offset_o = '0;
            gr_build_rbase_o = 1'b1;
          end else if (PRECOMP > 0 && e <= E_WIDTH'(PRECOMP)) begin
            // Precomputed: build shadow rbase
            gr_rbase_base_o  = VAR_ADDR_WIDTH_COMBINED'(
                SHADOW_RBASE_BASE + (e - 1) * RBASE_SHADOW_STRIDE);
            gr_slot_offset_o = (BRAM_ADDR_SIZE+1)'(RACC_TEMP_OFFSET);
            gr_build_rbase_o = 1'b1;
          end else begin
            // Non-precomputed: racc only
            gr_rbase_base_o  = '0;
            gr_slot_offset_o = (BRAM_ADDR_SIZE+1)'(RACC_TEMP_OFFSET);
            gr_build_rbase_o = 1'b0;
          end
          next_state = S_WAIT_GR;
        end
      end

      // ========================================================
      // Wait for gen_rbase + parallel hash feed.
      // hash feed only touches SHAKE din, no conflict with gen_rbase
      // ========================================================
      S_WAIT_GR: begin
        // -------- parallel hash feed into SHAKE (no gen_rbase conflict) --------
        if (hcom_feed_active) begin
          logic [63:0]  word;
          logic [119:0] combined;
          logic [3:0]   total;
          word = hcom_word;
          case (pack_cnt)
            0: combined = {word, 56'd0};
            1: combined = {pack_buf[55:48], word, 48'd0};
            2: combined = {pack_buf[55:40], word, 40'd0};
            3: combined = {pack_buf[55:32], word, 32'd0};
            4: combined = {pack_buf[55:24], word, 24'd0};
            5: combined = {pack_buf[55:16], word, 16'd0};
            6: combined = {pack_buf[55:8],  word,  8'd0};
            7: combined = {pack_buf[55:0],  word       };
            default: combined = {word, 56'd0};
          endcase
          total = pack_cnt + 4'd8;
          shake_din_o       = combined[119:56];
          shake_din_valid_o = 1'b1;
          if (shake_din_ready_i) begin
            next_pack_buf = combined[55:0];
            next_pack_cnt = total - 4'd8;
            if (hcom_word_in_half == LAMBDA_DIV_64_BITS'(LAMBDA_DIV_64 - 1)) begin
              next_hcom_word_in_half = '0;
              if (hcom_which_half == 1'b0) begin
                next_hcom_which_half = 1'b1;
              end else begin
                next_hcom_which_half = 1'b0;
                if (hcom_which_leaf == 1'b0 && need_commit_for_pair) begin
                  next_hcom_which_leaf = 1'b1;
                end else begin
                  next_hcom_feed_active = 1'b0;
                end
              end
            end else begin
              next_hcom_word_in_half = hcom_word_in_half + 1;
            end
          end
        end

        // -------- gen_rbase completion check --------
        if (gr_done_i && !next_hcom_feed_active) begin
          if (e == 0)
            next_state = S_NEXT_E;
          else begin
            // e>0: extract aux = slot0 XOR racc_temp
            next_aux_w = '0;
            next_state = S_AUX_RD;
          end
        end
      end

      // ========================================================
      // Aux extraction: read r_acc[0] and r_acc[e] (at RACC_TEMP_OFFSET)
      // ========================================================
      S_AUX_RD: begin
        if (CAN_DUAL) begin
          int_var_a_addr = VAR_ADDR_WIDTH_COMBINED'(aux_w);
          int_var_b_addr = VAR_ADDR_WIDTH_COMBINED'(RACC_TEMP_OFFSET + aux_w);
          next_state = S_AUX_WR;
        end else begin
          int_var_a_addr = VAR_ADDR_WIDTH_COMBINED'(aux_w);
          int_var_b_addr = VAR_ADDR_WIDTH_COMBINED'(aux_w);
          next_state = S_AUX_RD2;
        end
      end

      // CAN_DUAL=0 only: latch r_acc[0], read racc_temp at RACC_TEMP_OFFSET
      S_AUX_RD2: begin
        next_aux_r0    = combine_ab();
        int_var_a_addr = VAR_ADDR_WIDTH_COMBINED'(RACC_TEMP_OFFSET + aux_w);
        int_var_b_addr = VAR_ADDR_WIDTH_COMBINED'(RACC_TEMP_OFFSET + aux_w);
        next_state     = S_AUX_WR;
      end

      // Write aux[e] word to sig memory
      S_AUX_WR: begin
        if (CAN_DUAL) begin
          sig_data_o = 64'(var_a_data_i) ^ 64'(var_b_data_i);
        end else begin
          sig_data_o = aux_r0 ^ combine_ab();
        end

        sig_addr_o  = sig_aux_base + (SIG_ADDR_WIDTH)'(aux_w);
        sig_wr_en_o = 1'b1;

        if (aux_w == ($clog2(R_ACC_PARTS)+1)'(R_ACC_PARTS - 1)) begin
          next_sig_aux_base = sig_aux_base + (SIG_ADDR_WIDTH)'(R_ACC_PARTS);
          next_state = S_NEXT_E;
        end else begin
          next_aux_w = aux_w + 1;
          next_state = S_AUX_RD;
        end
      end

      // ========================================================
      // Advance to next e
      // ========================================================
      S_NEXT_E: begin
        if (e == E_WIDTH'(TAU - 1)) begin
          // alt: all e done -> finalize hcom, then compute haux
          next_state = S_HCOM_DRAIN;
        end else begin
          next_e = e + 1;
          next_leaf_base = (GGM_TREE_DEPTH+1)'(e + 1);  // new e, i=0 -> 0*TAU + (e+1)
          next_leaf_buf_valid = 1'b0;
          next_state = S_GET_LEAF;
        end
      end

      // ========================================================
      // HCOM finalize: drain remaining packing buffer bytes as last word.
      // ========================================================
      S_HCOM_DRAIN: begin
        if (pack_cnt > 4'd0) begin
          shake_din_o           = {pack_buf, 8'd0};
          shake_din_valid_o     = 1'b1;
          shake_last_din_o      = 1'b1;
          shake_last_din_byte_o = pack_cnt;
          if (shake_din_ready_i) begin
            next_pack_cnt       = '0;
            next_pack_buf       = '0;
            next_hcom_squeeze_w = '0;
            next_state          = S_HCOM_SQUEEZE;
          end
        end else begin
          next_hcom_squeeze_w = '0;
          next_state          = S_HCOM_SQUEEZE;
        end
      end

      // ========================================================
      // Squeeze 2*LAMBDA bits of hcom into var BRAM at HCOM_VAR_OFFSET.
      // ========================================================
      S_HCOM_SQUEEZE: begin
        shake_dout_ready_o = 1'b1;
        if (shake_dout_valid_i) begin
          int_var_a_data = shake_dout_i;
          int_var_a_addr = VAR_ADDR_WIDTH_COMBINED'(HCOM_VAR_OFFSET + hcom_squeeze_w);
          int_var_a_wr   = 1'b1;
          int_var_b_data = shake_dout_i;
          int_var_b_addr = VAR_ADDR_WIDTH_COMBINED'(HCOM_VAR_OFFSET + hcom_squeeze_w);
          int_var_b_wr   = CAN_DUAL ? 1'b0 : 1'b1;
          if (hcom_squeeze_w == HCOM_SQ_BITS'(HCOM_WORDS - 1)) begin
            // hcom now in var BRAM; reset packing for haux
            next_pack_buf = '0;
            next_pack_cnt = '0;
            next_state    = S_HAUX_START;
          end else begin
            next_hcom_squeeze_w = hcom_squeeze_w + 1;
          end
        end
      end

      // ========================================================
      // HAUX: Start SHAKE, load prefix byte into packing buffer
      // C reference: SHAKE(0x02 || hash_com || corr_u)
      // ========================================================
      S_HAUX_START: begin
        shake_start_o        = 1'b1;
        next_hash_w          = '0;
        next_e               = E_WIDTH'(1);
        next_sig_aux_base    = (SIG_ADDR_WIDTH)'(AUX_OFFSET);  // e=1 -> (1-1)*R_ACC_PARTS = 0
        next_pack_cnt        = 4'd1;
        next_pack_buf        = {HASH_AUX_PREFIX, 48'd0};
        // Prime var BRAM read for first hcom word
        int_var_a_addr = VAR_ADDR_WIDTH_COMBINED'(HCOM_VAR_OFFSET);
        int_var_b_addr = VAR_ADDR_WIDTH_COMBINED'(HCOM_VAR_OFFSET);
        next_state           = S_HAUX_HCOM;
      end

      // ========================================================
      // HAUX: Load hcom word from var BRAM into packing buffer
      // ========================================================
      S_HAUX_HCOM: begin
        int_var_a_addr = VAR_ADDR_WIDTH_COMBINED'(HCOM_VAR_OFFSET + hash_w);
        int_var_b_addr = VAR_ADDR_WIDTH_COMBINED'(HCOM_VAR_OFFSET + hash_w);
        begin
          logic [63:0]  hcom_word;
          logic [119:0] combined;
          logic [3:0]   total;

          hcom_word = combine_ab();

          case (pack_cnt)
            0: combined = {hcom_word, 56'd0};
            1: combined = {pack_buf[55:48], hcom_word, 48'd0};
            2: combined = {pack_buf[55:40], hcom_word, 40'd0};
            3: combined = {pack_buf[55:32], hcom_word, 32'd0};
            4: combined = {pack_buf[55:24], hcom_word, 24'd0};
            5: combined = {pack_buf[55:16], hcom_word, 16'd0};
            6: combined = {pack_buf[55:8],  hcom_word,  8'd0};
            7: combined = {pack_buf[55:0],  hcom_word       };
            default: combined = {hcom_word, 56'd0};
          endcase
          total = pack_cnt + 4'd8;

          shake_din_o       = combined[119:56];
          shake_din_valid_o = 1'b1;

          if (shake_din_ready_i) begin
            next_pack_buf = combined[55:0];
            next_pack_cnt = total - 4'd8;

            if (hash_w == ($clog2(HCOM_WORDS+1))'(HCOM_WORDS - 1)) begin
              next_hash_w = '0;
              next_state  = S_HAUX_AUX_PRIME;
            end else begin
              next_hash_w = hash_w + 1;
              next_state  = S_HAUX_HCOM_PRIME;
            end
          end
        end
      end

      // ========================================================
      // HAUX: Prime var BRAM for next hcom word (1-cycle latency)
      // ========================================================
      S_HAUX_HCOM_PRIME: begin
        int_var_a_addr = VAR_ADDR_WIDTH_COMBINED'(HCOM_VAR_OFFSET + hash_w);
        int_var_b_addr = VAR_ADDR_WIDTH_COMBINED'(HCOM_VAR_OFFSET + hash_w);
        next_state = S_HAUX_HCOM;
      end

      // ========================================================
      // HAUX: Prime sig memory read (1-cycle BRAM latency)
      // ========================================================
      S_HAUX_AUX_PRIME: begin
        sig_addr_o = sig_aux_base + (SIG_ADDR_WIDTH)'(hash_w);
        next_state = S_HAUX_AUX_FEED;
      end

      // ========================================================
      // HAUX: Load bswapped sig word into packing buffer, emit if full
      // ========================================================
      S_HAUX_AUX_FEED: begin
        begin
          logic [63:0]  new_data;
          logic [3:0]   new_bytes;
          logic         is_last_word;
          logic [119:0] combined;
          logic [3:0]   total;

          new_data     = bswap64(sig_data_i);
          is_last_word = (hash_w == ($clog2(R_ACC_PARTS)+1)'(R_ACC_PARTS - 1));
          new_bytes    = is_last_word ?
                         ((R_ACC_SIZE_BYTES % 8 == 0) ? 4'd8 : 4'(R_ACC_SIZE_BYTES % 8))
                         : 4'd8;

          case (pack_cnt)
            0: combined = {new_data, 56'd0};
            1: combined = {pack_buf[55:48], new_data, 48'd0};
            2: combined = {pack_buf[55:40], new_data, 40'd0};
            3: combined = {pack_buf[55:32], new_data, 32'd0};
            4: combined = {pack_buf[55:24], new_data, 24'd0};
            5: combined = {pack_buf[55:16], new_data, 16'd0};
            6: combined = {pack_buf[55:8],  new_data,  8'd0};
            7: combined = {pack_buf[55:0],  new_data       };
            default: combined = {new_data, 56'd0};
          endcase
          total = pack_cnt + new_bytes;

          if (total >= 4'd8) begin
            shake_din_o       = combined[119:56];
            shake_din_valid_o = 1'b1;

            if (is_last_word && e == TAU - 1 && total == 4'd8) begin
              shake_last_din_o      = 1'b1;
              shake_last_din_byte_o = 4'd8;
            end

            if (shake_din_ready_i) begin
              next_pack_buf = combined[55:0];
              next_pack_cnt = total - 4'd8;

              if (is_last_word) begin
                next_hash_w = '0;
                if (e == TAU - 1) begin
                  if ((total - 4'd8) > 4'd0)
                    next_state = S_HAUX_DRAIN;
                  else begin
                    next_squeeze_w = '0;
                    next_state     = S_HAUX_SQUEEZE;
                  end
                end else begin
                  next_e     = e + 1;
                  next_sig_aux_base = sig_aux_base + (SIG_ADDR_WIDTH)'(R_ACC_PARTS);
                  next_state = S_HAUX_AUX_PRIME;
                end
              end else begin
                next_hash_w = hash_w + 1;
                next_state  = S_HAUX_AUX_PRIME;
              end
            end
          end else begin
            next_pack_buf = combined[119:64];
            next_pack_cnt = total;

            if (is_last_word) begin
              next_hash_w = '0;
              if (e == TAU - 1) begin
                next_state = S_HAUX_DRAIN;
              end else begin
                next_e     = e + 1;
                next_sig_aux_base = sig_aux_base + (SIG_ADDR_WIDTH)'(R_ACC_PARTS);
                next_state = S_HAUX_AUX_PRIME;
              end
            end else begin
              next_hash_w = hash_w + 1;
              next_state  = S_HAUX_AUX_PRIME;
            end
          end
        end
      end

      // ========================================================
      // HAUX: Drain remaining bytes as last SHAKE word
      // ========================================================
      S_HAUX_DRAIN: begin
        if (pack_cnt > 4'd0) begin
          shake_din_o           = {pack_buf, 8'd0};
          shake_din_valid_o     = 1'b1;
          shake_last_din_o      = 1'b1;
          shake_last_din_byte_o = pack_cnt;
          if (shake_din_ready_i) begin
            next_pack_cnt  = '0;
            next_squeeze_w = '0;
            next_state     = S_HAUX_SQUEEZE;
          end
        end else begin
          next_squeeze_w = '0;
          next_state     = S_HAUX_SQUEEZE;
        end
      end

      // ========================================================
      // HAUX: Squeeze haux from SHAKE -> write to cache or var BRAM
      // ========================================================
      S_HAUX_SQUEEZE: begin
        shake_dout_ready_o = 1'b1;

        if (shake_dout_valid_i) begin
          if (USE_CACHE) begin
            cache_addr_o  = (CACHE_ADDR_WIDTH)'(CACHE_HAUX_OFFSET + squeeze_w);
            cache_data_o  = shake_dout_i;
            cache_wr_en_o = 1'b1;
          end else begin
            int_var_a_data = shake_dout_i;
            int_var_a_addr = VAR_ADDR_WIDTH_COMBINED'(HAUX_VAR_OFFSET + squeeze_w);
            int_var_a_wr   = 1'b1;
            int_var_b_data = shake_dout_i;
            int_var_b_addr = VAR_ADDR_WIDTH_COMBINED'(HAUX_VAR_OFFSET + squeeze_w);
            int_var_b_wr   = CAN_DUAL ? 1'b0 : 1'b1;
          end

          if (squeeze_w == ($clog2(HAUX_SQUEEZE_WORDS+1))'(HAUX_SQUEEZE_WORDS - 1)) begin
            next_state = S_DONE;
          end else begin
            next_squeeze_w = squeeze_w + 1;
          end
        end
      end

      // ========================================================
      S_DONE: begin
        fsm_done_o = 1'b1;
      end

    endcase
  end
  // Sequential

  always_ff @(posedge clk_i or posedge rst_i) begin
    if (rst_i) begin
      state          <= S_IDLE;
      e              <= '0;
      aux_w          <= '0;
      aux_r0         <= '0;
      hash_w         <= '0;
      squeeze_w      <= '0;
      pack_buf       <= '0;
      pack_cnt       <= '0;
      sig_aux_base   <= '0;
      leaf_base      <= '0;
      leaf_buf       <= '0;
      leaf_buf_valid <= 1'b0;
      commit_leaf1_r <= '0;
      commit_leaf2_r <= '0;
      commit_idx1_r  <= '0;
      commit_idx2_r  <= '0;
      need_commit_for_pair <= 1'b0;
      commit1_lo_r   <= '0;
      commit1_hi_r   <= '0;
      commit2_lo_r   <= '0;
      commit2_hi_r   <= '0;
      hcom_which_leaf   <= 1'b0;
      hcom_which_half   <= 1'b0;
      hcom_word_in_half <= '0;
      hcom_feed_active  <= 1'b0;
      hcom_squeeze_w <= '0;
    end else if (!var_stall_i) begin
      state          <= next_state;
      e              <= next_e;
      aux_w          <= next_aux_w;
      sig_aux_base   <= next_sig_aux_base;
      leaf_base      <= next_leaf_base;
      leaf_buf       <= next_leaf_buf;
      leaf_buf_valid <= next_leaf_buf_valid;
      aux_r0         <= next_aux_r0;
      hash_w         <= next_hash_w;
      squeeze_w      <= next_squeeze_w;
      pack_buf        <= next_pack_buf;
      pack_cnt        <= next_pack_cnt;
      commit_leaf1_r <= next_commit_leaf1_r;
      commit_leaf2_r <= next_commit_leaf2_r;
      commit_idx1_r  <= next_commit_idx1_r;
      commit_idx2_r  <= next_commit_idx2_r;
      need_commit_for_pair <= next_need_commit_for_pair;
      commit1_lo_r   <= next_commit1_lo_r;
      commit1_hi_r   <= next_commit1_hi_r;
      commit2_lo_r   <= next_commit2_lo_r;
      commit2_hi_r   <= next_commit2_hi_r;
      hcom_which_leaf   <= next_hcom_which_leaf;
      hcom_which_half   <= next_hcom_which_half;
      hcom_word_in_half <= next_hcom_word_in_half;
      hcom_feed_active  <= next_hcom_feed_active;
      hcom_squeeze_w <= next_hcom_squeeze_w;
    end
  end

endmodule
