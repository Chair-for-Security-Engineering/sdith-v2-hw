// SPDX-FileCopyrightText: 2026 Stef Halmans, Niklas Höher
// SPDX-License-Identifier: LicenseRef-RUB-SecEng

import sdith_params_pkg::*;
import sdith_helpers_pkg::*;

// piop
//
// PIOP prover stage. Loops over the V chunks: for each chunk it runs
// GenerateV (generate_pwit_chunk or generate_pwit_half), a transpose
// where needed, and ProcessPwit. After the last chunk it computes the
// h_piop Fiat-Shamir hash.
//
// HALF_POLY=0: NUM_PWIT_CHUNKS chunks of at most lambda V rows each,
// with an in-place TransposeV step between generation and processing
// (V is PRG-sampled column-wise but consumed row-wise).
// HALF_POLY=1: two passes over half of the P_wit rows each; the
// transpose is interleaved with generation inside generate_pwit_half,
// so there is no separate transpose stage.
//
// Resource usage per sub-phase:
//   generate_pwit_*: AES0 + AES1 + leaf cache + scratchpad
//   process_pwit:    SHAKE + key memory + scratchpad + AES (H' columns)
//   hash_piop:       SHAKE + key/msg/sig memory

module piop (
    input  logic clk_i,
    input  logic rst_i,

    // Control
    input  logic fsm_enable_i,
    output logic fsm_done_o,

    // Leaf cache interface (for generate_pwit_chunk)
    output logic                     get_next_leaf_o,
    input  logic                     leaf_done_i,
    output logic [GGM_TREE_DEPTH:0]  leaf_idx_o,
    output logic [GGM_TREE_DEPTH:0]  leaf_idx2_o,
    input  logic [LAMBDA-1:0]        leaf_i,
    input  logic [LAMBDA-1:0]        leaf2_i,

    // AES0 (for generate_pwit_chunk)
    output logic [ENC_KEYSIZE-1:0]   aes0_key_o,
    output logic [ENC_BLOCKSIZE-1:0] aes0_plaintext_o,
    input  logic [ENC_BLOCKSIZE-1:0] aes0_ciphertext_i,
    output logic                     aes0_enable_o,
    input  logic                     aes0_ready_i,
    input  logic                     aes0_valid_i,

    // AES1 (for generate_pwit_chunk)
    output logic [ENC_KEYSIZE-1:0]   aes1_key_o,
    output logic [ENC_BLOCKSIZE-1:0] aes1_plaintext_o,
    input  logic [ENC_BLOCKSIZE-1:0] aes1_ciphertext_i,
    output logic                     aes1_enable_o,
    input  logic                     aes1_ready_i,
    input  logic                     aes1_valid_i,

    // PRG owns AES flag (from generate_pwit_chunk, for AES mux in sign.sv)
    output logic prg_owns_aes_o,

    // SHAKE (for process_pwit + hash_piop)
    output logic        shake_start_o,
    output logic        shake_mode_o,
    output logic [63:0] shake_din_o,
    output logic        shake_din_valid_o,
    output logic        shake_last_din_o,
    output logic [ 3:0] shake_last_din_byte_o,
    output logic        shake_dout_ready_o,
    input  logic        shake_din_ready_i,
    input  logic [63:0] shake_dout_i,
    input  logic        shake_dout_valid_i,

    // Var BRAM dual-port
    input  logic [VAR_DATA_WIDTH_COMBINED-1:0] var_a_data_i,
    output logic [VAR_DATA_WIDTH_COMBINED-1:0] var_a_data_o,
    output logic [VAR_ADDR_WIDTH_COMBINED-1:0] var_a_addr_o,
    output logic                               var_a_wr_en_o,
    input  logic [VAR_DATA_WIDTH_COMBINED-1:0] var_b_data_i,
    output logic [VAR_DATA_WIDTH_COMBINED-1:0] var_b_data_o,
    output logic [VAR_ADDR_WIDTH_COMBINED-1:0] var_b_addr_o,
    output logic                               var_b_wr_en_o,

    // Key memory (read-only, for process_pwit and hash_piop)
    input  logic [63:0]             key_data_i,
    output logic [BRAM_ADDR_SIZE:0] key_addr_o,

    // Message memory (read-only, for hash_piop - word 0 = msg length in bytes)
    input  logic [63:0]               msg_data_i,
    output logic [MSG_ADDR_WIDTH-1:0] msg_addr_o,

    // Signature memory (for writing results)
    input  logic [63:0]              sig_data_i,
    output logic [63:0]              sig_data_o,
    output logic [SIG_ADDR_WIDTH-1:0] sig_addr_o,
    output logic                     sig_wr_en_o,

    // hash_lines seed (from blc_commit_hlines, stable before PIOP starts).
    input  logic [2*LAMBDA-1:0]      hlines_i
);

  // =========================================================================
  // h_piop sub-FSM parameters
  // =========================================================================
  localparam int HP_PKSEED_WORDS = CHUNK_WORDS;
  localparam int HP_HLINES_WORDS = 2 * LAMBDA_DIV_64;
  localparam int HP_CZ_WORDS     = PALPHA_SIG_WORDS;
  localparam int HP_OUT_WORDS    = H_PIOP_SIG_SIZE;
  localparam int HP_MSG_MAX_W    = MSG_MEM_WORDS - 1;
  localparam int HP_WCW          = $clog2(HP_MSG_MAX_W + 1);
  localparam logic HP_SHAKE_MODE = (HASH_XOF == HASH_SHAKE256) ? 1'b1 : 1'b0;

  typedef enum logic [3:0] {
    HP_IDLE,
    HP_START,
    HP_PKSEED_PRIME,
    HP_PKSEED_FEED,
    HP_HLINES_FEED,
    HP_CZ_PRIME,
    HP_CZ_FEED,
    HP_MSG_LEN_PRIME,
    HP_MSG_LEN,
    HP_MSG_PRIME,
    HP_MSG_FEED,
    HP_DRAIN,
    HP_SQUEEZE
  } hp_state_t;

  hp_state_t                hp_state, next_hp_state;
  logic [HP_WCW-1:0]        hp_w, next_hp_w;
  logic [55:0]              hp_pack_buf, next_hp_pack_buf;
  logic [3:0]               hp_pack_cnt, next_hp_pack_cnt;
  logic [15:0]              hp_msg_len, next_hp_msg_len;
  logic [15:0]              hp_msg_bytes_left;
  logic                     hp_is_last;

  // h_piop packing buffer combiner (shared across all feed states)
  logic [63:0]  hp_new_data;
  logic [119:0] hp_combined;
  always_comb begin
    case (hp_pack_cnt)
      0: hp_combined = {hp_new_data, 56'd0};
      1: hp_combined = {hp_pack_buf[55:48], hp_new_data, 48'd0};
      2: hp_combined = {hp_pack_buf[55:40], hp_new_data, 40'd0};
      3: hp_combined = {hp_pack_buf[55:32], hp_new_data, 32'd0};
      4: hp_combined = {hp_pack_buf[55:24], hp_new_data, 24'd0};
      5: hp_combined = {hp_pack_buf[55:16], hp_new_data, 16'd0};
      6: hp_combined = {hp_pack_buf[55:8],  hp_new_data,  8'd0};
      7: hp_combined = {hp_pack_buf[55:0],  hp_new_data       };
      default: hp_combined = {hp_new_data, 56'd0};
    endcase
  end

  // h_piop SHAKE / sig / key / msg output signals (muxed at top level)
  logic                     hp_shake_start;
  logic [63:0]              hp_shake_din;
  logic                     hp_shake_din_valid;
  logic                     hp_shake_last_din;
  logic [3:0]               hp_shake_last_din_byte;
  logic                     hp_shake_dout_ready;
  logic [SIG_ADDR_WIDTH-1:0] hp_sig_addr;
  logic [63:0]              hp_sig_data;
  logic                     hp_sig_wr_en;
  logic [BRAM_ADDR_SIZE:0]  hp_key_addr;
  logic [MSG_ADDR_WIDTH-1:0] hp_msg_addr;

  typedef enum logic [2:0] {
    S_IDLE,
    S_GEN_PWIT,
    S_TRANSPOSE,
    S_PROC_PWIT,
    S_HASH_PIOP,
    S_DONE
  } piop_state_t;

  piop_state_t state, next_state;

  // Loop counter: chunk_idx (5-chunk mode) or pass_idx (half-poly mode)
  localparam LOOP_MAX = (HALF_POLY == 0) ? NUM_PWIT_CHUNKS : 2;
  localparam LW = (LOOP_MAX > 1) ? $clog2(LOOP_MAX) : 1;
  logic [LW-1:0] loop_idx, next_loop_idx;

  // generate_pwit
  logic gen_start, gen_done;

  logic [VAR_DATA_WIDTH_COMBINED-1:0] gen_var_a_data_o, gen_var_b_data_o;
  logic [VAR_ADDR_WIDTH_COMBINED-1:0] gen_var_a_addr_o, gen_var_b_addr_o;
  logic                               gen_var_a_wr_en_o, gen_var_b_wr_en_o;

  // Local wires for AES owned by generate_pwit* (muxed below with process_pwit).
  logic [ENC_KEYSIZE-1:0]   gen_aes0_key, gen_aes1_key;
  logic [ENC_BLOCKSIZE-1:0] gen_aes0_pt,  gen_aes1_pt;
  logic                     gen_aes0_en,  gen_aes1_en;
  logic                     gen_prg_owns_aes;

  generate
    if (HALF_POLY == 0) begin : g_gen_chunk
      generate_pwit_chunk u_gen_pwit (
          .clk_i            (clk_i),
          .rst_i            (rst_i),
          .fsm_start_i      (gen_start),
          .fsm_done_o       (gen_done),
          .chunk_idx_i      (loop_idx[$clog2(NUM_PWIT_CHUNKS)-1:0]),
          // Leaf cache
          .get_next_leaf_o  (get_next_leaf_o),
          .leaf_done_i      (leaf_done_i),
          .leaf_idx_o       (leaf_idx_o),
          .leaf_idx2_o      (leaf_idx2_o),
          .leaf_i           (leaf_i),
          .leaf2_i          (leaf2_i),
          // AES0
          .aes0_key_o       (gen_aes0_key),
          .aes0_plaintext_o (gen_aes0_pt),
          .aes0_ciphertext_i(aes0_ciphertext_i),
          .aes0_enable_o    (gen_aes0_en),
          .aes0_ready_i     (aes0_ready_i),
          .aes0_valid_i     (aes0_valid_i),
          // AES1
          .aes1_key_o       (gen_aes1_key),
          .aes1_plaintext_o (gen_aes1_pt),
          .aes1_ciphertext_i(aes1_ciphertext_i),
          .aes1_enable_o    (gen_aes1_en),
          .aes1_ready_i     (aes1_ready_i),
          .aes1_valid_i     (aes1_valid_i),
          // PRG ownership
          .prg_owns_aes_o   (gen_prg_owns_aes),
          // Var BRAM
          .var_a_data_i     (var_a_data_i),
          .var_a_data_o     (gen_var_a_data_o),
          .var_a_addr_o     (gen_var_a_addr_o),
          .var_a_wr_en_o    (gen_var_a_wr_en_o),
          .var_b_data_i     (var_b_data_i),
          .var_b_data_o     (gen_var_b_data_o),
          .var_b_addr_o     (gen_var_b_addr_o),
          .var_b_wr_en_o    (gen_var_b_wr_en_o)
      );
    end else begin : g_gen_half
      generate_pwit_half u_gen_pwit (
          .clk_i            (clk_i),
          .rst_i            (rst_i),
          .fsm_start_i      (gen_start),
          .fsm_done_o       (gen_done),
          .pass_idx_i       (loop_idx[0]),
          // Leaf cache
          .get_next_leaf_o  (get_next_leaf_o),
          .leaf_done_i      (leaf_done_i),
          .leaf_idx_o       (leaf_idx_o),
          .leaf_idx2_o      (leaf_idx2_o),
          .leaf_i           (leaf_i),
          .leaf2_i          (leaf2_i),
          // AES0
          .aes0_key_o       (gen_aes0_key),
          .aes0_plaintext_o (gen_aes0_pt),
          .aes0_ciphertext_i(aes0_ciphertext_i),
          .aes0_enable_o    (gen_aes0_en),
          .aes0_ready_i     (aes0_ready_i),
          .aes0_valid_i     (aes0_valid_i),
          // AES1
          .aes1_key_o       (gen_aes1_key),
          .aes1_plaintext_o (gen_aes1_pt),
          .aes1_ciphertext_i(aes1_ciphertext_i),
          .aes1_enable_o    (gen_aes1_en),
          .aes1_ready_i     (aes1_ready_i),
          .aes1_valid_i     (aes1_valid_i),
          // PRG ownership
          .prg_owns_aes_o   (gen_prg_owns_aes),
          // Var BRAM
          .var_a_data_i     (var_a_data_i),
          .var_a_data_o     (gen_var_a_data_o),
          .var_a_addr_o     (gen_var_a_addr_o),
          .var_a_wr_en_o    (gen_var_a_wr_en_o),
          .var_b_data_i     (var_b_data_i),
          .var_b_data_o     (gen_var_b_data_o),
          .var_b_addr_o     (gen_var_b_addr_o),
          .var_b_wr_en_o    (gen_var_b_wr_en_o)
      );
    end
  endgenerate

  // transpose_pwit (only used for HALF_POLY == 0)
  logic transpose_start, transpose_done;

  logic [VAR_DATA_WIDTH_COMBINED-1:0] xpose_var_a_data_o, xpose_var_b_data_o;
  logic [VAR_ADDR_WIDTH_COMBINED-1:0] xpose_var_a_addr_o, xpose_var_b_addr_o;
  logic                               xpose_var_a_wr_en_o, xpose_var_b_wr_en_o;

  generate
    if (HALF_POLY == 0) begin : g_transpose
      transpose_pwit u_transpose (
          .clk_i        (clk_i),
          .rst_i        (rst_i),
          .fsm_start_i  (transpose_start),
          .fsm_done_o   (transpose_done),
          .var_a_data_i  (var_a_data_i),
          .var_a_data_o  (xpose_var_a_data_o),
          .var_a_addr_o  (xpose_var_a_addr_o),
          .var_a_wr_en_o (xpose_var_a_wr_en_o),
          .var_b_data_i  (var_b_data_i),
          .var_b_data_o  (xpose_var_b_data_o),
          .var_b_addr_o  (xpose_var_b_addr_o),
          .var_b_wr_en_o (xpose_var_b_wr_en_o)
      );
    end else begin : g_no_transpose
      assign transpose_done    = 1'b0;
      assign xpose_var_a_data_o = '0;
      assign xpose_var_a_addr_o = '0;
      assign xpose_var_a_wr_en_o = 1'b0;
      assign xpose_var_b_data_o = '0;
      assign xpose_var_b_addr_o = '0;
      assign xpose_var_b_wr_en_o = 1'b0;
    end
  endgenerate;

  // process_pwit
  logic proc_start, proc_done;

  logic        proc_shake_start, proc_shake_mode;
  logic [63:0] proc_shake_din;
  logic        proc_shake_din_valid, proc_shake_last_din;
  logic [3:0]  proc_shake_last_din_byte;
  logic        proc_shake_dout_ready;

  logic [VAR_DATA_WIDTH_COMBINED-1:0] proc_var_a_data_o, proc_var_b_data_o;
  logic [VAR_ADDR_WIDTH_COMBINED-1:0] proc_var_a_addr_o, proc_var_b_addr_o;
  logic                               proc_var_a_wr_en_o, proc_var_b_wr_en_o;

  logic [BRAM_ADDR_SIZE:0] proc_key_addr_o;

  // process_pwit's sig-mem and AES ports (muxed below).
  logic [63:0]               proc_sig_data_o;
  logic [SIG_ADDR_WIDTH-1:0] proc_sig_addr_o;
  logic                      proc_sig_wr_en_o;

  logic [ENC_KEYSIZE-1:0]   proc_aes0_key, proc_aes1_key;
  logic [ENC_BLOCKSIZE-1:0] proc_aes0_pt,  proc_aes1_pt;
  logic                     proc_aes0_en,  proc_aes1_en;

  process_pwit u_proc_pwit (
      .clk_i            (clk_i),
      .rst_i            (rst_i),
      .fsm_start_i      (proc_start),
      .fsm_done_o       (proc_done),
      .chunk_idx_i      (($clog2(NUM_PWIT_CHUNKS))'(loop_idx)),
      // SHAKE
      .shake_start_o        (proc_shake_start),
      .shake_mode_o         (proc_shake_mode),
      .shake_din_o          (proc_shake_din),
      .shake_din_valid_o    (proc_shake_din_valid),
      .shake_last_din_o     (proc_shake_last_din),
      .shake_last_din_byte_o(proc_shake_last_din_byte),
      .shake_dout_ready_o   (proc_shake_dout_ready),
      .shake_din_ready_i    (shake_din_ready_i),
      .shake_dout_i         (shake_dout_i),
      .shake_dout_valid_i   (shake_dout_valid_i),
      // Key memory
      .key_data_i       (key_data_i),
      .key_addr_o       (proc_key_addr_o),
      // Var BRAM
      .var_a_data_i     (var_a_data_i),
      .var_a_data_o     (proc_var_a_data_o),
      .var_a_addr_o     (proc_var_a_addr_o),
      .var_a_wr_en_o    (proc_var_a_wr_en_o),
      .var_b_data_i     (var_b_data_i),
      .var_b_data_o     (proc_var_b_data_o),
      .var_b_addr_o     (proc_var_b_addr_o),
      .var_b_wr_en_o    (proc_var_b_wr_en_o),
      // hlines seed for gamma, gamma' derivation
      .dbg_i_limit_i    ('1),
      .hlines_i         (hlines_i),
      // Sig memory (Palpha readback + P0 read on final chunk)
      .sig_data_i       (sig_data_i),
      .sig_data_o       (proc_sig_data_o),
      .sig_addr_o       (proc_sig_addr_o),
      .sig_wr_en_o      (proc_sig_wr_en_o),
      // AES (H' column stream)
      .aes0_key_o       (proc_aes0_key),
      .aes0_plaintext_o (proc_aes0_pt),
      .aes0_ciphertext_i(aes0_ciphertext_i),
      .aes0_enable_o    (proc_aes0_en),
      .aes0_ready_i     (aes0_ready_i),
      .aes0_valid_i     (aes0_valid_i),
      .aes1_key_o       (proc_aes1_key),
      .aes1_plaintext_o (proc_aes1_pt),
      .aes1_ciphertext_i(aes1_ciphertext_i),
      .aes1_enable_o    (proc_aes1_en),
      .aes1_ready_i     (aes1_ready_i),
      .aes1_valid_i     (aes1_valid_i),
      // Debug taps (TB-only; dangling in the full sign build).
      .dbg_gamma_o      (/* unused at piop level */),
      .dbg_gamma_p_o    (/* unused at piop level */),
      .dbg_i_cnt_o      (/* unused at piop level */),
      .dbg_state_o         (/* unused */),
      .dbg_delta_o         (/* unused */),
      .dbg_acc1_o          (/* unused */),
      .dbg_v_lo_o          (/* unused */),
      .dbg_base_o          (/* unused */),
      .dbg_mul_out_o       (/* unused */),
      .dbg_mul_out_valid_o (/* unused */)
  );

  // Var memory mux: gen_pwit / transpose / process_pwit
  always_comb begin
    if (state == S_GEN_PWIT) begin
      var_a_data_o  = gen_var_a_data_o;
      var_a_addr_o  = gen_var_a_addr_o;
      var_a_wr_en_o = gen_var_a_wr_en_o;
      var_b_data_o  = gen_var_b_data_o;
      var_b_addr_o  = gen_var_b_addr_o;
      var_b_wr_en_o = gen_var_b_wr_en_o;
    end else if (state == S_TRANSPOSE) begin
      var_a_data_o  = xpose_var_a_data_o;
      var_a_addr_o  = xpose_var_a_addr_o;
      var_a_wr_en_o = xpose_var_a_wr_en_o;
      var_b_data_o  = xpose_var_b_data_o;
      var_b_addr_o  = xpose_var_b_addr_o;
      var_b_wr_en_o = xpose_var_b_wr_en_o;
    end else if (state == S_PROC_PWIT) begin
      var_a_data_o  = proc_var_a_data_o;
      var_a_addr_o  = proc_var_a_addr_o;
      var_a_wr_en_o = proc_var_a_wr_en_o;
      var_b_data_o  = proc_var_b_data_o;
      var_b_addr_o  = proc_var_b_addr_o;
      var_b_wr_en_o = proc_var_b_wr_en_o;
    end else begin
      var_a_data_o  = '0;
      var_a_addr_o  = '0;
      var_a_wr_en_o = 1'b0;
      var_b_data_o  = '0;
      var_b_addr_o  = '0;
      var_b_wr_en_o = 1'b0;
    end
  end

  // SHAKE mux: process_pwit (S_PROC_PWIT) vs hash_piop (S_HASH_PIOP)
  always_comb begin
    if (state == S_PROC_PWIT) begin
      shake_start_o        = proc_shake_start;
      shake_mode_o         = proc_shake_mode;
      shake_din_o          = proc_shake_din;
      shake_din_valid_o    = proc_shake_din_valid;
      shake_last_din_o     = proc_shake_last_din;
      shake_last_din_byte_o = proc_shake_last_din_byte;
      shake_dout_ready_o   = proc_shake_dout_ready;
    end else if (state == S_HASH_PIOP) begin
      shake_start_o        = hp_shake_start;
      shake_mode_o         = HP_SHAKE_MODE;
      shake_din_o          = hp_shake_din;
      shake_din_valid_o    = hp_shake_din_valid;
      shake_last_din_o     = hp_shake_last_din;
      shake_last_din_byte_o = hp_shake_last_din_byte;
      shake_dout_ready_o   = hp_shake_dout_ready;
    end else begin
      shake_start_o        = 1'b0;
      shake_mode_o         = 1'b0;
      shake_din_o          = 64'b0;
      shake_din_valid_o    = 1'b0;
      shake_last_din_o     = 1'b0;
      shake_last_din_byte_o = 4'd0;
      shake_dout_ready_o   = 1'b0;
    end
  end

  assign key_addr_o = (state == S_HASH_PIOP) ? hp_key_addr : proc_key_addr_o;
  assign msg_addr_o = hp_msg_addr;

  // Sig memory mux: process_pwit drives during S_PROC_PWIT, hash_piop
  // drives during S_HASH_PIOP (reads circuit_cz_pub, writes h_piop).
  always_comb begin
    if (state == S_PROC_PWIT) begin
      sig_data_o  = proc_sig_data_o;
      sig_addr_o  = proc_sig_addr_o;
      sig_wr_en_o = proc_sig_wr_en_o;
    end else if (state == S_HASH_PIOP) begin
      sig_data_o  = hp_sig_data;
      sig_addr_o  = hp_sig_addr;
      sig_wr_en_o = hp_sig_wr_en;
    end else begin
      sig_data_o  = 64'b0;
      sig_addr_o  = '0;
      sig_wr_en_o = 1'b0;
    end
  end

  // AES mux (3-way): generate_pwit drives during S_GEN_PWIT, process_pwit
  // drives during S_PROC_PWIT, else idle. prg_owns_aes_o forwards the
  // gen child's signal in S_GEN_PWIT, and is forced high during S_PROC_PWIT
  // (process_pwit owns AES exclusively).
  always_comb begin
    case (state)
      S_GEN_PWIT: begin
        aes0_key_o       = gen_aes0_key;
        aes0_plaintext_o = gen_aes0_pt;
        aes0_enable_o    = gen_aes0_en;
        aes1_key_o       = gen_aes1_key;
        aes1_plaintext_o = gen_aes1_pt;
        aes1_enable_o    = gen_aes1_en;
        prg_owns_aes_o   = gen_prg_owns_aes;
      end
      S_PROC_PWIT: begin
        aes0_key_o       = proc_aes0_key;
        aes0_plaintext_o = proc_aes0_pt;
        aes0_enable_o    = proc_aes0_en;
        aes1_key_o       = proc_aes1_key;
        aes1_plaintext_o = proc_aes1_pt;
        aes1_enable_o    = proc_aes1_en;
        prg_owns_aes_o   = 1'b1;
      end
      default: begin
        aes0_key_o       = '0;
        aes0_plaintext_o = '0;
        aes0_enable_o    = 1'b0;
        aes1_key_o       = '0;
        aes1_plaintext_o = '0;
        aes1_enable_o    = 1'b0;
        prg_owns_aes_o   = 1'b0;
      end
    endcase
  end

  // FSM: loops generate -> process for each iteration (5 chunks or 2 passes),
  // then hashes.
  always_comb begin
    next_state      = state;
    next_loop_idx   = loop_idx;
    fsm_done_o      = 1'b0;
    gen_start       = 1'b0;
    transpose_start = 1'b0;
    proc_start      = 1'b0;

    case (state)
      S_IDLE: begin
        if (fsm_enable_i) begin
          next_loop_idx = '0;
          gen_start     = 1'b1;
          next_state    = S_GEN_PWIT;
        end
      end

      S_GEN_PWIT: begin
        if (gen_done) begin
          if (HALF_POLY == 0) begin
            transpose_start = 1'b1;
            next_state      = S_TRANSPOSE;
          end else begin
            proc_start = 1'b1;
            next_state = S_PROC_PWIT;
          end
        end
      end

      S_TRANSPOSE: begin
        if (transpose_done) begin
          proc_start = 1'b1;
          next_state = S_PROC_PWIT;
        end
      end

      S_PROC_PWIT: begin
        if (proc_done) begin
          if (loop_idx == LW'(LOOP_MAX - 1)) begin
            next_state = S_HASH_PIOP;
          end else begin
            next_loop_idx = loop_idx + 1;
            gen_start     = 1'b1;
            next_state    = S_GEN_PWIT;
          end
        end
      end

      S_HASH_PIOP: begin
        if (hp_state == HP_IDLE && hp_w != '0)
          next_state = S_DONE;
      end

      S_DONE: begin
        fsm_done_o = 1'b1;
        next_state = S_IDLE;
      end
    endcase
  end

  // =========================================================================
  // h_piop sub-FSM
  // Absorbs 0x04 || pkey_seed || h_lines || circuit_cz_pub || msg into SHAKE,
  // squeezes 2lambda bits into sig memory at H_PIOP_SIG_OFFSET.
  // =========================================================================
  always_comb begin
    next_hp_state    = hp_state;
    next_hp_w        = hp_w;
    next_hp_pack_buf = hp_pack_buf;
    next_hp_pack_cnt = hp_pack_cnt;
    next_hp_msg_len  = hp_msg_len;

    hp_shake_start        = 1'b0;
    hp_shake_din          = 64'b0;
    hp_shake_din_valid    = 1'b0;
    hp_shake_last_din     = 1'b0;
    hp_shake_last_din_byte = 4'd0;
    hp_shake_dout_ready   = 1'b0;
    hp_sig_addr           = '0;
    hp_sig_data           = 64'b0;
    hp_sig_wr_en          = 1'b0;
    hp_key_addr           = '0;
    hp_msg_addr           = '0;
    hp_new_data           = 64'b0;

    case (hp_state)
      HP_IDLE: begin
        if (state == S_HASH_PIOP && hp_w == '0)
          next_hp_state = HP_START;
        else if (state != S_HASH_PIOP)
          next_hp_w = '0;
      end

      HP_START: begin
        hp_shake_start   = 1'b1;
        next_hp_pack_cnt = 4'd1;
        next_hp_pack_buf = {HASH_PIOP_PREFIX, 48'd0};
        next_hp_w        = '0;
        hp_key_addr      = (BRAM_ADDR_SIZE+1)'(PKSEED_KEY_OFFSET);
        next_hp_state    = HP_PKSEED_FEED;
      end

      // -- pkey_seed from key BRAM (bswap64: LE BRAM -> SHAKE byte order) --
      HP_PKSEED_PRIME: begin
        hp_key_addr   = (BRAM_ADDR_SIZE+1)'(PKSEED_KEY_OFFSET + hp_w);
        next_hp_state = HP_PKSEED_FEED;
      end

      HP_PKSEED_FEED: begin
        hp_key_addr       = (BRAM_ADDR_SIZE+1)'(PKSEED_KEY_OFFSET + hp_w);
        hp_new_data       = bswap64(key_data_i);
        hp_shake_din      = hp_combined[119:56];
        hp_shake_din_valid = 1'b1;
        if (shake_din_ready_i) begin
          next_hp_pack_buf = hp_combined[55:0];
          next_hp_pack_cnt = hp_pack_cnt;
          if (hp_w == HP_WCW'(HP_PKSEED_WORDS - 1)) begin
            next_hp_w     = '0;
            next_hp_state = HP_HLINES_FEED;
          end else begin
            next_hp_w     = hp_w + 1;
            next_hp_state = HP_PKSEED_PRIME;
          end
        end
      end

      // -- h_lines from hlines_i register (no bswap, already SHAKE order) --
      HP_HLINES_FEED: begin
        hp_new_data        = hlines_i[hp_w*64 +: 64];
        hp_shake_din       = hp_combined[119:56];
        hp_shake_din_valid = 1'b1;
        if (shake_din_ready_i) begin
          next_hp_pack_buf = hp_combined[55:0];
          next_hp_pack_cnt = hp_pack_cnt;
          if (hp_w == HP_WCW'(HP_HLINES_WORDS - 1)) begin
            next_hp_w     = '0;
            hp_sig_addr   = SIG_ADDR_WIDTH'(PALPHA_SIG_OFFSET);
            next_hp_state = HP_CZ_FEED;
          end else begin
            next_hp_w = hp_w + 1;
          end
        end
      end

      // -- circuit_cz_pub from sig BRAM (bswap64: LE BRAM -> SHAKE order) --
      HP_CZ_PRIME: begin
        hp_sig_addr   = SIG_ADDR_WIDTH'(PALPHA_SIG_OFFSET + hp_w);
        next_hp_state = HP_CZ_FEED;
      end

      HP_CZ_FEED: begin
        hp_sig_addr        = SIG_ADDR_WIDTH'(PALPHA_SIG_OFFSET + hp_w);
        hp_new_data        = bswap64(sig_data_i);
        hp_shake_din       = hp_combined[119:56];
        hp_shake_din_valid = 1'b1;
        if (shake_din_ready_i) begin
          next_hp_pack_buf = hp_combined[55:0];
          next_hp_pack_cnt = hp_pack_cnt;
          if (hp_w == HP_WCW'(HP_CZ_WORDS - 1)) begin
            next_hp_w     = '0;
            hp_msg_addr   = '0;
            next_hp_state = HP_MSG_LEN_PRIME;
          end else begin
            next_hp_w     = hp_w + 1;
            next_hp_state = HP_CZ_PRIME;
          end
        end
      end

      // -- message length from msg BRAM word 0 --
      HP_MSG_LEN_PRIME: begin
        hp_msg_addr   = '0;
        next_hp_state = HP_MSG_LEN;
      end

      HP_MSG_LEN: begin
        hp_msg_addr      = '0;
        next_hp_msg_len  = msg_data_i[15:0];
        if (msg_data_i[15:0] == 16'd0) begin
          next_hp_state = HP_DRAIN;
        end else begin
          next_hp_w     = '0;
          hp_msg_addr   = MSG_ADDR_WIDTH'(1);
          next_hp_state = HP_MSG_FEED;
        end
      end

      // -- message data from msg BRAM (bswap64) --
      HP_MSG_PRIME: begin
        hp_msg_addr   = MSG_ADDR_WIDTH'(1 + hp_w);
        next_hp_state = HP_MSG_FEED;
      end

      HP_MSG_FEED: begin
        automatic logic [3:0]  new_bytes;
        automatic logic [3:0]  total;

        hp_msg_addr    = MSG_ADDR_WIDTH'(1 + hp_w);
        new_bytes      = hp_is_last ? hp_msg_bytes_left[3:0] : 4'd8;
        hp_new_data    = bswap64(msg_data_i);
        total          = hp_pack_cnt + new_bytes;

        if (total >= 4'd8) begin
          hp_shake_din       = hp_combined[119:56];
          hp_shake_din_valid = 1'b1;
          if (hp_is_last && total == 4'd8) begin
            hp_shake_last_din      = 1'b1;
            hp_shake_last_din_byte = 4'd8;
          end
          if (shake_din_ready_i) begin
            next_hp_pack_buf = hp_combined[55:0];
            next_hp_pack_cnt = total - 4'd8;
            if (hp_is_last) begin
              if (total == 4'd8) begin
                next_hp_w     = '0;
                next_hp_state = HP_SQUEEZE;
              end else
                next_hp_state = HP_DRAIN;
            end else begin
              next_hp_w     = hp_w + 1;
              next_hp_state = HP_MSG_PRIME;
            end
          end
        end else begin
          next_hp_pack_buf = hp_combined[119:64];
          next_hp_pack_cnt = total;
          if (hp_is_last)
            next_hp_state = HP_DRAIN;
          else begin
            next_hp_w     = hp_w + 1;
            next_hp_state = HP_MSG_PRIME;
          end
        end
      end

      // -- flush remaining pack buffer --
      HP_DRAIN: begin
        if (hp_pack_cnt > 4'd0) begin
          hp_shake_din           = {hp_pack_buf, 8'd0};
          hp_shake_din_valid     = 1'b1;
          hp_shake_last_din      = 1'b1;
          hp_shake_last_din_byte = hp_pack_cnt;
          if (shake_din_ready_i) begin
            next_hp_pack_cnt = '0;
            next_hp_w        = '0;
            next_hp_state    = HP_SQUEEZE;
          end
        end else begin
          next_hp_w     = '0;
          next_hp_state = HP_SQUEEZE;
        end
      end

      // -- squeeze 2lambda bits -> sig memory at H_PIOP_SIG_OFFSET --
      HP_SQUEEZE: begin
        hp_shake_dout_ready = 1'b1;
        if (shake_dout_valid_i) begin
          hp_sig_addr = SIG_ADDR_WIDTH'(H_PIOP_SIG_OFFSET + hp_w);
          hp_sig_data = shake_dout_i;
          hp_sig_wr_en = 1'b1;
          if (hp_w == HP_WCW'(HP_OUT_WORDS - 1)) begin
            next_hp_w     = HP_WCW'(1);
            next_hp_state = HP_IDLE;
          end else begin
            next_hp_w = hp_w + 1;
          end
        end
      end

      default: next_hp_state = HP_IDLE;
    endcase
  end

  always_ff @(posedge clk_i or posedge rst_i) begin
    if (rst_i) begin
      state        <= S_IDLE;
      loop_idx     <= '0;
      hp_state     <= HP_IDLE;
      hp_w         <= '0;
      hp_pack_buf  <= '0;
      hp_pack_cnt  <= '0;
      hp_msg_len   <= '0;
    end else begin
      state        <= next_state;
      loop_idx     <= next_loop_idx;
      hp_state     <= next_hp_state;
      hp_w         <= next_hp_w;
      hp_pack_buf  <= next_hp_pack_buf;
      hp_pack_cnt  <= next_hp_pack_cnt;
      hp_msg_len   <= next_hp_msg_len;
      hp_msg_bytes_left <= next_hp_msg_len - {next_hp_w[HP_WCW-1:0], 3'b0};
      hp_is_last        <= (next_hp_msg_len - {next_hp_w[HP_WCW-1:0], 3'b0}) <= 16'd8;
    end
  end

endmodule
