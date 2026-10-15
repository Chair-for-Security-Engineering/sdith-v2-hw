// SPDX-FileCopyrightText: 2026 Stef Halmans, Niklas Höher
// SPDX-License-Identifier: LicenseRef-RUB-SecEng

import sdith_params_pkg::*;

// sign
//
// Top-level signing pipeline, sequencing the five stages and muxing the
// shared resources (two Rijndael cores, one SHAKE core, tree-cache /
// scratchpad / signature / key / message memories) between them.
//
// Stage 1 (S_DFS):            get_leaf_combined - DFS traversal,
//                             tree-cache population, h_com
// Stage 2 (S_PHASE12):        blc_commit_phase12 - racc + aux + h_aux
// Stage 3 (S_HLINES):         blc_commit_hlines - r_base + alpha + P0 +
//                             dwit + h_lines
// Stage 4 (S_PIOP):           piop - V chunk generate/process + h_piop
// Stage 5 (S_OPEN_RAND_EVAL): blc_open_rand_eval - grinding, commits,
//                             sibling path, proof-of-work counter
//
// get_leaf_combined serves stage 1 (DFS mode) and the cache-mode leaf
// fetches of stages 2-4 with one shared register set.

module sign (
    input logic clk_i,
    input logic rst_i,
    input logic fsm_start_i,

    input logic [LAMBDA-1:0] salt_i,
    input logic [LAMBDA-1:0] rseed_i,

    output logic fsm_done_o,
    output logic [2*LAMBDA-1:0] hlines_o,

    // External AES 0
    output logic [ENC_KEYSIZE-1:0]   aes0_key_o,
    output logic [ENC_BLOCKSIZE-1:0] aes0_plaintext_o,
    input  logic [ENC_BLOCKSIZE-1:0] aes0_ciphertext_i,
    output logic                     aes0_enable_o,
    input  logic                     aes0_ready_i,
    input  logic                     aes0_valid_i,

    // External AES 1
    output logic [ENC_KEYSIZE-1:0]   aes1_key_o,
    output logic [ENC_BLOCKSIZE-1:0] aes1_plaintext_o,
    input  logic [ENC_BLOCKSIZE-1:0] aes1_ciphertext_i,
    output logic                     aes1_enable_o,
    input  logic                     aes1_ready_i,
    input  logic                     aes1_valid_i,

    // External SHAKE
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

    // External cache BRAM (single-port, 64-bit)
    input  logic [63:0]             cache_data_i,
    output logic [63:0]             cache_data_o,
    output logic [CACHE_ADDR_WIDTH-1:0] cache_addr_o,
    output logic                    cache_wr_en_o,

    // Var overflow stall (from sign_top RAMB18 serialization)
    input  logic var_stall_i,

    // External dual-port variable memory (muxed: BRAM or RAMB18)
    input  logic [VAR_DATA_WIDTH_COMBINED-1:0] var_a_data_i,
    output logic [VAR_DATA_WIDTH_COMBINED-1:0] var_a_data_o,
    output logic [VAR_ADDR_WIDTH_COMBINED-1:0] var_a_addr_o,
    output logic                               var_a_wr_en_o,

    input  logic [VAR_DATA_WIDTH_COMBINED-1:0] var_b_data_i,
    output logic [VAR_DATA_WIDTH_COMBINED-1:0] var_b_data_o,
    output logic [VAR_ADDR_WIDTH_COMBINED-1:0] var_b_addr_o,
    output logic                               var_b_wr_en_o,

    // Raw BRAM read data (bypasses overflow mux, same as var_*_data_i for non-overflow configs)
    input  logic [VAR_DATA_WIDTH_COMBINED-1:0] var_a_data_bram_i,
    input  logic [VAR_DATA_WIDTH_COMBINED-1:0] var_b_data_bram_i,

    // External signature memory (single-port, 64-bit)
    input  logic [63:0]              sig_data_i,
    output logic [63:0]              sig_data_o,
    output logic [SIG_ADDR_WIDTH-1:0] sig_addr_o,
    output logic                     sig_wr_en_o,

    // External key memory (read-only)
    input  logic [63:0]             key_data_i,
    output logic [BRAM_ADDR_SIZE:0] key_addr_o,

    // External message memory (read-only, used by hash_piop inside piop)
    input  logic [63:0]               msg_data_i,
    output logic [MSG_ADDR_WIDTH-1:0] msg_addr_o
);
  // Top-level FSM

  typedef enum logic [3:0] {
    S_IDLE,
    S_DFS,
    S_WRITE_SALT,
    S_PHASE12,
    S_HLINES,
    S_PIOP,
    S_OPEN_RAND_EVAL,
    S_DONE
  } top_state_t;

  top_state_t stage, next_stage;

  // Salt writer: copies salt_i to sig BRAM at SALT_SIG_OFFSET
  logic [$clog2(LAMBDA_DIV_64):0] salt_w, next_salt_w;

  // Must include S_IDLE: DFS fires its SHAKE start pulse on the same cycle
  // as fsm_start_i. Without S_IDLE, the SHAKE mux defaults to zero and
  // swallows that pulse, causing a deadlock.
  wire dfs_active_early = (stage == S_IDLE) || (stage == S_DFS);
  // Leaf combined -> cache BRAM internal signals (muxed below)

  logic [63:0]             leaf_cache_data;
  logic [CACHE_ADDR_WIDTH-1:0] leaf_cache_addr;
  logic                    leaf_cache_wr_en;

  // Combined leaf module (DFS + cache in one)
  // Siblings stored in var_bram scratch (overwritten by phase12)

  logic                     leaf_start;
  logic                     leaf_done;
  logic [LAMBDA-1:0]        leaf_out1, leaf_out2;

  logic                     leaf_get_next;
  logic [GGM_TREE_DEPTH:0]  leaf_idx, leaf_idx2;

  logic [ENC_KEYSIZE-1:0]   leaf_aes1_key, leaf_aes2_key;
  logic [ENC_BLOCKSIZE-1:0] leaf_aes1_plaintext, leaf_aes2_plaintext;
  logic                     leaf_aes1_enable, leaf_aes2_enable;

  logic        leaf_shake_start, leaf_shake_dout_ready;
  logic [63:0] leaf_shake_din;
  logic        leaf_shake_din_valid, leaf_shake_last_din;
  logic [3:0]  leaf_shake_last_din_byte;

  logic [VAR_DATA_WIDTH_COMBINED-1:0] leaf_var_a_data, leaf_var_b_data;
  logic [VAR_ADDR_WIDTH_COMBINED-1:0] leaf_var_a_addr, leaf_var_b_addr;

  // used in port maps above their assigns; without decls implicit 1-bit nets truncate
  wire aes0_to_leaf,          aes1_to_leaf;
  wire aes0_valid_for_leaf,   aes1_valid_for_leaf;
  wire aes0_valid_for_racc,   aes1_valid_for_racc;
  wire aes0_valid_for_commit, aes1_valid_for_commit;
  // declared early: used by u_gen_rbase
  logic racc_done;

  logic                               leaf_var_a_wr_en, leaf_var_b_wr_en;

  generate
    if (HCOM_IN_PHASE12 == 0) begin : g_leaf_default
      // Default path: full DFS+commit+hcom in get_leaf_combined.
      get_leaf_combined #(.MEM_SIZE(64)) u_leaf (
          .clk_i        (clk_i),
          .rst_i        (rst_i),
          .fsm_start_i  (leaf_start),
          .rseed_i        (rseed_i),
          .get_next_leaf_i(leaf_get_next),
          .leaf_idx_i     (leaf_idx),
          .leaf_idx2_i    (leaf_idx2),
          .leaf_o         (leaf_out1),
          .leaf2_o        (leaf_out2),
          .salt_i           (salt_i),
          .fsm_done_o     (leaf_done),
          .aes1_key_o       (leaf_aes1_key),
          .aes1_plaintext_o (leaf_aes1_plaintext),
          .aes1_ciphertext_i(aes0_ciphertext_i),
          .aes1_enable_o    (leaf_aes1_enable),
          .aes1_ready_i     (aes0_ready_i),
          .aes1_valid_i     (aes0_valid_for_leaf),
          .aes2_key_o       (leaf_aes2_key),
          .aes2_plaintext_o (leaf_aes2_plaintext),
          .aes2_ciphertext_i(aes1_ciphertext_i),
          .aes2_enable_o    (leaf_aes2_enable),
          .aes2_ready_i     (aes1_ready_i),
          .aes2_valid_i     (aes1_valid_for_leaf),
          .fire_accepted1_i(aes0_to_leaf & leaf_aes1_enable),
          .fire_accepted2_i(aes1_to_leaf & leaf_aes2_enable),
          .cache_data_i  (cache_data_i),
          .cache_data_o  (leaf_cache_data),
          .cache_addr_o  (leaf_cache_addr),
          .cache_wr_en_o (leaf_cache_wr_en),
          .var_a_data_i  (var_a_data_i),
          .var_a_data_o  (leaf_var_a_data),
          .var_a_addr_o  (leaf_var_a_addr),
          .var_a_wr_en_o (leaf_var_a_wr_en),
          .var_b_data_i  (var_b_data_i),
          .var_b_data_o  (leaf_var_b_data),
          .var_b_addr_o  (leaf_var_b_addr),
          .var_b_wr_en_o (leaf_var_b_wr_en),
          .shake_start_o        (leaf_shake_start),
          .shake_din_o          (leaf_shake_din),
          .shake_din_valid_o    (leaf_shake_din_valid),
          .shake_last_din_o     (leaf_shake_last_din),
          .shake_last_din_byte_o(leaf_shake_last_din_byte),
          .shake_din_ready_i    (shake_din_ready_i),
          .shake_dout_ready_o   (leaf_shake_dout_ready),
          .shake_dout_i         (shake_dout_i),
          .shake_dout_valid_i   (shake_dout_valid_i)
      );
    end else begin : g_leaf_alt
      // Alt path: the leaf module does not drive SHAKE/var (phase12 owns hcom).
      get_leaf_combined_nohcom #(.MEM_SIZE(64)) u_leaf (
          .clk_i        (clk_i),
          .rst_i        (rst_i),
          .fsm_start_i  (leaf_start),
          .rseed_i        (rseed_i),
          .get_next_leaf_i(leaf_get_next),
          .leaf_idx_i     (leaf_idx),
          .leaf_idx2_i    (leaf_idx2),
          .leaf_o         (leaf_out1),
          .leaf2_o        (leaf_out2),
          .salt_i           (salt_i),
          .fsm_done_o     (leaf_done),
          .aes1_key_o       (leaf_aes1_key),
          .aes1_plaintext_o (leaf_aes1_plaintext),
          .aes1_ciphertext_i(aes0_ciphertext_i),
          .aes1_enable_o    (leaf_aes1_enable),
          .aes1_ready_i     (aes0_ready_i),
          .aes1_valid_i     (aes0_valid_for_leaf),
          .aes2_key_o       (leaf_aes2_key),
          .aes2_plaintext_o (leaf_aes2_plaintext),
          .aes2_ciphertext_i(aes1_ciphertext_i),
          .aes2_enable_o    (leaf_aes2_enable),
          .aes2_ready_i     (aes1_ready_i),
          .aes2_valid_i     (aes1_valid_for_leaf),
          .fire_accepted1_i(aes0_to_leaf & leaf_aes1_enable),
          .fire_accepted2_i(aes1_to_leaf & leaf_aes2_enable),
          .cache_data_i  (cache_data_i),
          .cache_data_o  (leaf_cache_data),
          .cache_addr_o  (leaf_cache_addr),
          .cache_wr_en_o (leaf_cache_wr_en)
      );
      // Tie undriven outputs to safe defaults so the existing muxes stay inert.
      assign leaf_var_a_data    = '0;
      assign leaf_var_a_addr    = '0;
      assign leaf_var_a_wr_en   = 1'b0;
      assign leaf_var_b_data    = '0;
      assign leaf_var_b_addr    = '0;
      assign leaf_var_b_wr_en   = 1'b0;
      assign leaf_shake_start         = 1'b0;
      assign leaf_shake_din           = '0;
      assign leaf_shake_din_valid     = 1'b0;
      assign leaf_shake_last_din      = 1'b0;
      assign leaf_shake_last_din_byte = '0;
      assign leaf_shake_dout_ready    = 1'b0;
    end
  endgenerate
  // Gen_rbase - shared inner loop for rbase generation
  // Instantiated once, used by both phase12 and hlines via start/done handshake.

  logic                                  ph12_gr_start, hl_gr_start;
  logic [$clog2(TAU+1)-1:0]              ph12_gr_e, hl_gr_e;
  logic [VAR_ADDR_WIDTH_COMBINED-1:0]    ph12_gr_rbase_base, hl_gr_rbase_base;
  logic [BRAM_ADDR_SIZE:0]               ph12_gr_slot_offset, hl_gr_slot_offset;
  logic                                  ph12_gr_build_rbase, hl_gr_build_rbase;
  logic                                  gr_done;

  logic                                  gr_active, gr_racc_owns_mem;
  logic [BRAM_ADDR_SIZE:0]               gr_racc_slot_offset;
  logic                                  gr_racc_enable;
  logic [LAMBDA-1:0]                     gr_racc_seed;
  logic                                  gr_racc_first_run;
  logic                                  gr_get_next_leaf;
  logic [GGM_TREE_DEPTH:0]               gr_leaf_idx, gr_leaf_idx2;

  logic [VAR_DATA_WIDTH_COMBINED-1:0]    gr_var_a_data_o, gr_var_b_data_o;
  logic [VAR_ADDR_WIDTH_COMBINED-1:0]    gr_var_a_addr_o, gr_var_b_addr_o;
  logic                                  gr_var_a_wr_en_o, gr_var_b_wr_en_o;

  logic [63:0]             gr_cache_data_o;
  logic [CACHE_ADDR_WIDTH-1:0] gr_cache_addr_o;
  logic                    gr_cache_wr_en_o;
  logic                    gr_cache_active;

  wire gr_start = ph12_gr_start | hl_gr_start;
  wire [$clog2(TAU+1)-1:0] gr_e =
      ph12_gr_start ? ph12_gr_e : hl_gr_e;
  wire [VAR_ADDR_WIDTH_COMBINED-1:0] gr_rbase_base =
      ph12_gr_start ? ph12_gr_rbase_base : hl_gr_rbase_base;
  wire [BRAM_ADDR_SIZE:0] gr_slot_offset =
      ph12_gr_start ? ph12_gr_slot_offset : hl_gr_slot_offset;
  wire gr_build_rbase =
      ph12_gr_start ? ph12_gr_build_rbase : hl_gr_build_rbase;

  gen_rbase u_gen_rbase (
      .clk_i             (clk_i),
      .rst_i             (rst_i),
      .var_stall_i       (var_stall_i),
      .start_i           (gr_start),
      .done_o            (gr_done),
      .active_o          (gr_active),
      .e_i               (gr_e),
      .rbase_write_base_i(gr_rbase_base),
      .racc_slot_offset_i(gr_slot_offset),
      .build_rbase_i     (gr_build_rbase),
      .get_next_leaf_o   (gr_get_next_leaf),
      .leaf_idx_o        (gr_leaf_idx),
      .leaf_idx2_o       (gr_leaf_idx2),
      .leaf_done_i       (leaf_done),
      .leaf_i            (leaf_out1),
      .leaf2_i           (leaf_out2),
      .racc_enable_o     (gr_racc_enable),
      .racc_seed_o       (gr_racc_seed),
      .racc_first_run_o  (gr_racc_first_run),
      .racc_owns_mem_o   (gr_racc_owns_mem),
      .racc_slot_offset_o(gr_racc_slot_offset),
      .racc_done_i       (racc_done),
      .var_a_data_i      (var_a_data_i),
      .var_a_data_o      (gr_var_a_data_o),
      .var_a_addr_o      (gr_var_a_addr_o),
      .var_a_wr_en_o     (gr_var_a_wr_en_o),
      .var_b_data_i      (var_b_data_i),
      .var_b_data_o      (gr_var_b_data_o),
      .var_b_addr_o      (gr_var_b_addr_o),
      .var_b_wr_en_o     (gr_var_b_wr_en_o),
      .cache_data_i      (cache_data_i),
      .cache_data_o      (gr_cache_data_o),
      .cache_addr_o      (gr_cache_addr_o),
      .cache_wr_en_o     (gr_cache_wr_en_o),
      .cache_active_o    (gr_cache_active)
  );

  // Racc (blc_racc_combined) - driven exclusively by gen_rbase

  logic [ENC_KEYSIZE-1:0]   racc_aes0_key, racc_aes1_key;
  logic [ENC_BLOCKSIZE-1:0] racc_aes0_plaintext, racc_aes1_plaintext;
  logic                     racc_aes0_enable, racc_aes1_enable;

  logic [VAR_DATA_WIDTH_COMBINED-1:0] racc_var_a_data_o, racc_var_b_data_o;
  logic [VAR_ADDR_WIDTH_COMBINED-1:0] racc_var_a_addr_o, racc_var_b_addr_o;
  logic                               racc_var_a_wr_en_o, racc_var_b_wr_en_o;

  blc_racc_combined u_racc (
      .clk_i            (clk_i),
      .rst_i            (rst_i),
      .fsm_enable_i     (gr_racc_enable),
      .seed_i           (gr_racc_seed),
      .first_run_i      (gr_racc_first_run),
      .slot_offset_i    (gr_racc_slot_offset),
      .fsm_done_o       (racc_done),
      .aes0_key_o       (racc_aes0_key),
      .aes0_plaintext_o (racc_aes0_plaintext),
      .aes0_ciphertext_i(aes0_ciphertext_i),
      .aes0_enable_o    (racc_aes0_enable),
      .aes0_ready_i     (aes0_ready_i),
      .aes0_valid_i     (aes0_valid_for_racc),
      .aes1_key_o       (racc_aes1_key),
      .aes1_plaintext_o (racc_aes1_plaintext),
      .aes1_ciphertext_i(aes1_ciphertext_i),
      .aes1_enable_o    (racc_aes1_enable),
      .aes1_ready_i     (aes1_ready_i),
      .aes1_valid_i     (aes1_valid_for_racc),
      .var_a_data_i     (var_a_data_i),
      .var_a_data_o     (racc_var_a_data_o),
      .var_a_addr_o     (racc_var_a_addr_o),
      .var_a_wr_en_o    (racc_var_a_wr_en_o),
      .var_b_data_i     (var_b_data_i),
      .var_b_data_o     (racc_var_b_data_o),
      .var_b_addr_o     (racc_var_b_addr_o),
      .var_b_wr_en_o    (racc_var_b_wr_en_o)
  );
  // Phase12 signals

  logic ph12_enable;
  logic ph12_done;

  logic        ph12_shake_start, ph12_shake_mode, ph12_shake_seed_from_output;
  logic [63:0] ph12_shake_din;
  logic        ph12_shake_din_valid, ph12_shake_last_din;
  logic [3:0]  ph12_shake_last_din_byte;
  logic        ph12_shake_dout_ready;

  logic [63:0]              ph12_sig_data_o;
  logic [SIG_ADDR_WIDTH-1:0] ph12_sig_addr_o;
  logic                     ph12_sig_wr_en_o;

  logic [VAR_DATA_WIDTH_COMBINED-1:0] ph12_var_a_data_o, ph12_var_b_data_o;
  logic [VAR_ADDR_WIDTH_COMBINED-1:0] ph12_var_a_addr_o, ph12_var_b_addr_o;
  logic                               ph12_var_a_wr_en_o, ph12_var_b_wr_en_o;

  logic [63:0]             ph12_cache_data_o;
  logic [CACHE_ADDR_WIDTH-1:0] ph12_cache_addr_o;
  logic                    ph12_cache_wr_en_o;
  logic                    ph12_cache_active;

  // Leaf handshake (alt path only - phase12_hcom fetches leaves directly)
  logic                     ph12_get_next_leaf;
  logic [GGM_TREE_DEPTH:0]  ph12_leaf_idx, ph12_leaf_idx2;

  // Commit AES override (alt path only - wires drive top-level AES mux)
  logic                     ph12_commit_owns_aes0, ph12_commit_owns_aes1;
  logic [ENC_KEYSIZE-1:0]   ph12_commit_aes0_key,   ph12_commit_aes1_key;
  logic [ENC_BLOCKSIZE-1:0] ph12_commit_aes0_pt,    ph12_commit_aes1_pt;
  logic                     ph12_commit_aes0_enable, ph12_commit_aes1_enable;

  generate
    if (HCOM_IN_PHASE12 == 0) begin : g_ph12_default
      blc_commit_phase12 u_phase12 (
          .clk_i        (clk_i),
          .rst_i        (rst_i),
          .var_stall_i  (var_stall_i),
          .fsm_enable_i (ph12_enable),
          .fsm_done_o   (ph12_done),
          .gr_start_o       (ph12_gr_start),
          .gr_e_o           (ph12_gr_e),
          .gr_rbase_base_o  (ph12_gr_rbase_base),
          .gr_slot_offset_o (ph12_gr_slot_offset),
          .gr_build_rbase_o (ph12_gr_build_rbase),
          .gr_done_i        (gr_done),
          .shake_start_o           (ph12_shake_start),
          .shake_mode_o            (ph12_shake_mode),
          .shake_seed_from_output_o(ph12_shake_seed_from_output),
          .shake_din_o             (ph12_shake_din),
          .shake_din_valid_o       (ph12_shake_din_valid),
          .shake_last_din_o        (ph12_shake_last_din),
          .shake_last_din_byte_o   (ph12_shake_last_din_byte),
          .shake_dout_ready_o      (ph12_shake_dout_ready),
          .shake_din_ready_i       (shake_din_ready_i),
          .shake_dout_i            (shake_dout_i),
          .shake_dout_valid_i      (shake_dout_valid_i),
          .sig_data_i  (sig_data_i),
          .sig_data_o  (ph12_sig_data_o),
          .sig_addr_o  (ph12_sig_addr_o),
          .sig_wr_en_o (ph12_sig_wr_en_o),
          .var_a_data_i  (var_a_data_i),
          .var_a_data_o  (ph12_var_a_data_o),
          .var_a_addr_o  (ph12_var_a_addr_o),
          .var_a_wr_en_o (ph12_var_a_wr_en_o),
          .var_b_data_i  (var_b_data_i),
          .var_b_data_o  (ph12_var_b_data_o),
          .var_b_addr_o  (ph12_var_b_addr_o),
          .var_b_wr_en_o (ph12_var_b_wr_en_o),
          .cache_data_i  (cache_data_i),
          .cache_data_o  (ph12_cache_data_o),
          .cache_addr_o  (ph12_cache_addr_o),
          .cache_wr_en_o (ph12_cache_wr_en_o),
          .cache_active_o(ph12_cache_active)
      );
      // Leaf + commit AES wires unused in default path
      assign ph12_get_next_leaf      = 1'b0;
      assign ph12_leaf_idx           = '0;
      assign ph12_leaf_idx2          = '0;
      assign ph12_commit_owns_aes0   = 1'b0;
      assign ph12_commit_owns_aes1   = 1'b0;
      assign ph12_commit_aes0_key    = '0;
      assign ph12_commit_aes0_pt     = '0;
      assign ph12_commit_aes0_enable = 1'b0;
      assign ph12_commit_aes1_key    = '0;
      assign ph12_commit_aes1_pt     = '0;
      assign ph12_commit_aes1_enable = 1'b0;
    end else begin : g_ph12_alt
      blc_commit_phase12_hcom u_phase12 (
          .clk_i        (clk_i),
          .rst_i        (rst_i),
          .var_stall_i  (var_stall_i),
          .fsm_enable_i (ph12_enable),
          .fsm_done_o   (ph12_done),
          .gr_start_o       (ph12_gr_start),
          .gr_e_o           (ph12_gr_e),
          .gr_rbase_base_o  (ph12_gr_rbase_base),
          .gr_slot_offset_o (ph12_gr_slot_offset),
          .gr_build_rbase_o (ph12_gr_build_rbase),
          .gr_done_i        (gr_done),
          .get_next_leaf_o  (ph12_get_next_leaf),
          .leaf_done_i      (leaf_done),
          .leaf_i           (leaf_out1),
          .leaf_idx_o       (ph12_leaf_idx),
          .leaf_idx2_o      (ph12_leaf_idx2),
          .leaf2_i          (leaf_out2),
          .commit_owns_aes0_o(ph12_commit_owns_aes0),
          .commit_owns_aes1_o(ph12_commit_owns_aes1),
          .aes0_key_o       (ph12_commit_aes0_key),
          .aes0_plaintext_o (ph12_commit_aes0_pt),
          .aes0_ciphertext_i(aes0_ciphertext_i),
          .aes0_enable_o    (ph12_commit_aes0_enable),
          .aes0_ready_i     (aes0_ready_i),
          .aes0_valid_i     (aes0_valid_for_commit),
          .aes1_key_o       (ph12_commit_aes1_key),
          .aes1_plaintext_o (ph12_commit_aes1_pt),
          .aes1_ciphertext_i(aes1_ciphertext_i),
          .aes1_enable_o    (ph12_commit_aes1_enable),
          .aes1_ready_i     (aes1_ready_i),
          .aes1_valid_i     (aes1_valid_for_commit),
          .salt_i           (salt_i),
          .shake_start_o           (ph12_shake_start),
          .shake_mode_o            (ph12_shake_mode),
          .shake_seed_from_output_o(ph12_shake_seed_from_output),
          .shake_din_o             (ph12_shake_din),
          .shake_din_valid_o       (ph12_shake_din_valid),
          .shake_last_din_o        (ph12_shake_last_din),
          .shake_last_din_byte_o   (ph12_shake_last_din_byte),
          .shake_dout_ready_o      (ph12_shake_dout_ready),
          .shake_din_ready_i       (shake_din_ready_i),
          .shake_dout_i            (shake_dout_i),
          .shake_dout_valid_i      (shake_dout_valid_i),
          .sig_data_i  (sig_data_i),
          .sig_data_o  (ph12_sig_data_o),
          .sig_addr_o  (ph12_sig_addr_o),
          .sig_wr_en_o (ph12_sig_wr_en_o),
          .var_a_data_i  (var_a_data_i),
          .var_a_data_o  (ph12_var_a_data_o),
          .var_a_addr_o  (ph12_var_a_addr_o),
          .var_a_wr_en_o (ph12_var_a_wr_en_o),
          .var_b_data_i  (var_b_data_i),
          .var_b_data_o  (ph12_var_b_data_o),
          .var_b_addr_o  (ph12_var_b_addr_o),
          .var_b_wr_en_o (ph12_var_b_wr_en_o),
          .cache_data_i  (cache_data_i),
          .cache_data_o  (ph12_cache_data_o),
          .cache_addr_o  (ph12_cache_addr_o),
          .cache_wr_en_o (ph12_cache_wr_en_o),
          .cache_active_o(ph12_cache_active)
      );
    end
  endgenerate
  // Hlines signals

  logic hl_enable;
  logic hl_done;

  logic        hl_shake_start, hl_shake_mode, hl_shake_seed_from_output;
  logic [63:0] hl_shake_din;
  logic        hl_shake_din_valid, hl_shake_last_din;
  logic [3:0]  hl_shake_last_din_byte;
  logic        hl_shake_dout_ready;

  logic [63:0]              hl_sig_data_o;
  logic [SIG_ADDR_WIDTH-1:0] hl_sig_addr_o;
  logic                     hl_sig_wr_en_o;

  logic [VAR_DATA_WIDTH_COMBINED-1:0] hl_var_a_data_o, hl_var_b_data_o;
  logic [VAR_ADDR_WIDTH_COMBINED-1:0] hl_var_a_addr_o, hl_var_b_addr_o;
  logic                               hl_var_a_wr_en_o, hl_var_b_wr_en_o;

  logic [BRAM_ADDR_SIZE:0] hl_key_addr_o;

  logic [63:0]             hl_cache_data_o;
  logic [CACHE_ADDR_WIDTH-1:0] hl_cache_addr_o;
  logic                    hl_cache_wr_en_o;
  logic                    hl_cache_active;

  blc_commit_hlines u_hlines (
      .clk_i        (clk_i),
      .rst_i        (rst_i),
      .var_stall_i  (var_stall_i),
      .fsm_enable_i (hl_enable),
      .fsm_done_o   (hl_done),
      .hlines_o     (hlines_o),
      // Gen_rbase control
      .gr_start_o       (hl_gr_start),
      .gr_e_o           (hl_gr_e),
      .gr_rbase_base_o  (hl_gr_rbase_base),
      .gr_slot_offset_o (hl_gr_slot_offset),
      .gr_build_rbase_o (hl_gr_build_rbase),
      .gr_done_i        (gr_done),
      // SHAKE
      .shake_start_o           (hl_shake_start),
      .shake_mode_o            (hl_shake_mode),
      .shake_seed_from_output_o(hl_shake_seed_from_output),
      .shake_din_o             (hl_shake_din),
      .shake_din_valid_o       (hl_shake_din_valid),
      .shake_last_din_o        (hl_shake_last_din),
      .shake_last_din_byte_o   (hl_shake_last_din_byte),
      .shake_dout_ready_o      (hl_shake_dout_ready),
      .shake_din_ready_i       (shake_din_ready_i),
      .shake_dout_i            (shake_dout_i),
      .shake_dout_valid_i      (shake_dout_valid_i),
      // Sig memory
      .sig_data_i  (sig_data_i),
      .sig_data_o  (hl_sig_data_o),
      .sig_addr_o  (hl_sig_addr_o),
      .sig_wr_en_o (hl_sig_wr_en_o),
      // Var memory
      .var_a_data_i  (var_a_data_i),
      .var_a_data_o  (hl_var_a_data_o),
      .var_a_addr_o  (hl_var_a_addr_o),
      .var_a_wr_en_o (hl_var_a_wr_en_o),
      .var_b_data_i  (var_b_data_i),
      .var_b_data_o  (hl_var_b_data_o),
      .var_b_addr_o  (hl_var_b_addr_o),
      .var_b_wr_en_o (hl_var_b_wr_en_o),
      .var_a_data_bram_i (var_a_data_bram_i),
      .var_b_data_bram_i (var_b_data_bram_i),
      // Key memory
      .key_data_i  (key_data_i),
      .key_addr_o  (hl_key_addr_o),
      // Cache BRAM
      .cache_data_i  (cache_data_i),
      .cache_data_o  (hl_cache_data_o),
      .cache_addr_o  (hl_cache_addr_o),
      .cache_wr_en_o (hl_cache_wr_en_o),
      .cache_active_o(hl_cache_active)
  );

  // Cache BRAM port mux: leaf_combined / phase12 / hlines.
  // placed after all requester decls
  always_comb begin
    if (dfs_active_early) begin
      // DFS: leaf_combined owns cache (writes tree nodes)
      cache_data_o  = leaf_cache_data;
      cache_addr_o  = leaf_cache_addr;
      cache_wr_en_o = leaf_cache_wr_en;
    end else if (gr_active && gr_cache_active) begin
      // Gen_rbase: writes rbase[KAPPA-1] to cache (USE_CACHE_OVERFLOW only)
      cache_data_o  = gr_cache_data_o;
      cache_addr_o  = gr_cache_addr_o;
      cache_wr_en_o = gr_cache_wr_en_o;
    end else if (stage == S_PHASE12 && (ph12_cache_wr_en_o || ph12_cache_active)) begin
      // Phase12: haux squeeze in cache
      cache_data_o  = ph12_cache_data_o;
      cache_addr_o  = ph12_cache_addr_o;
      cache_wr_en_o = ph12_cache_wr_en_o;
    end else if (stage == S_HLINES && hl_cache_active) begin
      // Hlines: P0/haux/process_rbase cache access
      cache_data_o  = hl_cache_data_o;
      cache_addr_o  = hl_cache_addr_o;
      cache_wr_en_o = hl_cache_wr_en_o;
    end else begin
      // Default: leaf_combined (cache-mode leaf fetches during gen_rbase)
      cache_data_o  = leaf_cache_data;
      cache_addr_o  = leaf_cache_addr;
      cache_wr_en_o = leaf_cache_wr_en;
    end
  end

  // PIOP (Stage 4): generate/process pwit chunks + h_piop hash
  logic piop_enable;
  logic piop_done;

  logic                     piop_get_next_leaf;
  logic [GGM_TREE_DEPTH:0]  piop_leaf_idx, piop_leaf_idx2;

  logic [ENC_KEYSIZE-1:0]   piop_aes0_key, piop_aes1_key;
  logic [ENC_BLOCKSIZE-1:0] piop_aes0_pt,  piop_aes1_pt;
  logic                     piop_aes0_en,  piop_aes1_en;
  logic                     piop_prg_owns_aes;

  logic        piop_shake_start, piop_shake_mode;
  logic [63:0] piop_shake_din;
  logic        piop_shake_din_valid, piop_shake_last_din;
  logic [3:0]  piop_shake_last_din_byte;
  logic        piop_shake_dout_ready;

  logic [VAR_DATA_WIDTH_COMBINED-1:0] piop_var_a_data_o, piop_var_b_data_o;
  logic [VAR_ADDR_WIDTH_COMBINED-1:0] piop_var_a_addr_o, piop_var_b_addr_o;
  logic                               piop_var_a_wr_en_o, piop_var_b_wr_en_o;

  logic [BRAM_ADDR_SIZE:0]  piop_key_addr_o;

  logic [63:0]              piop_sig_data_o;
  logic [SIG_ADDR_WIDTH-1:0] piop_sig_addr_o;
  logic                     piop_sig_wr_en_o;

  piop u_piop (
      .clk_i            (clk_i),
      .rst_i            (rst_i),
      .fsm_enable_i     (piop_enable),
      .fsm_done_o       (piop_done),
      // Leaf cache
      .get_next_leaf_o  (piop_get_next_leaf),
      .leaf_done_i      (leaf_done),
      .leaf_idx_o       (piop_leaf_idx),
      .leaf_idx2_o      (piop_leaf_idx2),
      .leaf_i           (leaf_out1),
      .leaf2_i          (leaf_out2),
      // AES0
      .aes0_key_o       (piop_aes0_key),
      .aes0_plaintext_o (piop_aes0_pt),
      .aes0_ciphertext_i(aes0_ciphertext_i),
      .aes0_enable_o    (piop_aes0_en),
      .aes0_ready_i     (aes0_ready_i),
      .aes0_valid_i     (aes0_valid_i),
      // AES1
      .aes1_key_o       (piop_aes1_key),
      .aes1_plaintext_o (piop_aes1_pt),
      .aes1_ciphertext_i(aes1_ciphertext_i),
      .aes1_enable_o    (piop_aes1_en),
      .aes1_ready_i     (aes1_ready_i),
      .aes1_valid_i     (aes1_valid_i),
      // PRG ownership
      .prg_owns_aes_o   (piop_prg_owns_aes),
      // SHAKE
      .shake_start_o        (piop_shake_start),
      .shake_mode_o         (piop_shake_mode),
      .shake_din_o          (piop_shake_din),
      .shake_din_valid_o    (piop_shake_din_valid),
      .shake_last_din_o     (piop_shake_last_din),
      .shake_last_din_byte_o(piop_shake_last_din_byte),
      .shake_dout_ready_o   (piop_shake_dout_ready),
      .shake_din_ready_i    (shake_din_ready_i),
      .shake_dout_i         (shake_dout_i),
      .shake_dout_valid_i   (shake_dout_valid_i),
      // Var memory
      .var_a_data_i     (var_a_data_i),
      .var_a_data_o     (piop_var_a_data_o),
      .var_a_addr_o     (piop_var_a_addr_o),
      .var_a_wr_en_o    (piop_var_a_wr_en_o),
      .var_b_data_i     (var_b_data_i),
      .var_b_data_o     (piop_var_b_data_o),
      .var_b_addr_o     (piop_var_b_addr_o),
      .var_b_wr_en_o    (piop_var_b_wr_en_o),
      // Key memory
      .key_data_i       (key_data_i),
      .key_addr_o       (piop_key_addr_o),
      // Message memory (read-only, consumed by hash_piop)
      .msg_data_i       (msg_data_i),
      .msg_addr_o       (msg_addr_o),
      // Sig memory
      .sig_data_i       (sig_data_i),
      .sig_data_o       (piop_sig_data_o),
      .sig_addr_o       (piop_sig_addr_o),
      .sig_wr_en_o      (piop_sig_wr_en_o),
      // hlines seed (stable after u_hlines completes)
      .hlines_i         (hlines_o)
  );
  // Open-rand-eval (Stage 5): proof-of-work search + tree opening
  logic ore_start;
  logic ore_done;

  logic [ENC_KEYSIZE-1:0]   ore_enc_key;
  logic [ENC_BLOCKSIZE-1:0] ore_enc_pt0, ore_enc_pt1;
  logic                     ore_enc_enable;

  logic        ore_shake_start, ore_shake_mode;
  logic [63:0] ore_shake_din;
  logic        ore_shake_din_valid, ore_shake_last_din;
  logic [3:0]  ore_shake_last_din_byte;
  logic        ore_shake_dout_ready;

  logic [VAR_DATA_WIDTH_COMBINED-1:0] ore_var_a_data_o, ore_var_b_data_o;
  logic [VAR_ADDR_WIDTH_COMBINED-1:0] ore_var_a_addr_o, ore_var_b_addr_o;
  logic                               ore_var_a_wr_en_o, ore_var_b_wr_en_o;

  logic [63:0]              ore_sig_data_o;
  logic [SIG_ADDR_WIDTH-1:0] ore_sig_addr_o;
  logic                     ore_sig_wr_en_o;

  blc_open_rand_eval u_ore (
      .clk_i          (clk_i),
      .rst_ni         (~rst_i),
      .start_i        (ore_start),
      .salt_i         (salt_i),
      .root_seed_i    (rseed_i),
      .done_o         (ore_done),
      // Sig memory
      .sig_data_i     (sig_data_i),
      .sig_data_o     (ore_sig_data_o),
      .sig_addr_o     (ore_sig_addr_o),
      .sig_wr_en_o    (ore_sig_wr_en_o),
      // Var BRAM
      .var_a_data_i   (var_a_data_i),
      .var_a_data_o   (ore_var_a_data_o),
      .var_a_addr_o   (ore_var_a_addr_o),
      .var_a_wr_en_o  (ore_var_a_wr_en_o),
      .var_b_data_i   (var_b_data_i),
      .var_b_data_o   (ore_var_b_data_o),
      .var_b_addr_o   (ore_var_b_addr_o),
      .var_b_wr_en_o  (ore_var_b_wr_en_o),
      // AES
      .enc_enable_o       (ore_enc_enable),
      .enc_key_o          (ore_enc_key),
      .enc_plaintext_0_o  (ore_enc_pt0),
      .enc_ready_0_i      (aes0_ready_i),
      .enc_valid_0_i      (aes0_valid_i),
      .enc_ciphertext_0_i (aes0_ciphertext_i),
      .enc_plaintext_1_o  (ore_enc_pt1),
      .enc_ready_1_i      (aes1_ready_i),
      .enc_valid_1_i      (aes1_valid_i),
      .enc_ciphertext_1_i (aes1_ciphertext_i),
      // SHAKE
      .start_shake_o          (ore_shake_start),
      .mode_shake_o           (ore_shake_mode),
      .seed_from_output_shake_o(/* unused */),
      .din_shake_o            (ore_shake_din),
      .din_valid_shake_o      (ore_shake_din_valid),
      .last_din_shake_o       (ore_shake_last_din),
      .last_din_byte_shake_o  (ore_shake_last_din_byte),
      .dout_ready_shake_o     (ore_shake_dout_ready),
      .din_ready_shake_i      (shake_din_ready_i),
      .dout_shake_i           (shake_dout_i),
      .dout_valid_shake_i     (shake_dout_valid_i)
  );

  // AES priority mux. Three consumers share two AES engines:
  //   racc     - highest priority, cannot retry (fires and expects result)
  //   commit   - medium, retries via S_COMMIT_FIRE states (alt hcom path only)
  //   leaf     - lowest, retries via fire_accepted handshake
  // Ownership registered on fire; valid routed back to whoever fired.

  // leaf_active tracks multi-cycle leaf cache operations (get_next pulses once,
  // but the leaf module needs AES for several cycles after)
  logic leaf_active;
  always_ff @(posedge clk_i or posedge rst_i) begin
    if (rst_i) begin
      leaf_active <= 1'b0;
    end else if (!var_stall_i) begin
      if (leaf_done)          leaf_active <= 1'b0;
      else if (leaf_get_next) leaf_active <= 1'b1;
    end
  end

  wire dfs_active = (stage == S_IDLE) || (stage == S_DFS);
  wire leaf_wants_aes = dfs_active | ((leaf_active | leaf_get_next) & ~leaf_done);

  // racc > commit > leaf
  wire aes0_to_commit = ph12_commit_owns_aes0 & ~racc_aes0_enable;
  assign aes0_to_leaf = leaf_wants_aes & ~racc_aes0_enable & ~aes0_to_commit;

  // AES0 ownership tracking: latches who fired on each enable edge.
  // AES takes ~14 cycles; the valid signal must be routed to the
  // original requestor, not whoever wants AES now.
  logic aes0_owner_is_leaf, aes0_owner_is_commit;
  always_ff @(posedge clk_i or posedge rst_i) begin
    if (rst_i) begin
      aes0_owner_is_leaf   <= 1'b0;
      aes0_owner_is_commit <= 1'b0;
    end else if (aes0_enable_o && !var_stall_i) begin
      aes0_owner_is_leaf   <= aes0_to_leaf;
      aes0_owner_is_commit <= aes0_to_commit;
    end
  end

  // Route valid back to the requestor that fired this AES operation
  assign aes0_valid_for_leaf   = aes0_valid_i & aes0_owner_is_leaf;
  assign aes0_valid_for_commit = aes0_valid_i & aes0_owner_is_commit;
  assign aes0_valid_for_racc   = aes0_valid_i & ~aes0_owner_is_leaf & ~aes0_owner_is_commit;

  // AES1: same priority chain
  wire aes1_to_commit = ph12_commit_owns_aes1 & ~racc_aes1_enable;
  assign aes1_to_leaf = leaf_wants_aes & ~racc_aes1_enable & ~aes1_to_commit;

  logic aes1_owner_is_leaf, aes1_owner_is_commit;
  always_ff @(posedge clk_i or posedge rst_i) begin
    if (rst_i) begin
      aes1_owner_is_leaf   <= 1'b0;
      aes1_owner_is_commit <= 1'b0;
    end else if (aes1_enable_o && !var_stall_i) begin
      aes1_owner_is_leaf   <= aes1_to_leaf;
      aes1_owner_is_commit <= aes1_to_commit;
    end
  end

  assign aes1_valid_for_leaf   = aes1_valid_i & aes1_owner_is_leaf;
  assign aes1_valid_for_commit = aes1_valid_i & aes1_owner_is_commit;
  assign aes1_valid_for_racc   = aes1_valid_i & ~aes1_owner_is_leaf & ~aes1_owner_is_commit;
  // Racc control: gen_rbase is the sole user (no mux needed)
  // Leaf cache request mux (gen_rbase / piop)

  always_comb begin
    if (gr_active) begin
      leaf_get_next = gr_get_next_leaf;
      leaf_idx      = gr_leaf_idx;
      leaf_idx2     = gr_leaf_idx2;
    end else if (stage == S_PHASE12 && ph12_get_next_leaf) begin
      leaf_get_next = ph12_get_next_leaf;
      leaf_idx      = ph12_leaf_idx;
      leaf_idx2     = ph12_leaf_idx2;
    end else if (stage == S_PIOP) begin
      leaf_get_next = piop_get_next_leaf;
      leaf_idx      = piop_leaf_idx;
      leaf_idx2     = piop_leaf_idx2;
    end else begin
      leaf_get_next = 1'b0;
      leaf_idx      = '0;
      leaf_idx2     = '0;
    end
  end

  wire racc_owns_mem = gr_active && gr_racc_owns_mem;
  // AES output mux

  // racc > commit > leaf
  always_comb begin
    if (dfs_active) begin
      // DFS has exclusive AES - leaf combined drives directly
      aes0_key_o       = leaf_aes1_key;
      aes0_plaintext_o = leaf_aes1_plaintext;
      aes0_enable_o    = leaf_aes1_enable;
      aes1_key_o       = leaf_aes2_key;
      aes1_plaintext_o = leaf_aes2_plaintext;
      aes1_enable_o    = leaf_aes2_enable;
    end else if (stage == S_PIOP) begin
      // PIOP: generate_pwit_chunk drives AES via piop module
      // (piop internally muxes between PRG and leaf cache via prg_owns_aes)
      aes0_key_o       = piop_prg_owns_aes ? piop_aes0_key : leaf_aes1_key;
      aes0_plaintext_o = piop_prg_owns_aes ? piop_aes0_pt  : leaf_aes1_plaintext;
      aes0_enable_o    = piop_prg_owns_aes ? piop_aes0_en  : leaf_aes1_enable;
      aes1_key_o       = piop_prg_owns_aes ? piop_aes1_key : leaf_aes2_key;
      aes1_plaintext_o = piop_prg_owns_aes ? piop_aes1_pt  : leaf_aes2_plaintext;
      aes1_enable_o    = piop_prg_owns_aes ? piop_aes1_en  : leaf_aes2_enable;
    end else if (stage == S_OPEN_RAND_EVAL) begin
      aes0_key_o       = ore_enc_key;
      aes0_plaintext_o = ore_enc_pt0;
      aes0_enable_o    = ore_enc_enable;
      aes1_key_o       = ore_enc_key;
      aes1_plaintext_o = ore_enc_pt1;
      aes1_enable_o    = ore_enc_enable;
    end else begin
      // AES0
      if (aes0_to_commit) begin
        aes0_key_o       = ph12_commit_aes0_key;
        aes0_plaintext_o = ph12_commit_aes0_pt;
        aes0_enable_o    = ph12_commit_aes0_enable;
      end else begin
        aes0_key_o       = aes0_to_leaf ? leaf_aes1_key       : racc_aes0_key;
        aes0_plaintext_o = aes0_to_leaf ? leaf_aes1_plaintext : racc_aes0_plaintext;
        aes0_enable_o    = aes0_to_leaf ? leaf_aes1_enable    : racc_aes0_enable;
      end
      // AES1
      if (aes1_to_commit) begin
        aes1_key_o       = ph12_commit_aes1_key;
        aes1_plaintext_o = ph12_commit_aes1_pt;
        aes1_enable_o    = ph12_commit_aes1_enable;
      end else begin
        aes1_key_o       = aes1_to_leaf ? leaf_aes2_key       : racc_aes1_key;
        aes1_plaintext_o = aes1_to_leaf ? leaf_aes2_plaintext : racc_aes1_plaintext;
        aes1_enable_o    = aes1_to_leaf ? leaf_aes2_enable    : racc_aes1_enable;
      end
    end
  end
  // SHAKE output mux

  always_comb begin
    if (dfs_active) begin
      shake_start_o            = leaf_shake_start;
      shake_mode_o             = 1'b0;
      shake_seed_from_output_o = 1'b0;
      shake_din_o              = leaf_shake_din;
      shake_din_valid_o        = leaf_shake_din_valid;
      shake_last_din_o         = leaf_shake_last_din;
      shake_last_din_byte_o    = leaf_shake_last_din_byte;
      shake_dout_ready_o       = leaf_shake_dout_ready;
    end else
    case (stage)
      S_PHASE12: begin
        shake_start_o            = ph12_shake_start;
        shake_mode_o             = ph12_shake_mode;
        shake_seed_from_output_o = ph12_shake_seed_from_output;
        shake_din_o              = ph12_shake_din;
        shake_din_valid_o        = ph12_shake_din_valid;
        shake_last_din_o         = ph12_shake_last_din;
        shake_last_din_byte_o    = ph12_shake_last_din_byte;
        shake_dout_ready_o       = ph12_shake_dout_ready;
      end
      S_HLINES: begin
        shake_start_o            = hl_shake_start;
        shake_mode_o             = hl_shake_mode;
        shake_seed_from_output_o = hl_shake_seed_from_output;
        shake_din_o              = hl_shake_din;
        shake_din_valid_o        = hl_shake_din_valid;
        shake_last_din_o         = hl_shake_last_din;
        shake_last_din_byte_o    = hl_shake_last_din_byte;
        shake_dout_ready_o       = hl_shake_dout_ready;
      end
      S_PIOP: begin
        shake_start_o            = piop_shake_start;
        shake_mode_o             = piop_shake_mode;
        shake_seed_from_output_o = 1'b0;
        shake_din_o              = piop_shake_din;
        shake_din_valid_o        = piop_shake_din_valid;
        shake_last_din_o         = piop_shake_last_din;
        shake_last_din_byte_o    = piop_shake_last_din_byte;
        shake_dout_ready_o       = piop_shake_dout_ready;
      end
      S_OPEN_RAND_EVAL: begin
        shake_start_o            = ore_shake_start;
        shake_mode_o             = ore_shake_mode;
        shake_seed_from_output_o = 1'b0;
        shake_din_o              = ore_shake_din;
        shake_din_valid_o        = ore_shake_din_valid;
        shake_last_din_o         = ore_shake_last_din;
        shake_last_din_byte_o    = ore_shake_last_din_byte;
        shake_dout_ready_o       = ore_shake_dout_ready;
      end
      default: begin
        shake_start_o            = 1'b0;
        shake_mode_o             = 1'b0;
        shake_seed_from_output_o = 1'b0;
        shake_din_o              = 64'b0;
        shake_din_valid_o        = 1'b0;
        shake_last_din_o         = 1'b0;
        shake_last_din_byte_o    = 4'd0;
        shake_dout_ready_o       = 1'b0;
      end
    endcase
  end
  // Var memory mux

  always_comb begin
    if (dfs_active) begin
      // DFS writes hcom to var BRAM during squeeze
      var_a_data_o  = leaf_var_a_data;
      var_a_addr_o  = leaf_var_a_addr;
      var_a_wr_en_o = leaf_var_a_wr_en;
      var_b_data_o  = leaf_var_b_data;
      var_b_addr_o  = leaf_var_b_addr;
      var_b_wr_en_o = leaf_var_b_wr_en;
    end else if (racc_owns_mem) begin
      // Racc writing r_acc during gen_rbase
      var_a_data_o  = racc_var_a_data_o;
      var_a_addr_o  = racc_var_a_addr_o;
      var_a_wr_en_o = racc_var_a_wr_en_o;
      var_b_data_o  = racc_var_b_data_o;
      var_b_addr_o  = racc_var_b_addr_o;
      var_b_wr_en_o = racc_var_b_wr_en_o;
    end else if (gr_active) begin
      // Gen_rbase XOR loop (reads slot0, writes rbase columns)
      var_a_data_o  = gr_var_a_data_o;
      var_a_addr_o  = gr_var_a_addr_o;
      var_a_wr_en_o = gr_var_a_wr_en_o;
      var_b_data_o  = gr_var_b_data_o;
      var_b_addr_o  = gr_var_b_addr_o;
      var_b_wr_en_o = gr_var_b_wr_en_o;
    end else if (stage == S_PHASE12) begin
      var_a_data_o  = ph12_var_a_data_o;
      var_a_addr_o  = ph12_var_a_addr_o;
      var_a_wr_en_o = ph12_var_a_wr_en_o;
      var_b_data_o  = ph12_var_b_data_o;
      var_b_addr_o  = ph12_var_b_addr_o;
      var_b_wr_en_o = ph12_var_b_wr_en_o;
    end else if (stage == S_HLINES) begin
      var_a_data_o  = hl_var_a_data_o;
      var_a_addr_o  = hl_var_a_addr_o;
      var_a_wr_en_o = hl_var_a_wr_en_o;
      var_b_data_o  = hl_var_b_data_o;
      var_b_addr_o  = hl_var_b_addr_o;
      var_b_wr_en_o = hl_var_b_wr_en_o;
    end else if (stage == S_PIOP) begin
      var_a_data_o  = piop_var_a_data_o;
      var_a_addr_o  = piop_var_a_addr_o;
      var_a_wr_en_o = piop_var_a_wr_en_o;
      var_b_data_o  = piop_var_b_data_o;
      var_b_addr_o  = piop_var_b_addr_o;
      var_b_wr_en_o = piop_var_b_wr_en_o;
    end else if (stage == S_OPEN_RAND_EVAL) begin
      var_a_data_o  = ore_var_a_data_o;
      var_a_addr_o  = ore_var_a_addr_o;
      var_a_wr_en_o = ore_var_a_wr_en_o;
      var_b_data_o  = ore_var_b_data_o;
      var_b_addr_o  = ore_var_b_addr_o;
      var_b_wr_en_o = ore_var_b_wr_en_o;
    end else begin
      var_a_data_o  = '0;
      var_a_addr_o  = '0;
      var_a_wr_en_o = 1'b0;
      var_b_data_o  = '0;
      var_b_addr_o  = '0;
      var_b_wr_en_o = 1'b0;
    end
  end
  // Sig memory mux

  always_comb begin
    if (stage == S_WRITE_SALT) begin
      sig_data_o  = salt_i[(salt_w * 64) +: 64];
      sig_addr_o  = SIG_ADDR_WIDTH'(SALT_SIG_OFFSET + salt_w);
      sig_wr_en_o = 1'b1;
    end else if (stage == S_PHASE12) begin
      sig_data_o  = ph12_sig_data_o;
      sig_addr_o  = ph12_sig_addr_o;
      sig_wr_en_o = ph12_sig_wr_en_o;
    end else if (stage == S_HLINES) begin
      sig_data_o  = hl_sig_data_o;
      sig_addr_o  = hl_sig_addr_o;
      sig_wr_en_o = hl_sig_wr_en_o;
    end else if (stage == S_PIOP) begin
      sig_data_o  = piop_sig_data_o;
      sig_addr_o  = piop_sig_addr_o;
      sig_wr_en_o = piop_sig_wr_en_o;
    end else if (stage == S_OPEN_RAND_EVAL) begin
      sig_data_o  = ore_sig_data_o;
      sig_addr_o  = ore_sig_addr_o;
      sig_wr_en_o = ore_sig_wr_en_o;
    end else begin
      sig_data_o  = 64'b0;
      sig_addr_o  = '0;
      sig_wr_en_o = 1'b0;
    end
  end
  // Key memory mux (hlines vs piop)

  assign key_addr_o = (stage == S_PIOP) ? piop_key_addr_o : hl_key_addr_o;
  // Top-level FSM

  always_comb begin
    next_stage    = stage;
    next_salt_w   = salt_w;
    fsm_done_o    = 1'b0;
    leaf_start    = 1'b0;
    ph12_enable   = 1'b0;
    hl_enable     = 1'b0;
    piop_enable   = 1'b0;
    ore_start     = 1'b0;

    case (stage)
      S_IDLE: begin
        if (fsm_start_i) begin
          leaf_start = 1'b1;
          next_stage = S_DFS;
        end
      end

      S_DFS: begin
        if (leaf_done) begin
          next_salt_w = 0;
          next_stage  = S_WRITE_SALT;
        end
      end

      S_WRITE_SALT: begin
        next_salt_w = salt_w + 1;
        if (salt_w == ($clog2(LAMBDA_DIV_64)+1)'(LAMBDA_DIV_64 - 1)) begin
          ph12_enable = 1'b1;
          next_stage  = S_PHASE12;
        end
      end

      S_PHASE12: begin
        if (ph12_done) begin
          hl_enable  = 1'b1;
          next_stage = S_HLINES;
        end
      end

      S_HLINES: begin
        if (hl_done) begin
          piop_enable = 1'b1;
          next_stage  = S_PIOP;
        end
      end

      S_PIOP: begin
        if (piop_done) begin
          ore_start  = 1'b1;
          next_stage = S_OPEN_RAND_EVAL;
        end
      end

      S_OPEN_RAND_EVAL: begin
        if (ore_done)
          next_stage = S_DONE;
      end

      S_DONE: begin
        fsm_done_o = 1'b1;
      end
    endcase
  end

  always_ff @(posedge clk_i or posedge rst_i) begin
    if (rst_i) begin
      stage  <= S_IDLE;
      salt_w <= '0;
    end else if (!var_stall_i) begin
      stage  <= next_stage;
      salt_w <= next_salt_w;
    end
  end

endmodule
