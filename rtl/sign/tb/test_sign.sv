// SPDX-FileCopyrightText: 2026 Stef Halmans, Niklas Höher
// SPDX-License-Identifier: LicenseRef-RUB-SecEng

import sdith_params_pkg::*;

// test_sign
//
// Simulation harness for the sign pipeline: instantiates the two Rijndael
// cores, the SHAKE core, and all memories around the sign module, and adds
// debug ports so the testbench can pre-load the key/message memories and
// read back the tree-cache, scratchpad, and signature memories.

module test_sign (
    input logic clk_i,
    input logic rst_i,

    // Control
    input logic fsm_start_i,

    // GGM tree seed and salt
    input logic [LAMBDA-1:0] salt,
    input logic [LAMBDA-1:0] rseed,

    // Status
    output logic fsm_done_o,
    output logic [2*LAMBDA-1:0] hlines_o,

    // Debug: read cache BRAM
    input  logic                    dbg_cache_rd_en_i,
    input  logic [CACHE_ADDR_WIDTH-1:0] dbg_cache_addr_i,
    output logic [63:0]             dbg_cache_data_o,

    // Debug: pre-load var memory via dual-port debug
    input  logic                               dbg_mode_i,
    input  logic                               dbg_var_wr_en_i,
    input  logic [VAR_ADDR_WIDTH_COMBINED-1:0] dbg_var_a_addr_i,
    input  logic [VAR_DATA_WIDTH_COMBINED-1:0] dbg_var_a_data_i,
    input  logic [VAR_ADDR_WIDTH_COMBINED-1:0] dbg_var_b_addr_i,
    input  logic [VAR_DATA_WIDTH_COMBINED-1:0] dbg_var_b_data_i,

    // Debug: read var memory
    output logic [VAR_DATA_WIDTH_COMBINED-1:0] dbg_var_a_data_o,
    output logic [VAR_DATA_WIDTH_COMBINED-1:0] dbg_var_b_data_o,

    // Debug: read sig memory
    input  logic                    dbg_sig_rd_en_i,
    input  logic [SIG_ADDR_WIDTH-1:0] dbg_sig_addr_i,
    output logic [63:0]             dbg_sig_data_o,

    // Debug: write key memory
    input  logic                    dbg_key_wr_en_i,
    input  logic [BRAM_ADDR_SIZE:0] dbg_key_addr_i,
    input  logic [63:0]             dbg_key_data_i,

    // Debug: write message memory
    input  logic                       dbg_msg_wr_en_i,
    input  logic [MSG_ADDR_WIDTH-1:0]  dbg_msg_addr_i,
    input  logic [63:0]                dbg_msg_data_i,

    // SHAKE din snoop
    output logic [63:0] dbg_shake_din_o,
    output logic        dbg_shake_din_valid_o,
    output logic        dbg_shake_din_ready_o,
    output logic        dbg_shake_last_din_o,
    output logic [3:0]  dbg_shake_last_byte_o,

    // Internal stage (for early verification before PIOP overwrites memory)
    output logic [3:0]  dbg_stage_o,

    // Sub-module signals for per-module cycle profiling
    output logic        dbg_gr_active_o,
    output logic [5:0]  dbg_hlines_state_o,
    output logic [2:0]  dbg_piop_state_o
);

  // ============================================================
  // AES instances
  // ============================================================
  logic [ENC_KEYSIZE-1:0]   aes0_key, aes1_key;
  logic [ENC_BLOCKSIZE-1:0] aes0_plaintext, aes0_ciphertext;
  logic [ENC_BLOCKSIZE-1:0] aes1_plaintext, aes1_ciphertext;
  logic                     aes0_enable_sign, aes0_ready, aes0_valid;
  logic                     aes1_enable_sign, aes1_ready, aes1_valid;

  generate
    if (SECURITY_LEVEL == 1) begin : gen_aes
      rijndael_encrypt #(.NB(4), .NK(4)) aes0 (
          .clk_i(clk_i), .rst_ni(!rst_i),
          .enable_i(aes0_enable_sign), .ready_o(aes0_ready), .valid_o(aes0_valid),
          .plaintext_i(aes0_plaintext), .key_i(aes0_key), .ciphertext_o(aes0_ciphertext)
      );
      rijndael_encrypt #(.NB(4), .NK(4)) aes1_inst (
          .clk_i(clk_i), .rst_ni(!rst_i),
          .enable_i(aes1_enable_sign), .ready_o(aes1_ready), .valid_o(aes1_valid),
          .plaintext_i(aes1_plaintext), .key_i(aes1_key), .ciphertext_o(aes1_ciphertext)
      );
    end else if (SECURITY_LEVEL == 3 || SECURITY_LEVEL == 5) begin : gen_aes
      rijndael_encrypt #(.NB(8), .NK(8)) aes0 (
          .clk_i(clk_i), .rst_ni(!rst_i),
          .enable_i(aes0_enable_sign), .ready_o(aes0_ready), .valid_o(aes0_valid),
          .plaintext_i(aes0_plaintext), .key_i(aes0_key), .ciphertext_o(aes0_ciphertext)
      );
      rijndael_encrypt #(.NB(8), .NK(8)) aes1_inst (
          .clk_i(clk_i), .rst_ni(!rst_i),
          .enable_i(aes1_enable_sign), .ready_o(aes1_ready), .valid_o(aes1_valid),
          .plaintext_i(aes1_plaintext), .key_i(aes1_key), .ciphertext_o(aes1_ciphertext)
      );
    end
  endgenerate

  // ============================================================
  // SHAKE instance
  // ============================================================
  logic        shake_start_sign, shake_mode, shake_seed_from_output;
  logic [63:0] shake_din, shake_dout;
  logic        shake_din_valid_sign, shake_last_din, shake_dout_ready_sign;
  logic [ 3:0] shake_last_din_byte;
  logic        shake_din_ready, shake_dout_valid;

  generate
    if (SECURITY_LEVEL == 1) begin : gen_shake
      shake_top #(
          .VARIANT  (128),
          .HASH_SIZE(2 * LAMBDA)
      ) shake128 (
          .clk_i             (clk_i),
          .rst_ni            (!rst_i),
          .start_i           (shake_start_sign),
          .mode_i            (shake_mode),
          .seed_from_output_i(shake_seed_from_output),
          .din_i             (shake_din),
          .din_valid_i       (shake_din_valid_sign),
          .last_din_i        (shake_last_din),
          .last_din_byte_i   (shake_last_din_byte),
          .dout_ready_i      (shake_dout_ready_sign),
          .din_ready_o       (shake_din_ready),
          .dout_o            (shake_dout),
          .dout_valid_o      (shake_dout_valid)
      );
    end else if (SECURITY_LEVEL == 3 || SECURITY_LEVEL == 5) begin : gen_shake
      shake_top #(
          .VARIANT  (256),
          .HASH_SIZE(2 * LAMBDA)
      ) shake256 (
          .clk_i             (clk_i),
          .rst_ni            (!rst_i),
          .start_i           (shake_start_sign),
          .mode_i            (shake_mode),
          .seed_from_output_i(shake_seed_from_output),
          .din_i             (shake_din),
          .din_valid_i       (shake_din_valid_sign),
          .last_din_i        (shake_last_din),
          .last_din_byte_i   (shake_last_din_byte),
          .dout_ready_i      (shake_dout_ready_sign),
          .din_ready_o       (shake_din_ready),
          .dout_o            (shake_dout),
          .dout_valid_o      (shake_dout_valid)
      );
    end
  endgenerate

  // ============================================================
  // Tree-cache BRAM (DFS write + leaf cache read) with debug read mux
  // ============================================================
  wire [63:0]             cache_data_out;
  wire [63:0]             dut_cache_data_o;
  wire [CACHE_ADDR_WIDTH-1:0] dut_cache_addr_o;
  wire                        dut_cache_wr_en_o;

  wire [CACHE_ADDR_WIDTH-1:0] cache_eff_addr  = dbg_cache_rd_en_i ? dbg_cache_addr_i : dut_cache_addr_o;
  wire                    cache_eff_wr_en = dbg_cache_rd_en_i ? 1'b0             : dut_cache_wr_en_o;

  assign dbg_cache_data_o = cache_data_out;

  mem_single #(.WIDTH(64), .DEPTH(CACHE_BRAM_DEPTH)) md_cache (
      .clock(clk_i), .data(dut_cache_data_o), .address(cache_eff_addr),
      .wr_en(cache_eff_wr_en), .q(cache_data_out)
  );

  // ============================================================
  // Dual-port variable memory with debug mux + FF overflow bank
  // ============================================================
  wire [VAR_DATA_WIDTH_COMBINED-1:0] var_a_data_out, var_b_data_out;
  wire [VAR_DATA_WIDTH_COMBINED-1:0] dut_var_a_data_o, dut_var_b_data_o;
  wire [VAR_ADDR_WIDTH_COMBINED-1:0] dut_var_a_addr_o, dut_var_b_addr_o;
  wire                               dut_var_a_wr_en_o, dut_var_b_wr_en_o;

  // Overflow interception: what sign reads back (BRAM or overflow FF bank)
  wire [VAR_DATA_WIDTH_COMBINED-1:0] sign_var_a_rd, sign_var_b_rd;
  // Raw BRAM output (bypasses overflow mux, for identity reads during stall)
  wire [VAR_DATA_WIDTH_COMBINED-1:0] sign_var_a_rd_bram, sign_var_b_rd_bram;
  // Overflow interception: what reaches BRAM (writes suppressed for overflow)
  wire [VAR_ADDR_WIDTH_COMBINED-1:0] bram_var_a_addr, bram_var_b_addr;
  wire                               bram_var_a_wr_en, bram_var_b_wr_en;
  wire [VAR_DATA_WIDTH_COMBINED-1:0] bram_var_a_wr_data, bram_var_b_wr_data;
  logic var_stall;

  generate if (VAR_HAS_OVERFLOW) begin : gen_ovf
    // FF bank for the alpha overflow words. Single-cycle access, so no
    // stall is needed (unlike the RAMB18 bank used in sign_top).
    localparam OVF_PHYS_BASE = BRAM_TDP_DEPTH_32;
    localparam OVF_WORDS = VAR_MAX_LOGICAL_ADDR - BRAM_TDP_DEPTH_32 / 2;
    localparam OVF_PHYS_END = OVF_PHYS_BASE + 2 * OVF_WORDS;

    wire a_is_ovf = (dut_var_a_addr_o >= VAR_ADDR_WIDTH_COMBINED'(OVF_PHYS_BASE))
                  && (dut_var_a_addr_o < VAR_ADDR_WIDTH_COMBINED'(OVF_PHYS_END));

    wire [3:0] ff_idx = 4'((dut_var_a_addr_o - VAR_ADDR_WIDTH_COMBINED'(OVF_PHYS_BASE)) >> 1);

    reg [63:0] ff_overflow [0:OVF_WORDS-1];

    always_ff @(posedge clk_i) begin
      if (a_is_ovf && dut_var_a_wr_en_o)
        ff_overflow[ff_idx][31:0] <= dut_var_a_data_o;
      if (a_is_ovf && dut_var_b_wr_en_o)
        ff_overflow[ff_idx][63:32] <= dut_var_b_data_o;
    end

    logic was_ovf;
    logic [3:0] ff_idx_reg;
    always_ff @(posedge clk_i) begin
      was_ovf    <= a_is_ovf;
      ff_idx_reg <= ff_idx;
    end

    assign var_stall = 1'b0;
    assign sign_var_a_rd = was_ovf ? ff_overflow[ff_idx_reg][31:0]  : var_a_data_out;
    assign sign_var_b_rd = was_ovf ? ff_overflow[ff_idx_reg][63:32] : var_b_data_out;
    assign sign_var_a_rd_bram = var_a_data_out;
    assign sign_var_b_rd_bram = var_b_data_out;
    assign bram_var_a_addr    = dut_var_a_addr_o;
    assign bram_var_b_addr    = dut_var_b_addr_o;
    assign bram_var_a_wr_data = dut_var_a_data_o;
    assign bram_var_b_wr_data = dut_var_b_data_o;
    assign bram_var_a_wr_en   = dut_var_a_wr_en_o & ~a_is_ovf;
    assign bram_var_b_wr_en   = dut_var_b_wr_en_o & ~a_is_ovf;

    // synthesis translate_off
    initial $display("test_sign: FF overflow ACTIVE (VAR_HAS_OVERFLOW=%0d ADDR_W=%0d DEPTH=%0d OVF_WORDS=%0d)",
                     VAR_HAS_OVERFLOW, VAR_ADDR_WIDTH_COMBINED, VAR_MEM_DEPTH_COMBINED, OVF_WORDS);
    // synthesis translate_on

  end else begin : gen_no_ovf
    assign var_stall          = 1'b0;
    assign sign_var_a_rd      = var_a_data_out;
    assign sign_var_b_rd      = var_b_data_out;
    assign sign_var_a_rd_bram = var_a_data_out;
    assign sign_var_b_rd_bram = var_b_data_out;
    assign bram_var_a_addr    = dut_var_a_addr_o;
    assign bram_var_b_addr    = dut_var_b_addr_o;
    assign bram_var_a_wr_data = dut_var_a_data_o;
    assign bram_var_b_wr_data = dut_var_b_data_o;
    assign bram_var_a_wr_en   = dut_var_a_wr_en_o;
    assign bram_var_b_wr_en   = dut_var_b_wr_en_o;

    // synthesis translate_off
    initial $display("test_sign: NO overflow (VAR_HAS_OVERFLOW=%0d)", VAR_HAS_OVERFLOW);
    // synthesis translate_on
  end endgenerate

  // Debug mux: Port A (uses BRAM signals, not raw DUT signals)
  wire [VAR_ADDR_WIDTH_COMBINED-1:0] var_a_eff_addr  = dbg_mode_i ? dbg_var_a_addr_i : bram_var_a_addr;
  wire                               var_a_eff_wr_en = dbg_mode_i ? dbg_var_wr_en_i  : bram_var_a_wr_en;
  wire [VAR_DATA_WIDTH_COMBINED-1:0] var_a_eff_data  = dbg_mode_i ? dbg_var_a_data_i : bram_var_a_wr_data;

  // Debug mux: Port B
  wire [VAR_ADDR_WIDTH_COMBINED-1:0] var_b_eff_addr  = dbg_mode_i ? dbg_var_b_addr_i : bram_var_b_addr;
  wire                               var_b_eff_wr_en = dbg_mode_i ? (CAN_DUAL_COMBINED ? 1'b0 : dbg_var_wr_en_i) : bram_var_b_wr_en;
  wire [VAR_DATA_WIDTH_COMBINED-1:0] var_b_eff_data  = dbg_mode_i ? dbg_var_b_data_i : bram_var_b_wr_data;

  var_bram #(
      .DATA_WIDTH   (VAR_DATA_WIDTH_COMBINED),
      .TOTAL_DEPTH  (VAR_MEM_DEPTH_COMBINED),
      .BRAM_DEPTH_32(BRAM_TDP_DEPTH_32)
  ) md_var (
      .clock    (clk_i),
      .data_0   (var_a_eff_data),
      .address_0(var_a_eff_addr),
      .wren_0   (var_a_eff_wr_en),
      .q_0      (var_a_data_out),
      .data_1   (var_b_eff_data),
      .address_1(var_b_eff_addr),
      .wren_1   (var_b_eff_wr_en),
      .q_1      (var_b_data_out)
  );

  assign dbg_var_a_data_o = var_a_data_out;
  assign dbg_var_b_data_o = var_b_data_out;

  // ============================================================
  // Signature memory with debug read mux
  // ============================================================
  wire [63:0]                sig_data_out;
  wire [63:0]                dut_sig_data_o;
  wire [SIG_ADDR_WIDTH-1:0]  dut_sig_addr_o;
  wire                       dut_sig_wr_en_o;

  wire [SIG_ADDR_WIDTH-1:0] sig_eff_addr  = dbg_sig_rd_en_i ? dbg_sig_addr_i : dut_sig_addr_o;
  wire                      sig_eff_wr_en = dbg_sig_rd_en_i ? 1'b0           : dut_sig_wr_en_o;

  assign dbg_sig_data_o = sig_data_out;

  mem_single #(.WIDTH(64), .DEPTH(SIG_MEM_WORDS)) md_sig (
      .clock(clk_i), .data(dut_sig_data_o), .address(sig_eff_addr),
      .wr_en(sig_eff_wr_en), .q(sig_data_out)
  );

  // ============================================================
  // Key memory (witness, read-only by DUT, debug-writable)
  // ============================================================
  wire [63:0]             key_data_out;
  wire [BRAM_ADDR_SIZE:0] dut_key_addr_o;

  wire [BRAM_ADDR_SIZE:0] key_eff_addr  = dbg_key_wr_en_i ? dbg_key_addr_i : dut_key_addr_o;
  wire                    key_eff_wr_en = dbg_key_wr_en_i;

  mem_single #(.WIDTH(64), .DEPTH(BRAM_WIDTH_64_BLOCKS)) md_key (
      .clock(clk_i), .data(dbg_key_data_i), .address(key_eff_addr),
      .wr_en(key_eff_wr_en), .q(key_data_out)
  );

  // ============================================================
  // Message memory (debug-writable, read by piop for h_piop)
  // ============================================================
  wire [63:0]               msg_data_out;
  wire [MSG_ADDR_WIDTH-1:0] dut_msg_addr_o;

  wire [MSG_ADDR_WIDTH-1:0] msg_eff_addr  = dbg_msg_wr_en_i ? dbg_msg_addr_i : dut_msg_addr_o;

  mem_single #(.WIDTH(64), .DEPTH(MSG_MEM_WORDS)) md_msg (
      .clock(clk_i), .data(dbg_msg_data_i), .address(msg_eff_addr),
      .wr_en(dbg_msg_wr_en_i), .q(msg_data_out)
  );

  // ============================================================
  // DUT: sign
  // ============================================================
  sign uut (
      .clk_i        (clk_i),
      .rst_i        (rst_i),
      .var_stall_i  (var_stall),
      .fsm_start_i  (fsm_start_i),
      .salt_i       (salt),
      .rseed_i      (rseed),
      .fsm_done_o   (fsm_done_o),
      .hlines_o     (hlines_o),
      // AES 0
      .aes0_key_o       (aes0_key),
      .aes0_plaintext_o (aes0_plaintext),
      .aes0_ciphertext_i(aes0_ciphertext),
      .aes0_enable_o    (aes0_enable_sign),
      .aes0_ready_i     (aes0_ready),
      .aes0_valid_i     (aes0_valid),
      // AES 1
      .aes1_key_o       (aes1_key),
      .aes1_plaintext_o (aes1_plaintext),
      .aes1_ciphertext_i(aes1_ciphertext),
      .aes1_enable_o    (aes1_enable_sign),
      .aes1_ready_i     (aes1_ready),
      .aes1_valid_i     (aes1_valid),
      // SHAKE
      .shake_start_o           (shake_start_sign),
      .shake_mode_o            (shake_mode),
      .shake_seed_from_output_o(shake_seed_from_output),
      .shake_din_o             (shake_din),
      .shake_din_valid_o       (shake_din_valid_sign),
      .shake_last_din_o        (shake_last_din),
      .shake_last_din_byte_o   (shake_last_din_byte),
      .shake_dout_ready_o      (shake_dout_ready_sign),
      .shake_din_ready_i       (shake_din_ready),
      .shake_dout_i            (shake_dout),
      .shake_dout_valid_i      (shake_dout_valid),
      // Cache BRAM
      .cache_data_i  (cache_data_out),
      .cache_data_o  (dut_cache_data_o),
      .cache_addr_o  (dut_cache_addr_o),
      .cache_wr_en_o (dut_cache_wr_en_o),
      // Var memory (muxed: BRAM or overflow FF bank)
      .var_a_data_i  (sign_var_a_rd),
      .var_a_data_o  (dut_var_a_data_o),
      .var_a_addr_o  (dut_var_a_addr_o),
      .var_a_wr_en_o (dut_var_a_wr_en_o),
      .var_b_data_i  (sign_var_b_rd),
      .var_b_data_o  (dut_var_b_data_o),
      .var_b_addr_o  (dut_var_b_addr_o),
      .var_b_wr_en_o (dut_var_b_wr_en_o),
      // Var memory bypass (always raw BRAM, for identity reads during stall)
      .var_a_data_bram_i (sign_var_a_rd_bram),
      .var_b_data_bram_i (sign_var_b_rd_bram),
      // Sig memory
      .sig_data_i  (sig_data_out),
      .sig_data_o  (dut_sig_data_o),
      .sig_addr_o  (dut_sig_addr_o),
      .sig_wr_en_o (dut_sig_wr_en_o),
      // Key memory
      .key_data_i  (key_data_out),
      .key_addr_o  (dut_key_addr_o),
      // Message memory
      .msg_data_i  (msg_data_out),
      .msg_addr_o  (dut_msg_addr_o)
  );

  // SHAKE din snoop
  assign dbg_shake_din_o       = shake_din;
  assign dbg_shake_din_valid_o = shake_din_valid_sign;
  assign dbg_shake_din_ready_o = shake_din_ready;
  assign dbg_shake_last_din_o  = shake_last_din;
  assign dbg_shake_last_byte_o = shake_last_din_byte;

  // Expose internal stage for early verification
  assign dbg_stage_o = uut.stage;

  // Sub-module signals for cycle profiling (no generate-block references)
  assign dbg_gr_active_o    = uut.gr_active;
  assign dbg_hlines_state_o = uut.u_hlines.state;
  assign dbg_piop_state_o   = uut.u_piop.state;

endmodule
