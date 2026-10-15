// SPDX-FileCopyrightText: 2026 Stef Halmans, Niklas Höher
// SPDX-License-Identifier: LicenseRef-RUB-SecEng

import sdith_params_pkg::*;

// Structural wrapper: instantiates crypto primitives (2x AES, SHAKE) and
// internal memories (cache BRAM, var BRAM) around the sign orchestrator.
// Primitive variants selected via ENC and HASH_XOF enums from sdith_params_pkg:
//   ENC_AES128 + HASH_SHAKE128    (SEC1)
//   ENC_RIJNDAEL256 + HASH_SHAKE256 (SEC3/5)
// Sig and key memory are external (provided by implement_sign_top or host).

module sign_top (
    input  logic clk_i,
    input  logic rst_ni,

    // Control
    input  logic start_i,
    output logic done_o,

    // Seed and salt
    input logic [LAMBDA-1:0] salt_i,
    input logic [LAMBDA-1:0] rseed_i,

    // Hash output
    output logic [2*LAMBDA-1:0] hlines_o,

    // External signature memory
    input  logic [63:0]              sig_data_i,
    output logic [63:0]              sig_data_o,
    output logic [SIG_ADDR_WIDTH-1:0] sig_addr_o,
    output logic                     sig_wr_en_o,

    // External key memory (read-only from sign)
    input  logic [63:0]             key_data_i,
    output logic [BRAM_ADDR_SIZE:0] key_addr_o,

    // External message memory (read-only from sign, used by hash_piop)
    input  logic [63:0]               msg_data_i,
    output logic [MSG_ADDR_WIDTH-1:0] msg_addr_o
);

  // AES instances: ENC enum (from package) selects AES-128 (NB=NK=4) vs Rijndael-256 (NB=NK=8)
  logic [ENC_KEYSIZE-1:0]   aes0_key, aes1_key;
  logic [ENC_BLOCKSIZE-1:0] aes0_plaintext, aes0_ciphertext;
  logic [ENC_BLOCKSIZE-1:0] aes1_plaintext, aes1_ciphertext;
  logic                     aes0_enable_sign, aes0_ready, aes0_valid;
  logic                     aes1_enable_sign, aes1_ready, aes1_valid;

  // SHAKE/AES gating during var stall (forward-declared; var_stall driven below)
  logic var_stall;
  wire aes0_enable_gated      = aes0_enable_sign       & ~var_stall;
  wire aes1_enable_gated      = aes1_enable_sign       & ~var_stall;

  generate
    if (ENC == ENC_AES128) begin : gen_aes
      rijndael_encrypt #(.NB(4), .NK(4)) aes0 (
          .clk_i(clk_i), .rst_ni(rst_ni),
          .enable_i(aes0_enable_gated), .ready_o(aes0_ready), .valid_o(aes0_valid),
          .plaintext_i(aes0_plaintext), .key_i(aes0_key), .ciphertext_o(aes0_ciphertext)
      );
      rijndael_encrypt #(.NB(4), .NK(4)) aes1_inst (
          .clk_i(clk_i), .rst_ni(rst_ni),
          .enable_i(aes1_enable_gated), .ready_o(aes1_ready), .valid_o(aes1_valid),
          .plaintext_i(aes1_plaintext), .key_i(aes1_key), .ciphertext_o(aes1_ciphertext)
      );
    end else begin : gen_aes  // ENC_RIJNDAEL256
      rijndael_encrypt #(.NB(8), .NK(8)) aes0 (
          .clk_i(clk_i), .rst_ni(rst_ni),
          .enable_i(aes0_enable_gated), .ready_o(aes0_ready), .valid_o(aes0_valid),
          .plaintext_i(aes0_plaintext), .key_i(aes0_key), .ciphertext_o(aes0_ciphertext)
      );
      rijndael_encrypt #(.NB(8), .NK(8)) aes1_inst (
          .clk_i(clk_i), .rst_ni(rst_ni),
          .enable_i(aes1_enable_gated), .ready_o(aes1_ready), .valid_o(aes1_valid),
          .plaintext_i(aes1_plaintext), .key_i(aes1_key), .ciphertext_o(aes1_ciphertext)
      );
    end
  endgenerate

  // SHAKE: HASH_XOF enum (from package) selects SHAKE128 vs SHAKE256
  logic        shake_start_sign, shake_mode, shake_seed_from_output;
  logic [63:0] shake_din, shake_dout;
  logic        shake_din_valid_sign, shake_last_din, shake_dout_ready_sign;
  logic [ 3:0] shake_last_din_byte;
  logic        shake_din_ready, shake_dout_valid;

  logic var_stall_for_shake;
  always_ff @(posedge clk_i) begin
    if (~rst_ni) var_stall_for_shake <= 1'b0;
    else         var_stall_for_shake <= var_stall;
  end

  wire shake_start_gated       = shake_start_sign      & ~var_stall_for_shake;
  wire shake_din_valid_gated   = shake_din_valid_sign  & ~var_stall_for_shake;
  wire shake_last_din_gated    = shake_last_din        & ~var_stall_for_shake;
  wire shake_dout_ready_gated  = shake_dout_ready_sign & ~var_stall_for_shake;

  generate
    if (HASH_XOF == HASH_SHAKE128) begin : gen_shake
      shake_top #(
          .VARIANT  (128),
          .HASH_SIZE(2 * LAMBDA)
      ) shake128 (
          .clk_i             (clk_i),
          .rst_ni            (rst_ni),
          .start_i           (shake_start_gated),
          .mode_i            (shake_mode),
          .seed_from_output_i(shake_seed_from_output),
          .din_i             (shake_din),
          .din_valid_i       (shake_din_valid_gated),
          .last_din_i        (shake_last_din_gated),
          .last_din_byte_i   (shake_last_din_byte),
          .dout_ready_i      (shake_dout_ready_gated),
          .din_ready_o       (shake_din_ready),
          .dout_o            (shake_dout),
          .dout_valid_o      (shake_dout_valid)
      );
    end else begin : gen_shake  // HASH_SHAKE256
      shake_top #(
          .VARIANT  (256),
          .HASH_SIZE(2 * LAMBDA)
      ) shake256 (
          .clk_i             (clk_i),
          .rst_ni            (rst_ni),
          .start_i           (shake_start_gated),
          .mode_i            (shake_mode),
          .seed_from_output_i(shake_seed_from_output),
          .din_i             (shake_din),
          .din_valid_i       (shake_din_valid_gated),
          .last_din_i        (shake_last_din_gated),
          .last_din_byte_i   (shake_last_din_byte),
          .dout_ready_i      (shake_dout_ready_gated),
          .din_ready_o       (shake_din_ready),
          .dout_o            (shake_dout),
          .dout_valid_o      (shake_dout_valid)
      );
    end
  endgenerate

  // Tree-cache BRAM - stores the GGM tree layer at the cache depth
  logic [63:0]             cache_rd_data;
  logic [63:0]             cache_wr_data;
  logic [CACHE_ADDR_WIDTH-1:0] cache_addr;
  logic                    cache_wr_en;

  mem_single #(.WIDTH(64), .DEPTH(CACHE_BRAM_DEPTH)) md_cache (
      .clock(clk_i), .data(cache_wr_data), .address(cache_addr),
      .wr_en(cache_wr_en), .q(cache_rd_data)
  );

  // Variable memory - 32-bit TDP (SEC1) or 64-bit SDP (SEC3/5) via var_bram
  // Signals between sign module and the overflow interception layer
  logic [VAR_DATA_WIDTH_COMBINED-1:0] sign_var_a_rd_data, sign_var_b_rd_data;
  // Raw BRAM bypass (for identity reads during RAMB18 stall)
  logic [VAR_DATA_WIDTH_COMBINED-1:0] sign_var_a_rd_bram, sign_var_b_rd_bram;
  logic [VAR_DATA_WIDTH_COMBINED-1:0] sign_var_a_wr_data, sign_var_b_wr_data;
  logic [VAR_ADDR_WIDTH_COMBINED-1:0] sign_var_a_addr, sign_var_b_addr;
  logic                               sign_var_a_wr_en, sign_var_b_wr_en;

  // Signals between overflow interception and var_bram
  logic [VAR_DATA_WIDTH_COMBINED-1:0] bram_var_a_rd_data, bram_var_b_rd_data;
  logic [VAR_DATA_WIDTH_COMBINED-1:0] bram_var_a_wr_data, bram_var_b_wr_data;
  logic [VAR_ADDR_WIDTH_COMBINED-1:0] bram_var_a_addr, bram_var_b_addr;
  logic                               bram_var_a_wr_en, bram_var_b_wr_en;

  var_bram #(
      .DATA_WIDTH   (VAR_DATA_WIDTH_COMBINED),
      .TOTAL_DEPTH  (VAR_MEM_DEPTH_COMBINED),
      .BRAM_DEPTH_32(BRAM_TDP_DEPTH_32)
  ) md_var (
      .clock    (clk_i),
      .data_0   (bram_var_a_wr_data),
      .address_0(bram_var_a_addr),
      .wren_0   (bram_var_a_wr_en),
      .q_0      (bram_var_a_rd_data),
      .data_1   (bram_var_b_wr_data),
      .address_1(bram_var_b_addr),
      .wren_1   (bram_var_b_wr_en),
      .q_1      (bram_var_b_rd_data)
  );

  // RAMB18 overflow bank (SEC1 SHORT HP=0 only): alpha rows + haux exceeding var BRAM.
  // Stall safe: var_stall gates AES/SHAKE and freezes the sign FSM.

  generate
    if (VAR_HAS_OVERFLOW) begin : gen_ovf
      localparam OVF_PHYS_BASE = BRAM_TDP_DEPTH_32;
      localparam OVF_WORDS = VAR_MAX_LOGICAL_ADDR - BRAM_TDP_DEPTH_32 / 2;
      localparam OVF_PHYS_END = OVF_PHYS_BASE + 2 * OVF_WORDS;
      localparam OVF_BRAM_DEPTH = 1024;
      localparam OVF_ADDR_W = $clog2(OVF_BRAM_DEPTH);

      wire a_is_ovf = (sign_var_a_addr >= VAR_ADDR_WIDTH_COMBINED'(OVF_PHYS_BASE))
                    && (sign_var_a_addr < VAR_ADDR_WIDTH_COMBINED'(OVF_PHYS_END));

      wire [OVF_ADDR_W-1:0] ovf_entry_a = OVF_ADDR_W'(sign_var_a_addr - VAR_ADDR_WIDTH_COMBINED'(OVF_PHYS_BASE));
      wire [OVF_ADDR_W-1:0] ovf_entry_b = OVF_ADDR_W'(sign_var_b_addr - VAR_ADDR_WIDTH_COMBINED'(OVF_PHYS_BASE));

      wire [15:0] ovf_lo_q, ovf_hi_q;
      logic [15:0] ovf_lo_wr, ovf_hi_wr;
      logic [OVF_ADDR_W-1:0] ovf_bram_addr;
      logic ovf_bram_wren;

      mem_dual #(.WIDTH(16), .DEPTH(OVF_BRAM_DEPTH)) bram_overflow (
          .clock    (clk_i),
          .data_0   (ovf_lo_wr), .address_0({ovf_bram_addr, 1'b0}),
          .wren_0   (ovf_bram_wren), .q_0(ovf_lo_q),
          .data_1   (ovf_hi_wr), .address_1({ovf_bram_addr, 1'b1}),
          .wren_1   (ovf_bram_wren), .q_1(ovf_hi_q)
      );

      wire [31:0] ovf_rd_word = {ovf_hi_q, ovf_lo_q};

      typedef enum logic [1:0] {OVF_IDLE, OVF_PHASE_B, OVF_RD_DONE} ovf_state_t;
      ovf_state_t ovf_state;
      logic use_ovf_data, ovf_served;
      reg [VAR_DATA_WIDTH_COMBINED-1:0] ovf_a_captured, ovf_b_captured;
      reg [VAR_DATA_WIDTH_COMBINED-1:0] wr_b_latch;
      reg [OVF_ADDR_W-1:0]             wr_b_entry;
      reg [OVF_ADDR_W-1:0]             served_entry;
      logic phase_b_is_write;

      wire ovf_new_addr = (ovf_entry_a != served_entry);
      wire ovf_trigger = a_is_ovf && ovf_state == OVF_IDLE
                       && (ovf_new_addr || !ovf_served
                           || sign_var_a_wr_en != phase_b_is_write);

      always_ff @(posedge clk_i) begin
        if (~rst_ni) begin
          ovf_state        <= OVF_IDLE;
          use_ovf_data     <= 1'b0;
          ovf_served       <= 1'b0;
          phase_b_is_write <= 1'b0;
          served_entry     <= '0;
        end else begin
          case (ovf_state)
            OVF_IDLE: begin
              if (ovf_trigger) begin
                phase_b_is_write <= sign_var_a_wr_en;
                wr_b_entry       <= ovf_entry_b;
                served_entry     <= ovf_entry_a;
                if (sign_var_a_wr_en)
                  wr_b_latch <= sign_var_b_wr_data;
                ovf_state  <= OVF_PHASE_B;
                ovf_served <= 1'b1;
              end
              if (!a_is_ovf) begin
                use_ovf_data <= 1'b0;
                ovf_served   <= 1'b0;
              end
            end
            OVF_PHASE_B: begin
              if (phase_b_is_write) begin
                ovf_state <= OVF_IDLE;
              end else begin
                ovf_a_captured <= ovf_rd_word;
                ovf_state      <= OVF_RD_DONE;
              end
            end
            OVF_RD_DONE: begin
              ovf_b_captured <= ovf_rd_word;
              ovf_state      <= OVF_IDLE;
              use_ovf_data   <= 1'b1;
            end
            default: ovf_state <= OVF_IDLE;
          endcase
        end
      end

      assign var_stall = ovf_trigger || (ovf_state != OVF_IDLE);

      always_comb begin
        ovf_bram_wren = 1'b0;
        ovf_lo_wr     = '0;
        ovf_hi_wr     = '0;
        ovf_bram_addr = ovf_entry_a;

        case (ovf_state)
          OVF_IDLE: begin
            if (ovf_trigger) begin
              ovf_bram_addr = ovf_entry_a;
              if (sign_var_a_wr_en) begin
                ovf_bram_wren = 1'b1;
                ovf_lo_wr     = sign_var_a_wr_data[15:0];
                ovf_hi_wr     = sign_var_a_wr_data[31:16];
              end
            end
          end
          OVF_PHASE_B: begin
            ovf_bram_addr = wr_b_entry;
            if (phase_b_is_write) begin
              ovf_bram_wren = 1'b1;
              ovf_lo_wr     = wr_b_latch[15:0];
              ovf_hi_wr     = wr_b_latch[31:16];
            end
          end
          OVF_RD_DONE: begin
            ovf_bram_addr = ovf_entry_a;
          end
          default: ;
        endcase
      end

      assign sign_var_a_rd_data = use_ovf_data ? ovf_a_captured : bram_var_a_rd_data;
      assign sign_var_b_rd_data = use_ovf_data ? ovf_b_captured : bram_var_b_rd_data;
      assign sign_var_a_rd_bram = bram_var_a_rd_data;
      assign sign_var_b_rd_bram = bram_var_b_rd_data;
      assign bram_var_a_addr    = sign_var_a_addr;
      assign bram_var_b_addr    = sign_var_b_addr;
      assign bram_var_a_wr_data = sign_var_a_wr_data;
      assign bram_var_b_wr_data = sign_var_b_wr_data;
      assign bram_var_a_wr_en   = sign_var_a_wr_en & ~a_is_ovf;
      assign bram_var_b_wr_en   = sign_var_b_wr_en & ~a_is_ovf;

    end else begin : gen_no_ovf
      // No overflow: direct passthrough
      assign var_stall           = 1'b0;
      assign sign_var_a_rd_data  = bram_var_a_rd_data;
      assign sign_var_b_rd_data  = bram_var_b_rd_data;
      assign sign_var_a_rd_bram  = bram_var_a_rd_data;
      assign sign_var_b_rd_bram  = bram_var_b_rd_data;
      assign bram_var_a_addr     = sign_var_a_addr;
      assign bram_var_b_addr     = sign_var_b_addr;
      assign bram_var_a_wr_data  = sign_var_a_wr_data;
      assign bram_var_b_wr_data  = sign_var_b_wr_data;
      assign bram_var_a_wr_en    = sign_var_a_wr_en;
      assign bram_var_b_wr_en    = sign_var_b_wr_en;

    end
  endgenerate

  // Signing orchestrator - all crypto primitives and internal memories above
  sign u_blc_commit (
      .clk_i       (clk_i),
      .rst_i       (~rst_ni),
      .fsm_start_i (start_i),
      .salt_i      (salt_i),
      .rseed_i     (rseed_i),
      .fsm_done_o  (done_o),
      .hlines_o    (hlines_o),
      .var_stall_i (var_stall),
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
      // Cache BRAM (internal)
      .cache_data_i  (cache_rd_data),
      .cache_data_o  (cache_wr_data),
      .cache_addr_o  (cache_addr),
      .cache_wr_en_o (cache_wr_en),
      // Var memory (internal) - through overflow interception layer
      .var_a_data_i  (sign_var_a_rd_data),
      .var_a_data_o  (sign_var_a_wr_data),
      .var_a_addr_o  (sign_var_a_addr),
      .var_a_wr_en_o (sign_var_a_wr_en),
      .var_b_data_i  (sign_var_b_rd_data),
      .var_b_data_o  (sign_var_b_wr_data),
      .var_b_addr_o  (sign_var_b_addr),
      .var_b_wr_en_o (sign_var_b_wr_en),
      .var_a_data_bram_i (sign_var_a_rd_bram),
      .var_b_data_bram_i (sign_var_b_rd_bram),
      // Sig memory (external)
      .sig_data_i  (sig_data_i),
      .sig_data_o  (sig_data_o),
      .sig_addr_o  (sig_addr_o),
      .sig_wr_en_o (sig_wr_en_o),
      // Key memory (external)
      .key_data_i  (key_data_i),
      .key_addr_o  (key_addr_o),
      // Message memory (external)
      .msg_data_i  (msg_data_i),
      .msg_addr_o  (msg_addr_o)
  );

endmodule
