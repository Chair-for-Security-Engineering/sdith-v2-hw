// SPDX-FileCopyrightText: 2026 Stef Halmans, Niklas Höher
// SPDX-License-Identifier: LicenseRef-RUB-SecEng


import sdith_params_pkg::*;

// blc_racc_combined
//
// r_acc accumulator: expands a leaf seed with the Rijndael PRG in counter
// mode (both cores in parallel, CTR blocks are independent) into
// R_ACC_PARTS 64-bit words of r_rnd, XOR-accumulating them into the r_acc
// slot in scratchpad. first_run_i suppresses the read-modify-write so the
// first leaf initialises the slot. The memory interface adapts to the
// scratchpad port width:
//
//   CAN_DUAL=0 (SEC1, 32-bit ports):
//     Port A = lower 32 bits, Port B = upper 32 bits of each 64-bit word.
//     Both ports addressed simultaneously to form one 64-bit access.
//
//   CAN_DUAL=1 (SEC3/5, 64-bit+ ports):
//     Port A carries full 64-bit read/write.
//     Port B is idle (parent may reuse the port externally).

module blc_racc_combined (
    input logic clk_i,
    input logic rst_i,
    input logic fsm_enable_i,

    input logic [ENC_KEYSIZE-1:0] seed_i,
    input logic first_run_i,
    input logic [BRAM_ADDR_SIZE:0] slot_offset_i,

    output logic fsm_done_o,

    // IO for controlling external AES instance 0
    output logic [ENC_KEYSIZE-1 : 0] aes0_key_o,
    output logic [ENC_BLOCKSIZE-1 : 0] aes0_plaintext_o,
    input logic [ENC_BLOCKSIZE-1 : 0] aes0_ciphertext_i,
    output logic aes0_enable_o,
    input logic aes0_ready_i,
    input logic aes0_valid_i,

    // IO for controlling external AES instance 1
    output logic [ENC_KEYSIZE-1 : 0] aes1_key_o,
    output logic [ENC_BLOCKSIZE-1 : 0] aes1_plaintext_o,
    input logic [ENC_BLOCKSIZE-1 : 0] aes1_ciphertext_i,
    output logic aes1_enable_o,
    input logic aes1_ready_i,
    input logic aes1_valid_i,

    // Dual-port variable memory interface
    input  logic [VAR_DATA_WIDTH_COMBINED-1:0] var_a_data_i,
    output logic [VAR_DATA_WIDTH_COMBINED-1:0] var_a_data_o,
    output logic [VAR_ADDR_WIDTH_COMBINED-1:0] var_a_addr_o,
    output logic                               var_a_wr_en_o,

    input  logic [VAR_DATA_WIDTH_COMBINED-1:0] var_b_data_i,
    output logic [VAR_DATA_WIDTH_COMBINED-1:0] var_b_data_o,
    output logic [VAR_ADDR_WIDTH_COMBINED-1:0] var_b_addr_o,
    output logic                               var_b_wr_en_o
);

  // Internal 64-bit logical interface; port translation below maps to
  // physical 32-bit (SEC1) or 64-bit (SEC3/5) BRAM ports
  logic [63:0] var_data_rd, var_data_wr;
  logic [BRAM_ADDR_SIZE:0] var_addr_log;
  logic var_wr_en_log;
  generate
    if (CAN_DUAL_COMBINED) begin : gen_can_dual
      // 64-bit mode: Port A handles everything
      assign var_a_addr_o  = VAR_ADDR_WIDTH_COMBINED'(var_addr_log);
      assign var_a_data_o  = VAR_DATA_WIDTH_COMBINED'(var_data_wr);
      assign var_a_wr_en_o = var_wr_en_log;
      assign var_data_rd   = 64'(var_a_data_i);

      // Port B idle
      assign var_b_addr_o  = '0;
      assign var_b_data_o  = '0;
      assign var_b_wr_en_o = 1'b0;
    end else begin : gen_split
      // 32-bit mode: Port A = lower half, Port B = upper half
      assign var_a_addr_o  = VAR_ADDR_WIDTH_COMBINED'({var_addr_log, 1'b0});
      assign var_b_addr_o  = VAR_ADDR_WIDTH_COMBINED'({var_addr_log, 1'b1});
      assign var_a_data_o  = var_data_wr[31:0];
      assign var_b_data_o  = var_data_wr[63:32];
      assign var_a_wr_en_o = var_wr_en_log;
      assign var_b_wr_en_o = var_wr_en_log;
      assign var_data_rd   = {var_b_data_i, var_a_data_i};
    end
  endgenerate

  // Core: fires AES pairs (idx, idx+1), extracts 64-bit words from byte-swapped
  // ciphertext, XORs into var memory at slot_offset. Addressing:
  //   flat_word = (idx + block_phase) * BLOCK_DIV_64 + aes_part
  // where idx steps by 2 (pair), block_phase selects AES0(0) or AES1(1),
  // and aes_part selects the 64-bit sub-word within each AES block.

  typedef enum logic [2:0] {
    S_IDLE     = 3'd0,
    S_WAIT_AES = 3'd1,
    S_WRITE    = 3'd2,
    S_READ     = 3'd3,
    S_DONE     = 3'd4
  } state_t;

  state_t state, next_state;

  // Latched key: seed_i may change mid-computation due to leaf cache prefetch
  logic [ENC_KEYSIZE-1:0] aes_key_reg;

  logic [ENC_BLOCKSIZE-1 : 0] aes0_prev;
  logic [ENC_BLOCKSIZE-1 : 0] aes1_prev;
  // aes_prev registers use explicit clock enable
  wire aes_prev_en = (state == S_WAIT_AES) && valid_condition;
  logic block_phase, next_block_phase;

  wire valid_condition = aes0_valid_i && aes1_valid_i;

  reg [BLOCK_DIV_64-1:0] aes_part, next_aes_part;
  reg [$clog2(R_ACC_PARTS)-1:0] idx, next_idx;

  logic [63:0] seed_full;

  assign aes0_key_o = state == S_IDLE ? seed_i : aes_key_reg;
  assign aes1_key_o = state == S_IDLE ? seed_i : aes_key_reg;

  // Select which AES output to extract from:
  //   aes_part==0 -> live ciphertext, else -> prev (latched on first sub-word)
  //   block_phase==0 -> AES0 (even block), ==1 -> AES1 (odd block)
  wire [ENC_BLOCKSIZE-1:0] current_cipher =
      (block_phase == 0) ? (aes_part == 0 ? aes0_ciphertext_i : aes0_prev) : aes1_prev;

  // Extract 64-bit word from AES output, byte-swap to match C reference LE layout
  wire [63:0] seed_full_be = 64'(current_cipher >> ((BLOCK_DIV_64 - 1 - aes_part) * 64));
  assign seed_full = {seed_full_be[7:0], seed_full_be[15:8], seed_full_be[23:16], seed_full_be[31:24],
                      seed_full_be[39:32], seed_full_be[47:40], seed_full_be[55:48], seed_full_be[63:56]};
  // No masking: generate full R_ACC_PARTS*64 bits (= R_ACC_SIZE_ROUND)
  // to match C reference which uses Lbyte*8 = R_ACC_SIZE rounded up to mult of 8
  assign var_data_wr = (first_run_i ? 0 : var_data_rd) ^ seed_full;

  wire [BRAM_ADDR_SIZE:0] slot_offset = slot_offset_i;
  wire [BRAM_ADDR_SIZE:0] flat_word   = (idx + block_phase) * BLOCK_DIV_64 + aes_part;
  wire is_last_word = (flat_word == R_ACC_PARTS - 1);

  assign var_addr_log = slot_offset + flat_word;

  always_comb begin
    next_state = state;
    next_idx = idx;
    next_aes_part = aes_part;
    next_block_phase = block_phase;
    fsm_done_o = 0;
    var_wr_en_log = 0;
    aes0_enable_o = 0;
    aes1_enable_o = 0;
    aes0_plaintext_o = '0;
    aes1_plaintext_o = '0;

    case (state)
      S_IDLE:
      if (fsm_enable_i) begin
        aes0_enable_o = 1;
        aes1_enable_o = 1;
        next_state = S_WAIT_AES;
        aes0_plaintext_o = {8'd0, {ENC_BLOCKSIZE-8{1'b0}}};
        aes1_plaintext_o = {8'd1, {ENC_BLOCKSIZE-8{1'b0}}};
      end
      S_WAIT_AES: begin
        aes0_plaintext_o = {8'(idx), {ENC_BLOCKSIZE-8{1'b0}}};
        aes1_plaintext_o = {8'(idx + 1), {ENC_BLOCKSIZE-8{1'b0}}};
        if (valid_condition) begin
          if ((idx + 2) * BLOCK_DIV_64 < R_ACC_PARTS) begin
            aes0_enable_o = 1;
            aes1_enable_o = 1;
            aes0_plaintext_o = {8'(idx + 2), {ENC_BLOCKSIZE-8{1'b0}}};
            aes1_plaintext_o = {8'(idx + 3), {ENC_BLOCKSIZE-8{1'b0}}};
          end

          // aes0_prev/aes1_prev loaded via explicit CE (aes_prev_en)
          var_wr_en_log = 1;

          if (is_last_word) begin
            next_idx = 0;
            next_aes_part = 0;
            next_block_phase = 0;
            next_state = S_DONE;
          end else begin
            next_aes_part = aes_part + 1;
            next_state = S_READ;
          end
        end
      end
      S_READ: begin
        aes0_plaintext_o = {8'(idx + 2), {ENC_BLOCKSIZE-8{1'b0}}};
        aes1_plaintext_o = {8'(idx + 3), {ENC_BLOCKSIZE-8{1'b0}}};
        next_state = S_WRITE;
      end
      S_WRITE: begin
        aes0_plaintext_o = {8'(idx + 2), {ENC_BLOCKSIZE-8{1'b0}}};
        aes1_plaintext_o = {8'(idx + 3), {ENC_BLOCKSIZE-8{1'b0}}};
        var_wr_en_log = 1;

        if (is_last_word) begin
          next_idx = 0;
          next_aes_part = 0;
          next_block_phase = 0;
          next_state = S_DONE;
        end else if (aes_part == BLOCK_DIV_64 - 1 && block_phase == 0) begin
          next_state = S_READ;
          next_block_phase = 1;
          next_aes_part = 0;
        end else if (aes_part == BLOCK_DIV_64 - 1 && block_phase == 1) begin
          next_state = S_WAIT_AES;
          next_idx = idx + 2;
          next_block_phase = 0;
          next_aes_part = 0;
        end else begin
          next_aes_part = aes_part + 1;
          next_state = S_READ;
        end
      end
      S_DONE: begin
        fsm_done_o = 1;
        next_state = S_IDLE;
      end
    endcase
  end

  always_ff @(posedge clk_i or posedge rst_i) begin
    if (rst_i) begin
      state <= S_IDLE;
      idx <= 0;
      aes_part <= 0;
      aes0_prev <= '0;
      aes1_prev <= '0;
      block_phase <= 0;
    end else begin
      state <= next_state;
      aes_part <= next_aes_part;
      if (aes_prev_en) begin
        aes0_prev <= aes0_ciphertext_i;
        aes1_prev <= aes1_ciphertext_i;
      end
      block_phase <= next_block_phase;
      idx <= next_idx;
      if (fsm_enable_i && state == S_IDLE) begin
        aes_key_reg <= seed_i;
      end
    end
  end

endmodule
