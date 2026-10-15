// SPDX-FileCopyrightText: 2026 Stef Halmans, Niklas Höher
// SPDX-License-Identifier: LicenseRef-RUB-SecEng

import sdith_params_pkg::*;

// implement_sign_top
//
// FPGA implementation wrapper for sign_top. Instantiates the key and signature
// BRAMs alongside sign_top, with the key BRAM pre-loaded from a file.
//
// Usage:
//   1. Generate key_data.mem from the C reference (binary, 64-bit words)
//   2. Synthesize with KEY_FILE pointing to the .mem file
//   3. Assert start_i to begin signing
//   4. Wait for done_o
//   5. Read signature via sig_rd_addr_i / sig_rd_data_o

module implement_sign_top #(
    parameter KEY_FILE = ""
) (
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

    // Signature readback port (active after done_o)
    input  logic [SIG_ADDR_WIDTH-1:0] sig_rd_addr_i,
    output logic [63:0]               sig_rd_data_o
);
  // Key memory (read-only, loaded from file)

  logic [63:0]             key_rd_data;
  logic [BRAM_ADDR_SIZE:0] key_addr;

  mem_single #(
      .WIDTH(64),
      .DEPTH(BRAM_WIDTH_64_BLOCKS),
      .FILE (KEY_FILE)
  ) md_key (
      .clock  (clk_i),
      .data   (64'b0),
      .address(key_addr),
      .wr_en  (1'b0),
      .q      (key_rd_data)
  );
  // Signature memory (written by sign_top, read back after done)

  logic [63:0]              sig_rd_data;
  logic [63:0]              sig_wr_data;
  logic [SIG_ADDR_WIDTH-1:0] sig_addr;
  logic                     sig_wr_en;

  // Mux: sign_top writes during signing, readback port reads after done
  wire [SIG_ADDR_WIDTH-1:0] sig_eff_addr  = done_o ? sig_rd_addr_i : sig_addr;
  wire                      sig_eff_wr_en = done_o ? 1'b0          : sig_wr_en;

  assign sig_rd_data_o = sig_rd_data;

  mem_single #(
      .WIDTH(64),
      .DEPTH(SIG_MEM_WORDS)
  ) md_sig (
      .clock  (clk_i),
      .data   (sig_wr_data),
      .address(sig_eff_addr),
      .wr_en  (sig_eff_wr_en),
      .q      (sig_rd_data)
  );
  // sign_top

  sign_top u_sign (
      .clk_i      (clk_i),
      .rst_ni     (rst_ni),
      .start_i    (start_i),
      .done_o     (done_o),
      .salt_i     (salt_i),
      .rseed_i    (rseed_i),
      .hlines_o   (hlines_o),
      // Sig memory
      .sig_data_i (sig_rd_data),
      .sig_data_o (sig_wr_data),
      .sig_addr_o (sig_addr),
      .sig_wr_en_o(sig_wr_en),
      // Key memory
      .key_data_i (key_rd_data),
      .key_addr_o (key_addr),
      // Message memory tied off: this wrapper signs the empty message
      // (hash_piop reads a length of 0 and skips the message feed).
      .msg_data_i (64'b0),
      .msg_addr_o (/* unused */)
  );

endmodule
