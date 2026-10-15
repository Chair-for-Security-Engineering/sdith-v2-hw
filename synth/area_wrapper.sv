// SPDX-FileCopyrightText: 2026 Stef Halmans, Niklas Höher
// SPDX-License-Identifier: LicenseRef-RUB-SecEng

import sdith_params_pkg::*;

// Area-measurement wrapper for Vivado place-and-route.
//
// sign_top has several hundred I/O pins, more than the device provides, so it
// cannot be placed directly. This wrapper reduces the I/O to four pins: the
// inputs are fed from a serial shift register and all outputs are
// XOR-reduced so that no logic is optimised away. It wraps implement_sign_top
// (key and signature BRAMs + sign_top). Utilisation is reported for the
// sign_top instance only; the wrapper and the I/O memories are excluded.
module area_wrapper (
    input  logic clk_i,
    input  logic rst_ni,
    input  logic data_i,
    output logic data_o
);

  localparam int INPUT_WIDTH = 1 + LAMBDA + LAMBDA + SIG_ADDR_WIDTH;

  logic [INPUT_WIDTH-1:0] input_sr;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) input_sr <= '0;
    else         input_sr <= {input_sr[INPUT_WIDTH-2:0], data_i};
  end

  logic                      dut_start;
  logic [LAMBDA-1:0]         dut_salt;
  logic [LAMBDA-1:0]         dut_rseed;
  logic [SIG_ADDR_WIDTH-1:0] dut_sig_rd_addr;

  assign {dut_start, dut_salt, dut_rseed, dut_sig_rd_addr} = input_sr;

  logic                dut_done;
  logic [2*LAMBDA-1:0] dut_hlines;
  logic [63:0]         dut_sig_rd_data;

  implement_sign_top #(
      .KEY_FILE("")
  ) u_dut (
      .clk_i        (clk_i),
      .rst_ni       (rst_ni),
      .start_i      (dut_start),
      .done_o       (dut_done),
      .salt_i       (dut_salt),
      .rseed_i      (dut_rseed),
      .hlines_o     (dut_hlines),
      .sig_rd_addr_i(dut_sig_rd_addr),
      .sig_rd_data_o(dut_sig_rd_data)
  );

  assign data_o = ^{dut_done, dut_hlines, dut_sig_rd_data};

endmodule
