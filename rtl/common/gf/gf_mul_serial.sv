// SPDX-FileCopyrightText: 2026 Stef Halmans, Niklas Höher
// SPDX-License-Identifier: LicenseRef-RUB-SecEng

import sdith_params_pkg::*;

// gf_mul_serial
//
// Serial GF(2^LAMBDA) multiplier with on-the-fly reduction.
// Processes G bits of operand b per cycle (MSB-first Horner evaluation).
// Latency = LAMBDA/G cycles.
//
// Reduction polynomial from sdith_params_pkg (GF_POLY / GF_POLY_DEGREE):
//   LAMBDA = 128/192: x^lambda + x^7 + x^2 + x + 1
//   LAMBDA = 256    : x^lambda + x^10 + x^5 + x^2 + 1
//
// MSB-first Horner: accum = accum*x^G + a*chunk, reduced each step.
//
// No backpressure. Caller must wait for out_valid before issuing a new pair.

module gf_mul_serial #(
    parameter int LAMBDA = 128
) (
    input  logic              clk_i,
    input  logic              rst_i,
    input  logic              in_valid_i,
    input  logic [LAMBDA-1:0] a_i,
    input  logic [LAMBDA-1:0] b_i,
    output logic              out_valid_o,
    output logic [LAMBDA-1:0] out_o
);

  localparam int G      = 16;
  localparam int N_ITER = LAMBDA / G;
  localparam int CNT_W  = $clog2(N_ITER);
  localparam int EXT_W  = LAMBDA + G;

  logic [LAMBDA-1:0] a_reg;
  logic [LAMBDA-1:0] b_reg;
  logic [LAMBDA-1:0] accum;
  logic [CNT_W-1:0]  cnt;
  logic              running;
  logic [LAMBDA-1:0] out_reg;
  logic              v_out;

  wire [G-1:0] b_chunk = b_reg[LAMBDA-1 -: G];

  // Partial products for current G bits of b
  logic [EXT_W-1:0] pp_sum;
  always_comb begin
    pp_sum = '0;
    for (int k = 0; k < G; k++) begin
      if (b_chunk[k])
        pp_sum = pp_sum ^ (EXT_W'(a_reg) << k);
    end
  end

  // Shift accumulator left by G, add partial products
  wire [EXT_W-1:0] with_pp = {accum, G'(0)} ^ pp_sum;

  // Reduce bits [LAMBDA+G-1 : LAMBDA] back into [0 : LAMBDA-1]
  logic [LAMBDA-1:0] reduced;
  always_comb begin
    reduced = with_pp[LAMBDA-1:0];
    for (int bp = 0; bp < G; bp++) begin
      if (with_pp[LAMBDA + bp])
        reduced = reduced ^ (LAMBDA'(GF_POLY) << bp);
    end
  end

  always_ff @(posedge clk_i or posedge rst_i) begin
    if (rst_i) begin
      a_reg   <= '0;
      b_reg   <= '0;
      accum   <= '0;
      cnt     <= '0;
      running <= 1'b0;
      out_reg <= '0;
      v_out   <= 1'b0;
    end else begin
      v_out <= 1'b0;
      if (in_valid_i) begin
        a_reg   <= a_i;
        b_reg   <= b_i;
        accum   <= '0;
        cnt     <= '0;
        running <= 1'b1;
      end else if (running) begin
        accum <= reduced;
        b_reg <= b_reg << G;
        if (cnt == CNT_W'(N_ITER - 1)) begin
          running <= 1'b0;
          out_reg <= reduced;
          v_out   <= 1'b1;
        end else begin
          cnt <= cnt + 1;
        end
      end
    end
  end

  assign out_o       = out_reg;
  assign out_valid_o = v_out;

  // synthesis translate_off
  initial assert (LAMBDA % G == 0)
      else $fatal(1, "gf_mul_serial: LAMBDA=%0d must be a multiple of G=%0d", LAMBDA, G);
  // synthesis translate_on

endmodule
