// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Niklas Höher

`timescale 1ns / 1ps

module rijndael_subbytes #(
    parameter int NB = 4,
    localparam int STATESIZE = 32 * NB
) (
        input  logic [STATESIZE-1:0] state_i,
        output logic [STATESIZE-1:0] state_o
    );

    localparam int NUMBYTES = 4 * NB;

    generate
        for (genvar i = 0; i < NUMBYTES; i++) begin : gen_sbox
            rijndael_sbox sbox (
                .x_i (state_i[8*i+7 -: 8]),
                .y_o (state_o[8*i+7 -: 8])
            );
        end
    endgenerate
endmodule
