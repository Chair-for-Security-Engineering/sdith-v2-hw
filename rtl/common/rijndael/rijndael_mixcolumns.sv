// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Niklas Höher

`timescale 1ns / 1ps

module rijndael_mixcolumns #(
    parameter int NB = 4,
    localparam int STATESIZE = 32 * NB
) (
    input  logic [STATESIZE-1:0] state_i,
    output logic [STATESIZE-1:0] state_o
);

    // Internal 2D byte matrices
    logic [7:0]  in_state_matrix [4][NB];
    logic [7:0] out_state_matrix [4][NB];

    // Flattened state <-> State matrix mapping
    generate
        for (genvar i = 0; i < NB; i++) begin : gen_cols
            for (genvar j = 0; j < 4; j++) begin : gen_rows
                localparam int HI = (STATESIZE - 1) - (32 * i + 8 * j);
                assign in_state_matrix[j][i] = state_i[HI -: 8];
                assign state_o[HI -: 8]      = out_state_matrix[j][i];
            end
        end
    endgenerate

    // Functions mul1, mul2, mul3 for multiplication in Galois field
    // => Declared as automatic because Synopsys DC does not like static
    function automatic [7:0] mul1(input logic [7:0] x);
        return x;
    endfunction

    function automatic [7:0] mul2(input logic [7:0] x);
        return {x[6:0], 1'b0} ^ (x[7] * 8'h1b);
    endfunction

    function automatic [7:0] mul3(input logic [7:0] x);
        return mul1(x) ^ mul2(x);
    endfunction

    // Compute the output matrix given the input matrix
    generate
        for (genvar i = 0; i < NB; i++) begin : gen_mixcolumns
            assign out_state_matrix[0][i] =
                mul2(in_state_matrix[0][i]) ^ mul3(in_state_matrix[1][i]) ^
                mul1(in_state_matrix[2][i]) ^ mul1(in_state_matrix[3][i]);
            assign out_state_matrix[1][i] =
                mul1(in_state_matrix[0][i]) ^ mul2(in_state_matrix[1][i]) ^
                mul3(in_state_matrix[2][i]) ^ mul1(in_state_matrix[3][i]);
            assign out_state_matrix[2][i] =
                mul1(in_state_matrix[0][i]) ^ mul1(in_state_matrix[1][i]) ^
                mul2(in_state_matrix[2][i]) ^ mul3(in_state_matrix[3][i]);
            assign out_state_matrix[3][i] =
                mul3(in_state_matrix[0][i]) ^ mul1(in_state_matrix[1][i]) ^
                mul1(in_state_matrix[2][i]) ^ mul2(in_state_matrix[3][i]);
        end
    endgenerate
endmodule
