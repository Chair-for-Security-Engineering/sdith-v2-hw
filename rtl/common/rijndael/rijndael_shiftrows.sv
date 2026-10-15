// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Niklas Höher

`timescale 1ns / 1ps

module rijndael_shiftrows #(
    parameter int NB = 4,
    localparam int STATESIZE = 32 * NB
) (
    input  logic [STATESIZE-1:0] state_i,
    output logic [STATESIZE-1:0] state_o
);

    // Internal 2D byte matrices
    logic [7:0] istate_matrix [4][NB];
    logic [7:0] ostate_matrix [4][NB];

    // Flattened state <-> State matrix mapping
    generate
        for (genvar i = 0; i < NB; i++) begin : gen_cols
            for (genvar j = 0; j < 4; j++) begin : gen_rows
                localparam int HI = (STATESIZE-1) - (i*32 + j*8);
                assign istate_matrix[j][i] = state_i[HI -: 8];
                assign state_o[HI -: 8]    = ostate_matrix[j][i];
            end
        end
    endgenerate

    // Determine row-shift pattern
    // NB = 4 or 6  -> shifts = {0,1,2,3}
    // NB = 8       -> shifts = {0,1,3,4}
    // => We use separate localparams instead of an array-type due to missing Icarus support
    localparam int SHIFT0 = 0;
    localparam int SHIFT1 = 1;
    localparam int SHIFT2 = (NB == 8) ? 3 : 2;
    localparam int SHIFT3 = (NB == 8) ? 4 : 3;

    // Perform shift rows operation itself
    generate
        for (genvar i = 0; i < NB; i++) begin : gen_shift_cols
            assign ostate_matrix[0][i] = istate_matrix[0][(i + SHIFT0) % NB];
            assign ostate_matrix[1][i] = istate_matrix[1][(i + SHIFT1) % NB];
            assign ostate_matrix[2][i] = istate_matrix[2][(i + SHIFT2) % NB];
            assign ostate_matrix[3][i] = istate_matrix[3][(i + SHIFT3) % NB];
        end
    endgenerate

endmodule
