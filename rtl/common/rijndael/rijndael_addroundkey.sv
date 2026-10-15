// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Niklas Höher

`timescale 1ns / 1ps

module rijndael_addroundkey #(
    parameter int NB = 4,
    localparam int STATESIZE = 32 * NB
) (
    input  logic [STATESIZE-1:0] state_i,
    input  logic [STATESIZE-1:0] roundkey_i,
    output logic [STATESIZE-1:0] state_o
);

    assign state_o = state_i ^ roundkey_i;
endmodule
