// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Niklas Höher

`timescale 1ns / 1ps

module rijndael_round #(
    parameter int NB = 4,
    localparam int STATESIZE = 32 * NB
) (
    input  logic                 is_last_i,
    input  logic [STATESIZE-1:0] state_i,
    input  logic [STATESIZE-1:0] roundkey_i,
    output logic [STATESIZE-1:0] state_o
);

    logic [STATESIZE-1:0] in_subbytes, out_subbytes;
    logic [STATESIZE-1:0] in_shiftrows, out_shiftrows;
    logic [STATESIZE-1:0] in_mixcolumns, out_mixcolumns;
    logic [STATESIZE-1:0] in_addroundkey, out_addroundkey;

    // Connect individual round functions
    assign in_subbytes    = state_i;
    assign in_shiftrows   = out_subbytes;
    assign in_mixcolumns  = out_shiftrows;
    assign in_addroundkey = is_last_i ? out_shiftrows : out_mixcolumns;
    assign state_o        = out_addroundkey;

    rijndael_subbytes #(.NB (NB)) subbytes (
        .state_i  ( in_subbytes),
        .state_o  (out_subbytes)
    );

    rijndael_shiftrows #(.NB (NB)) shiftrows (
        .state_i  ( in_shiftrows),
        .state_o  (out_shiftrows)
    );

    rijndael_mixcolumns #(.NB (NB)) mixcolumns (
        .state_i  ( in_mixcolumns),
        .state_o  (out_mixcolumns)
    );

    rijndael_addroundkey #(.NB (NB)) addroundkey (
        .state_i     ( in_addroundkey),
        .state_o     (out_addroundkey),
        .roundkey_i  (roundkey_i)
    );

endmodule
