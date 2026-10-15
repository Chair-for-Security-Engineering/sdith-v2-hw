// SPDX-FileCopyrightText: 2025 Sanjay Deshpande
// SPDX-License-Identifier: MIT

// ============================================================================
// Project:   Keccak Top Module
// Author:    Sanjay Deshpande
//
// Description: Top module for the Keccak sponge function in Verilog. This module 
// is a wrapper around the keccak_round module and handles the input/output data 
// formatting, round constant generation, and control logic for the Keccak algorithm.
//
//
//
// The MIT License (MIT)
//
// Copyright (c) 2025 Sanjay Deshpande
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
// ============================================================================

module keccak_top 
#(
    parameter N = 64,
    parameter IN_BUF_SIZE = 200,
    parameter OUT_BUF_SIZE = 200
)
(
    input                             Clock,       //System clock
    input                             Reset,       //Active HIGH synchronous reset signal
    input                             Start,       //Start signal, valid on Ready
    input   [200*8-1:0]               Din,         //Data input byte stream, 200 bytes length. Valid during Start AND Ready
    input                             Req_more,    //Request more data output, valid on Ready

    output  reg                       Ready,       //keccak's ready signal
    output  [200*8-1:0]               Dout
                );       //Data output byte stream, 200 bytes length


reg  [4:0]       counter_nr_rounds;
wire [N-1:0]    Round_constant_signal;
wire [1599:0]   state_in;
wire [1599:0]   state_out;
reg  [1599:0]    reg_data;
wire [1599:0]   swap_data_in, swap_data_out;
wire [1599:0]  Round_in, Round_out;


//Swapped input endiannes, byte streams to 64 bit data
// assign swap_data_in = Din;
genvar i;
generate
    for (i=0; i < 25; i=i+1)
    begin: swap_input
    //   assign swap_data_in[64*i +:64] = {Din[64*i+0 +:8], Din[64*i+8 +:8],
    //                                     Din[64*i+16+:8], Din[64*i+24+:8],
    //                                     Din[64*i+32+:8], Din[64*i+40+:8],
    //                                     Din[64*i+48+:8], Din[64*i+56+:8]};
      
      assign swap_data_in[64*(i+1) -1:64*i] =   {   
                                                    Din[64*(i)+08-1:64*(i)+00], Din[64*(i)+16-1:64*(i)+08],
                                                    Din[64*(i)+24-1:64*(i)+16], Din[64*(i)+32-1:64*(i)+24],
                                                    Din[64*(i)+40-1:64*(i)+32], Din[64*(i)+48-1:64*(i)+40],
                                                    Din[64*(i)+56-1:64*(i)+48], Din[64*(i)+64-1:64*(i)+56]
                                                };
    end
endgenerate

assign state_in  = reg_data;
// assign Round_in  = bit_to_state(state_in);
assign Round_in  = state_in;

keccak_round 
keccak_round_i
    (
    .Round_in               (Round_in),
    .Round_constant_signal  (Round_constant_signal),
    .Round_out              (Round_out)
    );

keccak_round_constants_gen 
keccak_round_constants_gen_i
    (
    .round_number(counter_nr_rounds),
    .round_constant_signal_out(Round_constant_signal)
    );

// assign state_out = state_to_bit(Round_out);
assign state_out = Round_out;

//Swapped output endiannes, 64 bit data to byte streams
// assign swap_data_out = reg_data;

// wire [31:0] swap_output_32_map [0:49]



genvar j;
generate
    for (j=0; j < 25; j=j+1)
    begin: swap_output
    //   assign swap_data_out[64*j +:64] = {reg_data[64*j+0 +:8], reg_data[64*j+8 +:8],
    //                                      reg_data[64*j+16+:8], reg_data[64*j+24+:8],
    //                                      reg_data[64*j+32+:8], reg_data[64*j+40+:8],
    //                                      reg_data[64*j+48+:8], reg_data[64*j+56+:8]};
      
      assign swap_data_out[64*(j+1)-1:64*j] =   {   
                                                    reg_data[64*(j)+08-1:64*(j)+00], reg_data[64*(j)+16-1:64*(j)+08],
                                                    reg_data[64*(j)+24-1:64*(j)+16], reg_data[64*(j)+32-1:64*(j)+24],
                                                    reg_data[64*(j)+40-1:64*(j)+32], reg_data[64*(j)+48-1:64*(j)+40],
                                                    reg_data[64*(j)+56-1:64*(j)+48], reg_data[64*(j)+64-1:64*(j)+56]
                                                };
    end
endgenerate

assign Dout = swap_data_out;

//Data register
always @ (posedge Clock) begin
    if(Reset) begin
        reg_data        <= 0;
    end else if(Start) begin
        reg_data        <= swap_data_in;
    end else if(~Ready) begin
        reg_data        <= state_out;
    end
end

//Counter and Ready assignments
always @ (posedge Clock) begin
    if(Reset) begin
        counter_nr_rounds       <= 0;
        Ready                   <= 1;
    end else if((Start | Req_more) & Ready) begin
        counter_nr_rounds       <= 0;
        Ready                   <= 0;
    end else if(counter_nr_rounds == 23) begin
        counter_nr_rounds       <= 0;
        Ready                   <= 1;
    end else if(~Ready) begin
        counter_nr_rounds       <= counter_nr_rounds + 1;
    end
end


//// Function: k_state to bit array
//function [1599:0] state_to_bit;
//    input k_state din;
//    integer i,j,k;
//    begin
//        for(i=0; i<5; i=i+1)
//          for (j=0; j<5; j=j+1)
//            for (k=0; k<64; k=k+1)
//              state_to_bit[64*(24-(5*i+j))+k] = din[i][j][k];
//    end
//endfunction

//// Function: bit array to k_state
//function automatic k_state bit_to_state;
//    input [1599:0] din;
//    integer i,j,k;
//    begin
//        for(i=0; i<5; i=i+1)
//          for (j=0; j<5; j=j+1)
//            for (k=0; k<64; k=k+1)
//              bit_to_state[i][j][k] = din[64*(24-(5*i+j))+k];
//    end
//endfunction

endmodule
