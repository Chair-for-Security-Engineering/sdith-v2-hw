// SPDX-FileCopyrightText: 2025 Sanjay Deshpande
// SPDX-License-Identifier: MIT

// ============================================================================
// Project:   Dual port memory module
// Author:    Sanjay Deshpande
//
// Description: This module implements a dual-port memory with parameterizable 
// width and depth. It supports simultaneous read and write operations on two 
// independent ports. The memory can be initialized from a file or set to zero 
// based on the parameters provided.
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


module mem_dual
#(
  parameter WIDTH = 8,
  parameter DEPTH = 64,
  parameter FILE = "",
  parameter INIT = 0
)
(
  input  wire                 clock,
  input  wire [WIDTH-1:0]     data_0,
  input  wire [WIDTH-1:0]     data_1,
  input  wire [$clog2(DEPTH)-1:0] address_0,
  input  wire [$clog2(DEPTH)-1:0] address_1,
  input  wire                 wren_0,
  input  wire                 wren_1,
  output reg  [WIDTH-1:0]     q_0,
  output reg  [WIDTH-1:0]     q_1
);

  reg [WIDTH-1:0] mem [0:DEPTH-1] /* synthesis ramstyle = "M20K" */;

  integer file;
  integer scan;
  integer i;

  initial
    begin
      // read file contents if FILE is given
      if (FILE != "")
        $readmemb(FILE, mem);

      // set all data to 0 if INIT is true
      if (INIT)
        for (i = 0; i < DEPTH; i = i + 1)
          mem[i] = {WIDTH{1'b0}};
   end

  always @ (posedge clock)
  begin
    if (wren_0)
      begin
        mem[address_0] <= data_0;
        q_0 <= data_0;
      end
    else
      q_0 <= mem[address_0];
  end

  always @ (posedge clock)
  begin
    if (wren_1)
      begin
        mem[address_1] <= data_1;
        q_1 <= data_1;
      end
    else
      q_1 <= mem[address_1];
  end

endmodule

