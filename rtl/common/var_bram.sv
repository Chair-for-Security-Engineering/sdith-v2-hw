// SPDX-FileCopyrightText: 2026 Stef Halmans, Niklas Höher
// SPDX-License-Identifier: LicenseRef-RUB-SecEng

/*
 * var_bram, dual-port scratchpad memory wrapper. Drop-in replacement for
 * mem_dual, splitting 64-bit data into 32-bit halves to map onto RAMB36E1s.
 * Case selected by DATA_WIDTH/TOTAL_DEPTH.
 * Cases 3/5: top range maps both logical ports to the same word, users there
 * (alpha_base, P0, haux, shadow r_base) only use one port.
 * BRAM_DEPTH_32 must match the physical RAMB36E1 depth at TDP width 36
 */
module var_bram #(
    parameter int DATA_WIDTH    = 64,
    parameter int TOTAL_DEPTH   = 1024,
    parameter int BRAM_DEPTH_32 = 1024
) (
    input  wire                              clock,
    input  wire [DATA_WIDTH-1:0]             data_0,
    input  wire [DATA_WIDTH-1:0]             data_1,
    input  wire [$clog2(TOTAL_DEPTH)-1:0]    address_0,
    input  wire [$clog2(TOTAL_DEPTH)-1:0]    address_1,
    input  wire                              wren_0,
    input  wire                              wren_1,
    output wire [DATA_WIDTH-1:0]             q_0,
    output wire [DATA_WIDTH-1:0]             q_1
);

  localparam ADDR_W = $clog2(TOTAL_DEPTH);

  generate
    // ================================================================
    // Case 1: 32-bit data - single mem_dual, 1 BRAM
    // ================================================================
    if (DATA_WIDTH == 32) begin : gen_single_dual

      mem_dual #(.WIDTH(32), .DEPTH(BRAM_DEPTH_32)) bram (
          .clock    (clock),
          .data_0   (data_0),
          .address_0(address_0[$clog2(BRAM_DEPTH_32)-1:0]),
          .wren_0   (wren_0),
          .q_0      (q_0),
          .data_1   (data_1),
          .address_1(address_1[$clog2(BRAM_DEPTH_32)-1:0]),
          .wren_1   (wren_1),
          .q_1      (q_1)
      );

    // ================================================================
    // Case 2: 64-bit data, fits in one dual pair - 2 BRAMs
    // ================================================================
    end else if (DATA_WIDTH == 64 && TOTAL_DEPTH <= BRAM_DEPTH_32) begin : gen_dual_pair

      localparam DUAL_ADDR_W = $clog2(BRAM_DEPTH_32);

      wire [31:0] lo_q0, lo_q1, hi_q0, hi_q1;

      mem_dual #(.WIDTH(32), .DEPTH(BRAM_DEPTH_32)) bram_lo (
          .clock    (clock),
          .data_0   (data_0[31:0]),
          .address_0(address_0[DUAL_ADDR_W-1:0]),
          .wren_0   (wren_0),
          .q_0      (lo_q0),
          .data_1   (data_1[31:0]),
          .address_1(address_1[DUAL_ADDR_W-1:0]),
          .wren_1   (wren_1),
          .q_1      (lo_q1)
      );

      mem_dual #(.WIDTH(32), .DEPTH(BRAM_DEPTH_32)) bram_hi (
          .clock    (clock),
          .data_0   (data_0[63:32]),
          .address_0(address_0[DUAL_ADDR_W-1:0]),
          .wren_0   (wren_0),
          .q_0      (hi_q0),
          .data_1   (data_1[63:32]),
          .address_1(address_1[DUAL_ADDR_W-1:0]),
          .wren_1   (wren_1),
          .q_1      (hi_q1)
      );

      assign q_0 = {hi_q0, lo_q0};
      assign q_1 = {hi_q1, lo_q1};

    // ================================================================
    // Case 3: 64-bit data, 1 dual pair + 1 single - 3 BRAMs
    // lower range: dual pair; top range: single BRAM, lo/hi TDP split
    // ================================================================
    end else if (DATA_WIDTH == 64 && TOTAL_DEPTH > BRAM_DEPTH_32
                 && TOTAL_DEPTH <= BRAM_DEPTH_32 + BRAM_DEPTH_32 / 2) begin : gen_dual_pair_plus_single

      localparam DUAL_ADDR_W = $clog2(BRAM_DEPTH_32);

      // --- Address decode ---
      wire in_upper_0 = (address_0 >= ADDR_W'(BRAM_DEPTH_32));
      wire in_upper_1 = (address_1 >= ADDR_W'(BRAM_DEPTH_32));

      // --- Lower dual pair (addresses 0 .. BRAM_DEPTH_32-1): full dual-port ---
      wire [DUAL_ADDR_W-1:0] lower_addr_0 = address_0[DUAL_ADDR_W-1:0];
      wire [DUAL_ADDR_W-1:0] lower_addr_1 = address_1[DUAL_ADDR_W-1:0];
      wire lower_wren_0 = wren_0 & ~in_upper_0;
      wire lower_wren_1 = wren_1 & ~in_upper_1;

      wire [31:0] lower_lo_q0, lower_lo_q1, lower_hi_q0, lower_hi_q1;

      mem_dual #(.WIDTH(32), .DEPTH(BRAM_DEPTH_32)) bram_lower_lo (
          .clock    (clock),
          .data_0   (data_0[31:0]),
          .address_0(lower_addr_0),
          .wren_0   (lower_wren_0),
          .q_0      (lower_lo_q0),
          .data_1   (data_1[31:0]),
          .address_1(lower_addr_1),
          .wren_1   (lower_wren_1),
          .q_1      (lower_lo_q1)
      );

      mem_dual #(.WIDTH(32), .DEPTH(BRAM_DEPTH_32)) bram_lower_hi (
          .clock    (clock),
          .data_0   (data_0[63:32]),
          .address_0(lower_addr_0),
          .wren_0   (lower_wren_0),
          .q_0      (lower_hi_q0),
          .data_1   (data_1[63:32]),
          .address_1(lower_addr_1),
          .wren_1   (lower_wren_1),
          .q_1      (lower_hi_q1)
      );

      // --- Upper single BRAM (addresses BRAM_DEPTH_32 .. TOTAL_DEPTH-1) ---
      // Uses both TDP ports for lo/hi split of a single 64-bit word.
      // Port 0 = lo 32 bits (even address), Port 1 = hi 32 bits (odd address).
      wire [DUAL_ADDR_W-1:0] upper_offset_0 = DUAL_ADDR_W'(address_0 - ADDR_W'(BRAM_DEPTH_32));
      wire [DUAL_ADDR_W-1:0] upper_offset_1 = DUAL_ADDR_W'(address_1 - ADDR_W'(BRAM_DEPTH_32));

      wire upper_wren_0 = wren_0 & in_upper_0;
      wire upper_wren_1 = wren_1 & in_upper_1;

      // Mux: prefer port 0 for upper access; port 1 only if port 0 is in lower range
      wire [DUAL_ADDR_W-1:0] upper_addr = in_upper_0 ? upper_offset_0 : upper_offset_1;
      wire [31:0] upper_wr_lo = in_upper_0 ? data_0[31:0]  : data_1[31:0];
      wire [31:0] upper_wr_hi = in_upper_0 ? data_0[63:32] : data_1[63:32];
      wire upper_wren = in_upper_0 ? upper_wren_0 : upper_wren_1;

      wire [31:0] upper_lo_q, upper_hi_q;

      mem_dual #(.WIDTH(32), .DEPTH(BRAM_DEPTH_32)) bram_upper (
          .clock    (clock),
          // Port 0 = lo 32 bits
          .data_0   (upper_wr_lo),
          .address_0({upper_addr, 1'b0}),
          .wren_0   (upper_wren),
          .q_0      (upper_lo_q),
          // Port 1 = hi 32 bits
          .data_1   (upper_wr_hi),
          .address_1({upper_addr, 1'b1}),
          .wren_1   (upper_wren),
          .q_1      (upper_hi_q)
      );

      // --- Output mux (registered to match BRAM read latency) ---
      reg was_upper_0, was_upper_1;
      always @(posedge clock) begin
        was_upper_0 <= in_upper_0;
        was_upper_1 <= in_upper_1;
      end

      assign q_0 = was_upper_0 ? {upper_hi_q, upper_lo_q} : {lower_hi_q0, lower_lo_q0};
      assign q_1 = was_upper_1 ? {upper_hi_q, upper_lo_q} : {lower_hi_q1, lower_lo_q1};

    // ================================================================
    // Case 4: 64-bit data, two dual pairs - 4 BRAMs
    // ================================================================
    end else if (DATA_WIDTH == 64 && TOTAL_DEPTH <= 2 * BRAM_DEPTH_32) begin : gen_two_dual_pairs

      localparam DUAL_ADDR_W = $clog2(BRAM_DEPTH_32);

      // --- Address decode ---
      wire in_upper_0 = (address_0 >= ADDR_W'(BRAM_DEPTH_32));
      wire in_upper_1 = (address_1 >= ADDR_W'(BRAM_DEPTH_32));

      // --- Lower dual pair (addresses 0 .. BRAM_DEPTH_32-1) ---
      wire [DUAL_ADDR_W-1:0] lower_addr_0 = address_0[DUAL_ADDR_W-1:0];
      wire [DUAL_ADDR_W-1:0] lower_addr_1 = address_1[DUAL_ADDR_W-1:0];
      wire lower_wren_0 = wren_0 & ~in_upper_0;
      wire lower_wren_1 = wren_1 & ~in_upper_1;

      wire [31:0] lower_lo_q0, lower_lo_q1, lower_hi_q0, lower_hi_q1;

      mem_dual #(.WIDTH(32), .DEPTH(BRAM_DEPTH_32)) bram_lower_lo (
          .clock    (clock),
          .data_0   (data_0[31:0]),
          .address_0(lower_addr_0),
          .wren_0   (lower_wren_0),
          .q_0      (lower_lo_q0),
          .data_1   (data_1[31:0]),
          .address_1(lower_addr_1),
          .wren_1   (lower_wren_1),
          .q_1      (lower_lo_q1)
      );

      mem_dual #(.WIDTH(32), .DEPTH(BRAM_DEPTH_32)) bram_lower_hi (
          .clock    (clock),
          .data_0   (data_0[63:32]),
          .address_0(lower_addr_0),
          .wren_0   (lower_wren_0),
          .q_0      (lower_hi_q0),
          .data_1   (data_1[63:32]),
          .address_1(lower_addr_1),
          .wren_1   (lower_wren_1),
          .q_1      (lower_hi_q1)
      );

      // --- Upper dual pair (addresses BRAM_DEPTH_32 .. 2*BRAM_DEPTH_32-1) ---
      wire [DUAL_ADDR_W-1:0] upper_addr_0 = DUAL_ADDR_W'(address_0 - ADDR_W'(BRAM_DEPTH_32));
      wire [DUAL_ADDR_W-1:0] upper_addr_1 = DUAL_ADDR_W'(address_1 - ADDR_W'(BRAM_DEPTH_32));
      wire upper_wren_0 = wren_0 & in_upper_0;
      wire upper_wren_1 = wren_1 & in_upper_1;

      wire [31:0] upper_lo_q0, upper_lo_q1, upper_hi_q0, upper_hi_q1;

      mem_dual #(.WIDTH(32), .DEPTH(BRAM_DEPTH_32)) bram_upper_lo (
          .clock    (clock),
          .data_0   (data_0[31:0]),
          .address_0(upper_addr_0),
          .wren_0   (upper_wren_0),
          .q_0      (upper_lo_q0),
          .data_1   (data_1[31:0]),
          .address_1(upper_addr_1),
          .wren_1   (upper_wren_1),
          .q_1      (upper_lo_q1)
      );

      mem_dual #(.WIDTH(32), .DEPTH(BRAM_DEPTH_32)) bram_upper_hi (
          .clock    (clock),
          .data_0   (data_0[63:32]),
          .address_0(upper_addr_0),
          .wren_0   (upper_wren_0),
          .q_0      (upper_hi_q0),
          .data_1   (data_1[63:32]),
          .address_1(upper_addr_1),
          .wren_1   (upper_wren_1),
          .q_1      (upper_hi_q1)
      );

      // --- Output mux (registered to match BRAM read latency) ---
      reg was_upper_0, was_upper_1;
      always @(posedge clock) begin
        was_upper_0 <= in_upper_0;
        was_upper_1 <= in_upper_1;
      end

      assign q_0 = was_upper_0 ? {upper_hi_q0, upper_lo_q0} : {lower_hi_q0, lower_lo_q0};
      assign q_1 = was_upper_1 ? {upper_hi_q1, upper_lo_q1} : {lower_hi_q1, lower_lo_q1};

    // ================================================================
    // Case 5: 64-bit data, two dual pairs + one single - 5 BRAMs
    //   Lower range: two dual pairs, full dual-port 64-bit
    //   Top range: single BRAM, lo/hi TDP split
    // ================================================================
    end else begin : gen_two_dual_pairs_plus_single

      localparam DUAL_ADDR_W = $clog2(BRAM_DEPTH_32);
      localparam DUAL_BOUNDARY = 2 * BRAM_DEPTH_32;

      // --- Three-way address decode ---
      wire in_mid_0  = (address_0 >= ADDR_W'(BRAM_DEPTH_32)) & (address_0 < ADDR_W'(DUAL_BOUNDARY));
      wire in_mid_1  = (address_1 >= ADDR_W'(BRAM_DEPTH_32)) & (address_1 < ADDR_W'(DUAL_BOUNDARY));
      wire in_top_0  = (address_0 >= ADDR_W'(DUAL_BOUNDARY));
      wire in_top_1  = (address_1 >= ADDR_W'(DUAL_BOUNDARY));
      wire in_low_0  = ~in_mid_0 & ~in_top_0;
      wire in_low_1  = ~in_mid_1 & ~in_top_1;

      // --- Lower dual pair (addresses 0 .. BRAM_DEPTH_32-1) ---
      wire [DUAL_ADDR_W-1:0] low_addr_0 = address_0[DUAL_ADDR_W-1:0];
      wire [DUAL_ADDR_W-1:0] low_addr_1 = address_1[DUAL_ADDR_W-1:0];

      wire [31:0] low_lo_q0, low_lo_q1, low_hi_q0, low_hi_q1;
      mem_dual #(.WIDTH(32), .DEPTH(BRAM_DEPTH_32)) bram_low_lo (
          .clock(clock),
          .data_0(data_0[31:0]),  .address_0(low_addr_0), .wren_0(wren_0 & in_low_0), .q_0(low_lo_q0),
          .data_1(data_1[31:0]),  .address_1(low_addr_1), .wren_1(wren_1 & in_low_1), .q_1(low_lo_q1)
      );
      mem_dual #(.WIDTH(32), .DEPTH(BRAM_DEPTH_32)) bram_low_hi (
          .clock(clock),
          .data_0(data_0[63:32]), .address_0(low_addr_0), .wren_0(wren_0 & in_low_0), .q_0(low_hi_q0),
          .data_1(data_1[63:32]), .address_1(low_addr_1), .wren_1(wren_1 & in_low_1), .q_1(low_hi_q1)
      );

      // --- Mid dual pair (addresses BRAM_DEPTH_32 .. 2*BRAM_DEPTH_32-1) ---
      wire [DUAL_ADDR_W-1:0] mid_addr_0 = DUAL_ADDR_W'(address_0 - ADDR_W'(BRAM_DEPTH_32));
      wire [DUAL_ADDR_W-1:0] mid_addr_1 = DUAL_ADDR_W'(address_1 - ADDR_W'(BRAM_DEPTH_32));

      wire [31:0] mid_lo_q0, mid_lo_q1, mid_hi_q0, mid_hi_q1;
      mem_dual #(.WIDTH(32), .DEPTH(BRAM_DEPTH_32)) bram_mid_lo (
          .clock(clock),
          .data_0(data_0[31:0]),  .address_0(mid_addr_0), .wren_0(wren_0 & in_mid_0), .q_0(mid_lo_q0),
          .data_1(data_1[31:0]),  .address_1(mid_addr_1), .wren_1(wren_1 & in_mid_1), .q_1(mid_lo_q1)
      );
      mem_dual #(.WIDTH(32), .DEPTH(BRAM_DEPTH_32)) bram_mid_hi (
          .clock(clock),
          .data_0(data_0[63:32]), .address_0(mid_addr_0), .wren_0(wren_0 & in_mid_0), .q_0(mid_hi_q0),
          .data_1(data_1[63:32]), .address_1(mid_addr_1), .wren_1(wren_1 & in_mid_1), .q_1(mid_hi_q1)
      );

      // --- Top single BRAM (addresses 2*BRAM_DEPTH_32 .. TOTAL_DEPTH-1) ---
      // Both TDP ports serve lo/hi halves of the same 64-bit word.
      wire [DUAL_ADDR_W-1:0] top_offset_0 = DUAL_ADDR_W'(address_0 - ADDR_W'(DUAL_BOUNDARY));
      wire [DUAL_ADDR_W-1:0] top_offset_1 = DUAL_ADDR_W'(address_1 - ADDR_W'(DUAL_BOUNDARY));

      wire [DUAL_ADDR_W-1:0] top_addr = in_top_0 ? top_offset_0 : top_offset_1;
      wire [31:0] top_wr_lo = in_top_0 ? data_0[31:0]  : data_1[31:0];
      wire [31:0] top_wr_hi = in_top_0 ? data_0[63:32] : data_1[63:32];
      wire top_wren = in_top_0 ? wren_0 : (wren_1 & in_top_1);

      wire [31:0] top_lo_q, top_hi_q;
      mem_dual #(.WIDTH(32), .DEPTH(BRAM_DEPTH_32)) bram_top (
          .clock(clock),
          .data_0(top_wr_lo), .address_0({top_addr, 1'b0}), .wren_0(top_wren), .q_0(top_lo_q),
          .data_1(top_wr_hi), .address_1({top_addr, 1'b1}), .wren_1(top_wren), .q_1(top_hi_q)
      );

      // --- Output mux (registered) ---
      reg [1:0] was_region_0, was_region_1;  // 0=low, 1=mid, 2=top
      always @(posedge clock) begin
        was_region_0 <= in_top_0 ? 2'd2 : (in_mid_0 ? 2'd1 : 2'd0);
        was_region_1 <= in_top_1 ? 2'd2 : (in_mid_1 ? 2'd1 : 2'd0);
      end

      assign q_0 = (was_region_0 == 2'd2) ? {top_hi_q, top_lo_q} :
                   (was_region_0 == 2'd1) ? {mid_hi_q0, mid_lo_q0} :
                                            {low_hi_q0, low_lo_q0};
      assign q_1 = (was_region_1 == 2'd2) ? {top_hi_q, top_lo_q} :
                   (was_region_1 == 2'd1) ? {mid_hi_q1, mid_lo_q1} :
                                            {low_hi_q1, low_lo_q1};

    end
  endgenerate

endmodule
