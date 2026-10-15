// SPDX-FileCopyrightText: 2026 Stef Halmans, Niklas Höher
// SPDX-License-Identifier: LicenseRef-RUB-SecEng

// insertion_sort
//
// In-place insertion sort for small lists. Chosen over the reference
// implementation's quicksort for hardware simplicity: with at most
// tau <= 32 elements the worst case stays cheap.
//
// Storage is either an internal mem_dual instance or, with EXTERNAL_MEM=1,
// an external memory driven through the mem_* ports (the ORE stage places
// the list in scratchpad). While sorting, the module owns the memory;
// otherwise the wr/rd/index ports pass through for the caller.

module insertion_sort #(
    parameter int INT_WIDTH    = 13,
    parameter int INDEX_WIDTH  = 0,
    parameter int LIST_LEN     = 16,
    parameter int EXTERNAL_MEM = 0,
    parameter     FILE         = ""
) (
    input  wire                                  clk,
    input  wire                                  start,

    input  wire                                  wr_en,
    input  wire [$clog2(LIST_LEN)-1:0]          wr_addr,
    input  wire [INT_WIDTH+INDEX_WIDTH-1:0]     data_in,

    input  wire                                  rd_en,
    input  wire [$clog2(LIST_LEN)-1:0]          rd_addr,
    output wire [INT_WIDTH+INDEX_WIDTH-1:0]     data_out,

    input  wire                                  index_wr_en,
    input  wire [$clog2(LIST_LEN)-1:0]          index_wr_addr,
    input  wire [INT_WIDTH+INDEX_WIDTH-1:0]     index,

    output wire                                  done,

    // External memory interface (active when EXTERNAL_MEM=1)
    output wire [$clog2(LIST_LEN)-1:0]          mem_rd_addr_o,
    input  wire [INT_WIDTH+INDEX_WIDTH-1:0]     mem_rd_data_i,
    output wire [$clog2(LIST_LEN)-1:0]          mem_wr_addr_o,
    output wire [INT_WIDTH+INDEX_WIDTH-1:0]     mem_wr_data_o,
    output wire                                  mem_wr_en_o
);

    localparam int K  = $clog2(LIST_LEN);
    localparam int DW = INT_WIDTH + INDEX_WIDTH;

    typedef enum logic [2:0] {
        S_IDLE,
        S_WAIT_READ,
        S_LATCH_KEY,
        S_WAIT_CMP,
        S_COMPARE,
        S_INSERT,
        S_DONE
    } state_e;

    state_e        state        = S_IDLE;
    logic [K:0]    i_reg        = '0;
    logic signed [K:0] j_reg   = '0;
    logic [DW-1:0] key_reg     = '0;
    logic          done_reg     = 1'b0;
    logic [K-1:0]  rd_addr_sort = '0;
    logic [K-1:0]  wr_addr_sort = '0;
    logic [DW-1:0] wr_data_sort = '0;
    logic          wr_en_sort   = 1'b0;

    wire sorting = (state != S_IDLE);

    wire [K-1:0]  ext_a1 = index_wr_en ? index_wr_addr : wr_addr;
    wire [DW-1:0] ext_d1 = index_wr_en ? index         : data_in;
    wire          ext_w1 = wr_en | index_wr_en;

    wire [K-1:0]  mem_a0 = sorting ? rd_addr_sort : (rd_en ? rd_addr : {K{1'b0}});
    wire [K-1:0]  mem_a1 = sorting ? wr_addr_sort : ext_a1;
    wire [DW-1:0] mem_d1 = sorting ? wr_data_sort : ext_d1;
    wire          mem_w1 = sorting ? wr_en_sort   : ext_w1;

    wire [DW-1:0] q_0;

    generate
        if (EXTERNAL_MEM) begin : gen_ext
            assign mem_rd_addr_o = mem_a0;
            assign mem_wr_addr_o = mem_a1;
            assign mem_wr_data_o = mem_d1;
            assign mem_wr_en_o   = mem_w1;
            assign q_0           = mem_rd_data_i;
        end else begin : gen_int
            mem_dual #(
                .WIDTH(DW),
                .DEPTH(LIST_LEN),
                .FILE (FILE)
            ) mem (
                .clock    (clk),
                .data_0   ({DW{1'b0}}),
                .data_1   (mem_d1),
                .address_0(mem_a0),
                .address_1(mem_a1),
                .wren_0   (1'b0),
                .wren_1   (mem_w1),
                .q_0      (q_0),
                .q_1      ()
            );
            assign mem_rd_addr_o = '0;
            assign mem_wr_addr_o = '0;
            assign mem_wr_data_o = '0;
            assign mem_wr_en_o   = 1'b0;
        end
    endgenerate

    assign data_out = q_0;
    assign done     = done_reg;

    always_ff @(posedge clk) begin
        done_reg   <= 1'b0;
        wr_en_sort <= 1'b0;

        case (state)
        S_IDLE: begin
            if (start) begin
                if (LIST_LEN <= 1) begin
                    state <= S_DONE;
                end else begin
                    i_reg        <= (K+1)'(1);
                    rd_addr_sort <= K'(1);
                    state        <= S_WAIT_READ;
                end
            end
        end

        S_WAIT_READ:
            state <= S_LATCH_KEY;

        S_LATCH_KEY: begin
            key_reg      <= q_0;
            j_reg        <= $signed({1'b0, i_reg[K-1:0]}) - 1;
            rd_addr_sort <= K'(i_reg - 1);
            state        <= S_WAIT_CMP;
        end

        S_WAIT_CMP:
            state <= S_COMPARE;

        S_COMPARE: begin
            if (q_0[DW-1:INDEX_WIDTH] > key_reg[DW-1:INDEX_WIDTH]) begin
                wr_addr_sort <= K'(j_reg + 1);
                wr_data_sort <= q_0;
                wr_en_sort   <= 1'b1;

                if (j_reg > 0) begin
                    j_reg        <= j_reg - 1;
                    rd_addr_sort <= K'(j_reg - 1);
                    state        <= S_WAIT_CMP;
                end else begin
                    j_reg <= j_reg - 1;
                    state <= S_INSERT;
                end
            end else begin
                wr_addr_sort <= K'(j_reg + 1);
                wr_data_sort <= key_reg;
                wr_en_sort   <= 1'b1;

                if (i_reg >= (K+1)'(LIST_LEN - 1)) begin
                    state <= S_DONE;
                end else begin
                    i_reg        <= i_reg + (K+1)'(1);
                    rd_addr_sort <= K'(i_reg + 1);
                    state        <= S_WAIT_READ;
                end
            end
        end

        S_INSERT: begin
            wr_addr_sort <= K'(j_reg + 1);
            wr_data_sort <= key_reg;
            wr_en_sort   <= 1'b1;

            if (i_reg >= (K+1)'(LIST_LEN - 1)) begin
                state <= S_DONE;
            end else begin
                i_reg        <= i_reg + (K+1)'(1);
                rd_addr_sort <= K'(i_reg + 1);
                state        <= S_WAIT_READ;
            end
        end

        S_DONE: begin
            done_reg <= 1'b1;
            state    <= S_IDLE;
        end

        default: state <= S_IDLE;
        endcase
    end

endmodule
