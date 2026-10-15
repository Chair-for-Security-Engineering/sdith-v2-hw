// SPDX-FileCopyrightText: 2026 Stef Halmans, Niklas Höher
// SPDX-License-Identifier: LicenseRef-RUB-SecEng

// estimate_topen
//
// Opening-path computation (GetOpeningPath): queue-based bottom-up merge
// over the sorted hidden-index list.
// count_only mode just counts the path size; reveal mode also emits seeds.
// The list is consumed destructively -- caller restores it between runs.

module estimate_topen
#(
    parameter int TAU = 16,
    parameter int KAPPA = 8,
    parameter int LEAVE_INDEX_WIDTH = $clog2(2 * TAU * (1 << KAPPA)),
    parameter int SEED_WIDTH = 128
)
 (
    input  wire                          clk_i,
    input  wire                          rst_i,
    input  wire                          start_i,
    input  wire                          count_only_mode_i,
    output reg                           done_o,

    input  wire [LEAVE_INDEX_WIDTH-1:0]  hidden_leaf_index_0_i,
    output wire [$clog2(TAU):0]          hidden_leaf_index_addr_0_o,
    output reg                           hidden_leaf_index_sel_o,

    output wire [LEAVE_INDEX_WIDTH-1:0]  bend_nxt_index_o,
    output wire [$clog2(TAU):0]          bend_nxt_index_addr_o,
    output reg                           bend_nxt_index_en,

    input  wire                          seed_reveal_mode_i,
    output reg  [LEAVE_INDEX_WIDTH-1:0]  leaf_index_reveal_o,
    output reg                           start_leaf_index_reveal_o,
    input  wire                          done_leaf_index_reveal_i,
    input  wire [SEED_WIDTH-1:0]         reveal_seed_i,

    output wire [SEED_WIDTH-1:0]         reveal_seed_o,
    output wire                          reveal_seed_valid_o,

    output wire [LEAVE_INDEX_WIDTH-1:0]  sibling_path_size_o
);

localparam int ADDR_W = $clog2(TAU);

typedef enum logic [3:0] {
    S_WAIT_START,
    S_LOAD_FIRST_IDX,
    S_LOAD_SECOND_IDX,
    S_CHECK_LEAVES_INDEX,
    S_REVEAL_SEED_START,
    S_REVEAL_SEED_WAIT,
    S_DONE,
    S_DONE_REVEAL_START,
    S_DONE_REVEAL_WAIT
} state_t;

state_t state;

reg [ADDR_W:0] bstart_addr;         // queue head pointer (circular)
reg [ADDR_W:0] bend_addr;           // queue tail pointer (circular)
reg [$clog2(TAU+1):0] count;        // live queue entries

reg [LEAVE_INDEX_WIDTH-1:0] first_idx;
wire [LEAVE_INDEX_WIDTH-1:0] second_idx;
reg [LEAVE_INDEX_WIDTH-1:0] next_idx;
reg [LEAVE_INDEX_WIDTH-1:0] bstart_final;

reg [LEAVE_INDEX_WIDTH-1:0] sibling_path_size;

assign bend_nxt_index_addr_o = bend_addr;
assign second_idx = hidden_leaf_index_0_i;
assign hidden_leaf_index_addr_0_o = bstart_addr;
assign bend_nxt_index_o = next_idx;
assign sibling_path_size_o = sibling_path_size;

assign reveal_seed_o = reveal_seed_i;
assign reveal_seed_valid_o = (state == S_REVEAL_SEED_WAIT && done_leaf_index_reveal_i)
                           | (state == S_DONE_REVEAL_WAIT && done_leaf_index_reveal_i);

always @(posedge clk_i) begin
    if (rst_i) begin
        state <= S_WAIT_START;
        done_o <= 0;
        sibling_path_size <= 0;
        bstart_addr <= 0;
        bend_addr <= 0;
        count <= 0;
        bstart_final <= 0;
        leaf_index_reveal_o <= 0;
        first_idx <= 0;
        next_idx <= 0;
    end
    else begin
        case (state)

        S_WAIT_START: begin
            if (start_i) begin
                state <= S_LOAD_FIRST_IDX;
                sibling_path_size <= 0;
                bstart_final <= 0;
                count <= TAU;
            end
            bstart_addr <= 0;
            bend_addr <= 0;
            done_o <= 0;
            leaf_index_reveal_o <= 0;
        end

        S_LOAD_FIRST_IDX: begin
            state <= S_LOAD_SECOND_IDX;
            if (bstart_addr == (ADDR_W+1)'(TAU - 1))
                bstart_addr <= 0;
            else
                bstart_addr <= bstart_addr + 1;
        end

        S_LOAD_SECOND_IDX: begin
            first_idx <= hidden_leaf_index_0_i;
            next_idx <= hidden_leaf_index_0_i >> 1;
            state <= S_CHECK_LEAVES_INDEX;
        end

        S_CHECK_LEAVES_INDEX: begin
            bstart_final <= next_idx;

            if (bend_addr == (ADDR_W+1)'(TAU - 1))
                bend_addr <= 0;
            else
                bend_addr <= bend_addr + 1;

            // siblings: consume both, enqueue parent
            if ((first_idx ^ second_idx) == 1) begin
                if (bstart_addr == (ADDR_W+1)'(TAU - 1))
                    bstart_addr <= 0;
                else
                    bstart_addr <= bstart_addr + 1;
                count <= count - 1;

                if (count - 1 < 2) begin
                    state <= S_DONE;
                end
                else begin
                    state <= S_LOAD_FIRST_IDX;
                end
            end
            // sibling not hidden -> part of opening path
            else begin
                sibling_path_size <= sibling_path_size + 1;

                if (seed_reveal_mode_i) begin
                    leaf_index_reveal_o <= first_idx ^ 1;
                    state <= S_REVEAL_SEED_START;
                end
                else begin
                    state <= S_LOAD_FIRST_IDX;
                end
            end
        end

        S_REVEAL_SEED_START: begin
            state <= S_REVEAL_SEED_WAIT;
        end

        S_REVEAL_SEED_WAIT: begin
            if (done_leaf_index_reveal_i) begin
                state <= S_LOAD_FIRST_IDX;
            end
        end

        // walk remaining node up to root
        S_DONE: begin
            if (bstart_final != 1) begin
                sibling_path_size <= sibling_path_size + 1;
                if (seed_reveal_mode_i) begin
                    leaf_index_reveal_o <= bstart_final ^ 1;
                    state <= S_DONE_REVEAL_START;
                end
                else begin
                    bstart_final <= bstart_final >> 1;
                end
            end
            else begin
                state <= S_WAIT_START;
                done_o <= 1;
            end
        end

        S_DONE_REVEAL_START: begin
            state <= S_DONE_REVEAL_WAIT;
        end

        S_DONE_REVEAL_WAIT: begin
            if (done_leaf_index_reveal_i) begin
                bstart_final <= bstart_final >> 1;
                state <= S_DONE;
            end
        end

        default: begin
            state <= S_WAIT_START;
        end

        endcase
    end
end

always_comb begin
    case (state)
        S_WAIT_START: begin
            hidden_leaf_index_sel_o = start_i;
            bend_nxt_index_en = 0;
            start_leaf_index_reveal_o = 0;
        end
        S_LOAD_FIRST_IDX, S_LOAD_SECOND_IDX: begin
            hidden_leaf_index_sel_o = 1;
            bend_nxt_index_en = 0;
            start_leaf_index_reveal_o = 0;
        end
        S_CHECK_LEAVES_INDEX: begin
            hidden_leaf_index_sel_o = 1;
            bend_nxt_index_en = ~count_only_mode_i;
            start_leaf_index_reveal_o = 0;
        end
        S_REVEAL_SEED_START, S_DONE_REVEAL_START: begin
            hidden_leaf_index_sel_o = 0;
            bend_nxt_index_en = 0;
            start_leaf_index_reveal_o = 1;
        end
        default: begin
            hidden_leaf_index_sel_o = 0;
            bend_nxt_index_en = 0;
            start_leaf_index_reveal_o = 0;
        end
    endcase
end

endmodule
