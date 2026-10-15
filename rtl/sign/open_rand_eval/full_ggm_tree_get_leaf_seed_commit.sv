// SPDX-FileCopyrightText: 2026 Stef Halmans, Niklas Höher
// SPDX-License-Identifier: LicenseRef-RUB-SecEng

// Full GGM tree leaf-seed/commit and node-seed retrieval (stateless).
//
// Implements SeedAndCommitGen: any tree node is recomputed on demand from
// the root seed (depth and path taken from the bits of its index), so the
// ORE stage needs no stored tree.
//
// Two modes:
//   seed_search_mode_i = 0 (commit): traverses root -> leaf, produces
//       reveal_seed_o = leaf seed, commit_o = CommitSeed(leaf).
//       node_index_i  = leaf TREE index (1-indexed, num_leaves..2*num_leaves-1).
//   seed_search_mode_i = 1 (seed reveal): traverses root -> node at any depth,
//       reveal_seed_o = node seed.  commit_o is undefined.
//       node_index_i  = node TREE index (1-indexed, 1..2*num_leaves-1).

module full_ggm_tree_get_leaf_seed_commit
    import sdith_params_pkg::*;
#(
    parameter int SEED_WIDTH = LAMBDA,
    parameter int MAX_SEEDS  = TAU * N_CAP
) (
    input  logic clk_i,
    input  logic rst_ni,

    input  logic                                    start_i,
    input  logic                                    seed_search_mode_i,
    output logic                                    done_o,

    input  logic [$clog2(2*MAX_SEEDS)-1:0]          node_index_i,
    input  logic [SEED_WIDTH-1:0]                   seed_i,
    input  logic [SEED_WIDTH-1:0]                   salt_i,

    output logic [2*SEED_WIDTH-1:0]                 commit_o,
    output logic [SEED_WIDTH-1:0]                   reveal_seed_o,

    output logic                                    enc_enable_o,
    output logic [ENC_KEYSIZE-1:0]                  enc_key_o,

    output logic [ENC_BLOCKSIZE-1:0]                enc_plaintext_0_o,
    input  logic                                    enc_ready_0_i,
    input  logic                                    enc_valid_0_i,
    input  logic [ENC_BLOCKSIZE-1:0]                enc_ciphertext_0_i,

    output logic [ENC_BLOCKSIZE-1:0]                enc_plaintext_1_o,
    input  logic                                    enc_ready_1_i,
    input  logic                                    enc_valid_1_i,
    input  logic [ENC_BLOCKSIZE-1:0]                enc_ciphertext_1_i
);

    // -- derived constants --
    localparam int BLOCKSIZE  = ENC_BLOCKSIZE;
    localparam int KEYSIZE    = ENC_KEYSIZE;
    localparam int IDX_BITS   = $clog2(2 * MAX_SEEDS);
    // commit mode does node_index<<1, which can exceed IDX_BITS
    localparam int WORK_BITS  = IDX_BITS + 1;
    localparam int DEPTH_BITS = $clog2(WORK_BITS + 1);
    localparam int SALT_SHIFT = (SECURITY_LEVEL == 3) ? 64 : 0;

    // -- FSM --
    typedef enum logic [1:0] {
        S_IDLE,
        S_FIRE_AES,
        S_WAIT_AES
    } state_e;
    state_e state;

    // -- registers --
    logic [WORK_BITS-1:0]  node_r;
    logic [WORK_BITS-1:0]  current_node_r;
    logic [DEPTH_BITS-1:0] count_r;
    logic [DEPTH_BITS-1:0] num_aes_r;
    logic                  capture_right_r;
    logic                  is_commit_r;
    logic [KEYSIZE-1:0]    key_r;
    logic [SEED_WIDTH-1:0] reveal_seed_r;
    logic                  done_r;
    logic [BLOCKSIZE-1:0]  pt0_r;
    logic [BLOCKSIZE-1:0]  pt1_r;

    // -- priority encoder: floor_log2(x), returns 0 for x==0 --
    function automatic [DEPTH_BITS-1:0] floor_log2 (input [WORK_BITS-1:0] x);
        floor_log2 = '0;
        for (int i = WORK_BITS - 1; i >= 0; i--) begin
            if (x[i]) begin
                floor_log2 = DEPTH_BITS'(i);
                break;
            end
        end
    endfunction

    // -- start-time computations --
    // effective index: commit mode applies <<1
    wire [WORK_BITS-1:0] eff_index = seed_search_mode_i ?
        WORK_BITS'(node_index_i) :
        WORK_BITS'({node_index_i, 1'b0});

    wire [DEPTH_BITS-1:0] node_depth = floor_log2(eff_index);

    // first path bit (below the leading 1): variable-index into eff_index
    wire first_path_bit = (node_depth > 0) ? eff_index[node_depth - DEPTH_BITS'(1)] : 1'b0;

    // shift remaining path bits to MSB
    wire [DEPTH_BITS-1:0] remaining_shift = DEPTH_BITS'(WORK_BITS) - node_depth + DEPTH_BITS'(1);
    wire [WORK_BITS-1:0]  node_init       = eff_index << remaining_shift;

    // -- child seed extraction from AES ciphertext --
    wire [SEED_WIDTH-1:0] left_child = SEED_WIDTH'(enc_ciphertext_0_i);
    wire [SEED_WIDTH-1:0] right_child;
    generate
        if (SECURITY_LEVEL == 3) begin : g_sec3_right
            assign right_child = enc_ciphertext_1_i[BLOCKSIZE-1:64];
        end else begin : g_other_right
            assign right_child = SEED_WIDTH'(enc_ciphertext_1_i);
        end
    endgenerate

    // -- plaintext construction (C convention: XOR then +1) --
    // Pre-registered: computed in S_IDLE (init) and S_WAIT_AES (next iter),
    // used in S_FIRE_AES. Eliminates carry chain from the AES-start path.
    wire [BLOCKSIZE-1:0] salt_shifted =
        BLOCKSIZE'(salt_i) << SALT_SHIFT;

    // Next-iteration plaintext (computed during S_WAIT_AES from next current_node)
    wire [WORK_BITS-1:0] next_current =
        {current_node_r[WORK_BITS-2:0], node_r[WORK_BITS-1]};
    wire [WORK_BITS-1:0] next_xor_even = next_current & ~WORK_BITS'(1);
    wire [BLOCKSIZE-1:0] next_pt0 = salt_shifted ^ BLOCKSIZE'(next_xor_even);
    wire [BLOCKSIZE-1:0] next_pt1 = next_pt0 + BLOCKSIZE'(1);

    // Initial plaintext (computed in S_IDLE from starting current_node)
    wire [WORK_BITS-1:0] init_current = WORK_BITS'({1'b1, first_path_bit});
    wire [WORK_BITS-1:0] init_xor_even = init_current & ~WORK_BITS'(1);
    wire [BLOCKSIZE-1:0] init_pt0 = salt_shifted ^ BLOCKSIZE'(init_xor_even);
    wire [BLOCKSIZE-1:0] init_pt1 = init_pt0 + BLOCKSIZE'(1);

    assign enc_plaintext_0_o = pt0_r;
    assign enc_plaintext_1_o = pt1_r;

    // -- outputs --
    assign commit_o      = {left_child, right_child};
    assign reveal_seed_o = reveal_seed_r;
    assign enc_key_o     = key_r;
    assign done_o        = done_r;

    // -- AES enable (combinational) --
    always_comb begin
        enc_enable_o = 1'b0;
        if (state == S_FIRE_AES && enc_ready_0_i && enc_ready_1_i)
            enc_enable_o = 1'b1;
    end

    // -- main sequential logic --
    always_ff @(posedge clk_i) begin
        if (!rst_ni) begin
            state           <= S_IDLE;
            node_r          <= '0;
            current_node_r  <= '0;
            count_r         <= '0;
            num_aes_r       <= '0;
            capture_right_r <= 1'b0;
            is_commit_r     <= 1'b0;
            key_r           <= '0;
            reveal_seed_r   <= '0;
            done_r          <= 1'b0;
            pt0_r           <= '0;
            pt1_r           <= '0;
        end else begin
            case (state)

            S_IDLE: begin
                done_r <= 1'b0;
                if (start_i) begin
                    key_r         <= KEYSIZE'(seed_i);
                    reveal_seed_r <= seed_i;
                    is_commit_r   <= ~seed_search_mode_i;
                    if (node_depth == '0) begin
                        done_r <= 1'b1;
                    end else begin
                        current_node_r <= WORK_BITS'({1'b1, first_path_bit});
                        node_r         <= node_init;
                        count_r        <= '0;
                        num_aes_r      <= node_depth;
                        pt0_r          <= {<<8{init_pt0}};
                        pt1_r          <= {<<8{init_pt1}};
                        state          <= S_FIRE_AES;
                    end
                end
            end

            S_FIRE_AES: begin
                capture_right_r <= current_node_r[0];
                if (enc_ready_0_i && enc_ready_1_i)
                    state <= S_WAIT_AES;
            end

            S_WAIT_AES: begin
                if (enc_valid_0_i && enc_valid_1_i) begin
                    if (is_commit_r)
                        // commit mode: snapshot key BEFORE overwrite;
                        // on the last iteration this is the leaf seed
                        reveal_seed_r <= key_r[SEED_WIDTH-1:0];
                    else
                        // search mode: reveal = path child AFTER this AES;
                        // on the last iteration this is the target node seed
                        reveal_seed_r <= capture_right_r ?
                                         right_child : left_child;

                    if (capture_right_r)
                        key_r <= KEYSIZE'(right_child);
                    else
                        key_r <= KEYSIZE'(left_child);

                    current_node_r <= {current_node_r[WORK_BITS-2:0],
                                       node_r[WORK_BITS-1]};
                    node_r         <= {node_r[WORK_BITS-2:0], 1'b0};
                    count_r        <= count_r + DEPTH_BITS'(1);

                    if (count_r + DEPTH_BITS'(1) >= num_aes_r) begin
                        done_r <= 1'b1;
                        state  <= S_IDLE;
                    end else begin
                        pt0_r <= {<<8{next_pt0}};
                        pt1_r <= {<<8{next_pt1}};
                        state <= S_FIRE_AES;
                    end
                end
            end

            default: state <= S_IDLE;
            endcase
        end
    end

endmodule
