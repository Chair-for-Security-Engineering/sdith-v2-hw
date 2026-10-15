// SPDX-FileCopyrightText: 2026 Stef Halmans, Niklas Höher
// SPDX-License-Identifier: LicenseRef-RUB-SecEng

// blc_open_rand_eval
//
// Open Random Evaluation (final signing stage).
// Grinding loop: SHAKE(h_piop, ctr) -> delta; reject on v_pow != 0,
// delta == 0, or opening path > T_OPEN seeds.
// Then sort hidden leaf indices, regenerate their commits, and reveal the
// sibling-path seeds. estimate_topen runs twice: count pass, then reveal pass.

module blc_open_rand_eval
    import sdith_params_pkg::*;
    import sdith_helpers_pkg::*;
(
    input  logic                            clk_i,
    input  logic                            rst_ni,
    input  logic                            start_i,

    input  logic [LAMBDA-1:0]               salt_i,
    input  logic [LAMBDA-1:0]               root_seed_i,

    output logic                            done_o,

    // Signature memory (read h_piop, write commits/seeds/pow_ctr)
    input  logic [63:0]                     sig_data_i,
    output logic [63:0]                     sig_data_o,
    output logic [SIG_ADDR_WIDTH-1:0]       sig_addr_o,
    output logic                            sig_wr_en_o,

    // Var BRAM dual-port (sort + backup)
    input  logic [VAR_DATA_WIDTH_COMBINED-1:0] var_a_data_i,
    output logic [VAR_DATA_WIDTH_COMBINED-1:0] var_a_data_o,
    output logic [VAR_ADDR_WIDTH_COMBINED-1:0] var_a_addr_o,
    output logic                               var_a_wr_en_o,

    input  logic [VAR_DATA_WIDTH_COMBINED-1:0] var_b_data_i,
    output logic [VAR_DATA_WIDTH_COMBINED-1:0] var_b_data_o,
    output logic [VAR_ADDR_WIDTH_COMBINED-1:0] var_b_addr_o,
    output logic                               var_b_wr_en_o,

    // AES interface (GGM tree)
    output logic                            enc_enable_o,
    output logic [ENC_KEYSIZE-1:0]         enc_key_o,

    output logic [ENC_BLOCKSIZE-1:0]       enc_plaintext_0_o,
    input  logic                            enc_ready_0_i,
    input  logic                            enc_valid_0_i,
    input  logic [ENC_BLOCKSIZE-1:0]       enc_ciphertext_0_i,

    output logic [ENC_BLOCKSIZE-1:0]       enc_plaintext_1_o,
    input  logic                            enc_ready_1_i,
    input  logic                            enc_valid_1_i,
    input  logic [ENC_BLOCKSIZE-1:0]       enc_ciphertext_1_i,

    // SHAKE interface
    output logic                            start_shake_o,
    output logic                            mode_shake_o,
    output logic                            seed_from_output_shake_o,
    output logic [63:0]                    din_shake_o,
    output logic                            din_valid_shake_o,
    output logic                            last_din_shake_o,
    output logic [3:0]                     last_din_byte_shake_o,
    output logic                            dout_ready_shake_o,
    input  logic                            din_ready_shake_i,
    input  logic [63:0]                    dout_shake_i,
    input  logic                            dout_valid_shake_i
);

    // -- derived constants --
    localparam int HPIOP_WORDS   = 2 * LAMBDA / 64;
    localparam int HPIOP_ADDR_W  = $clog2(HPIOP_WORDS);
    localparam int MAX_SEEDS     = TAU * N_CAP;
    localparam int LIDX_W        = $clog2(2 * MAX_SEEDS);
    localparam int START_INDEX   = MAX_SEEDS;
    localparam int SORT_K        = $clog2(TAU);

    localparam int DELTA_BITS        = TAU * KAPPA + W_POW;
    localparam int DELTA_BYTES       = (DELTA_BITS + 7) / 8;
    localparam int SHIFT_WIDTH       = DELTA_BYTES * 8;
    localparam int SHAKE_FULL_WORDS  = DELTA_BYTES / 8;
    localparam int SHAKE_REM_BYTES   = DELTA_BYTES % 8;
    localparam int SHAKE_WORD_COUNT  = SHAKE_FULL_WORDS + (SHAKE_REM_BYTES > 0 ? 1 : 0);
    localparam int SHAKE_CNT_W       = $clog2(SHAKE_WORD_COUNT + 1);

    localparam int CMT_WORDS     = 2 * LAMBDA_DIV_64;
    localparam int CMT_WORD_W    = $clog2(CMT_WORDS + 1);
    localparam int SEED_WORDS    = LAMBDA_DIV_64;
    localparam int SEED_WORD_W   = $clog2(SEED_WORDS + 1);
    localparam int PAD_TOTAL_MAX = T_OPEN * SEED_WORDS;
    localparam int PAD_CNT_W     = $clog2(PAD_TOTAL_MAX + 1);
    localparam int SEED_IDX_W    = $clog2(T_OPEN + 1);

    // -- FSM --
    typedef enum logic [4:0] {
        S_WAIT_START,
        S_OPEN_DELTA,
        S_LOAD_HASH_PIOP,
        S_LOAD_HASH_PIOP_LAST,
        S_LOAD_COUNTER,
        S_WAIT_SHAKE,
        S_CHECK_VGRIND,
        S_HIDDEN_LEAVES_INDEXES,
        S_SORT_INDEXES,
        S_BACKUP_PREREAD,
        S_BACKUP_SORTED,
        S_BACKUP_DRAIN,
        S_START_ESTIMATE_TOPEN,
        S_DONE_ESTIMATE_TOPEN,
        S_COMMIT_GENERATION,
        S_GET_LEAF_SEED_COMMIT_START,
        S_GET_LEAF_SEED_COMMIT_WAIT,
        S_WRITE_COMMIT,
        S_RESTORE_PREREAD,
        S_RESTORE_SORT,
        S_RESTORE_DRAIN,
        S_START_ESTIMATE_TOPEN_REVEAL,
        S_WAIT_ESTIMATE_TOPEN_REVEAL,
        S_WRITE_REVEAL_SEED,
        S_WRITE_POW_CTR,
        S_ZERO_PAD_SIB,
        S_DONE
    } state_e;
    state_e state;

    // -- pow counter --
    logic [31:0] counter;

    // -- h_piop address (indexes into sig_mem) --
    logic [HPIOP_ADDR_W-1:0] hash_addr_reg;
    logic sel_shake_in;

    assign din_shake_o = sel_shake_in ? sig_data_i :
        {counter[7:0], counter[15:8], counter[23:16], counter[31:24], 32'h0};

    // -- delta shift register --
    logic [SHIFT_WIDTH-1:0] delta_shift_reg;
    logic [SHAKE_CNT_W-1:0] shake_cnt;

    always_ff @(posedge clk_i) begin
        if (!rst_ni || start_shake_o)
            delta_shift_reg <= '0;
        else if (state == S_WAIT_SHAKE && dout_valid_shake_i) begin
            if (SHAKE_REM_BYTES != 0 && shake_cnt == SHAKE_CNT_W'(SHAKE_FULL_WORDS))
                delta_shift_reg <= {delta_shift_reg[SHIFT_WIDTH-SHAKE_REM_BYTES*8-1:0],
                                    dout_shake_i[63 -: SHAKE_REM_BYTES*8]};
            else
                delta_shift_reg <= {delta_shift_reg[SHIFT_WIDTH-64-1:0], dout_shake_i};
        end
        else if (state == S_CHECK_VGRIND && challenge_ok)
            delta_shift_reg <= delta_le;
        else if (state == S_HIDDEN_LEAVES_INDEXES)
            delta_shift_reg <= delta_shift_reg >> KAPPA;
    end

    // -- LE bitstream --
    logic [SHIFT_WIDTH-1:0] delta_le;
    generate
        for (genvar bi = 0; bi < DELTA_BYTES; bi++) begin : byte_swap
            assign delta_le[bi*8 +: 8] = delta_shift_reg[SHIFT_WIDTH - 8*(bi+1) +: 8];
        end
    endgenerate

    wire vgrind = (delta_le[TAU*KAPPA +: W_POW] == '0);

    // reject all-zero delta (C: bitvec_is_zero)
    wire delta_nonzero = (delta_le[TAU*KAPPA-1:0] != '0);

    // Challenge accepted so far (compactness is checked later by the
    // estimate_topen dry run).
    wire challenge_ok = vgrind && delta_nonzero;

    // -- hidden leaf index extraction (shift-register approach) --
    logic [$clog2(TAU):0] delta_counter;
    logic                  delta_write;

    wire [KAPPA-1:0] delta_k = delta_shift_reg[KAPPA-1:0];
    wire [LIDX_W-1:0] hidden_leaf_index =
        LIDX_W'(delta_k) * LIDX_W'(TAU) + LIDX_W'(delta_counter) + LIDX_W'(START_INDEX);

    // -- signals --
    logic start_sort, done_sort;
    logic start_estimate_topen, done_estimate_topen;
    logic [LIDX_W-1:0]    hidden_leaf_index_0;
    logic [$clog2(TAU):0] hidden_leaf_index_addr_0;
    logic                  hidden_leaf_index_sel_eto;
    logic [LIDX_W-1:0]    bend_nxt_index;
    logic [$clog2(TAU):0] bend_nxt_index_addr;
    logic                  bend_nxt_index_en;
    wire  [LIDX_W-1:0]    sort_data_out;
    logic                  sel_commit, sel_backup, restore_sort;
    logic                  seed_reveal_mode;
    logic [LIDX_W-1:0]    leaf_index_reveal;
    logic                  start_leaf_index_reveal;
    logic                  done_leaf_index_reveal;
    logic [LAMBDA-1:0]     reveal_seed_internal;
    logic                  start_commit_gen, done_commit_gen;

    assign hidden_leaf_index_0 = sort_data_out;

    // -- si_q: read data from var_bram Port A (sort or backup region) --
    wire [LIDX_W-1:0] si_q = var_a_data_i[LIDX_W-1:0];

    logic [$clog2(TAU):0] delta_counter_reg;
    always_ff @(posedge clk_i)
        delta_counter_reg <= delta_counter;

    // Sibling path size (internal, for T_OPEN check)
    logic [$clog2(2*TAU*N_CAP)-1:0] sibling_path_size;

    // -- Commit serialization --
    logic [CMT_WORD_W-1:0] commit_word_cnt;

    // -- Seed serialization (shift register for overlap with GGM reveal) --
    logic [LAMBDA-1:0] seed_reg;
    logic [SEED_IDX_W-1:0] seed_write_idx;
    logic [PAD_CNT_W-1:0] pad_word_cnt;

    logic [SIG_ADDR_WIDTH-1:0] sig_base_addr;
    logic [PAD_CNT_W-1:0] pad_limit;


    // -- Sort read address mux --
    // During backup: read the sort list ascending (delta_counter directly).
    // During estimate_topen: read descending (TAU-1-addr).
    wire [SORT_K-1:0] sort_rd_addr =
        sel_backup ? delta_counter[SORT_K-1:0] :
                     (SORT_K'(TAU - 1) - hidden_leaf_index_addr_0[SORT_K-1:0]);

    wire sort_rd_en = sel_backup | hidden_leaf_index_sel_eto;

    // Sort index_wr: estimate_topen writes OR restore from backup
    wire sort_idx_wr = bend_nxt_index_en | restore_sort;
    wire [SORT_K-1:0] sort_idx_addr = restore_sort
        ? delta_counter_reg[SORT_K-1:0]
        : (SORT_K'(TAU - 1) - bend_nxt_index_addr[SORT_K-1:0]);
    wire [LIDX_W-1:0] sort_idx_data = restore_sort ? si_q : bend_nxt_index;

    // Pre-read next backup index during penultimate commit write
    wire commit_preread = (state == S_WRITE_COMMIT &&
                           commit_word_cnt == CMT_WORD_W'(CMT_WORDS - 2) &&
                           delta_counter < ($clog2(TAU)+1)'(TAU - 1));

    // -- insertion_sort with external memory --
    logic [SORT_K-1:0]  sort_mem_rd_addr;
    logic [SORT_K-1:0]  sort_mem_wr_addr;
    logic [LIDX_W-1:0]  sort_mem_wr_data;
    logic               sort_mem_wr_en;

    insertion_sort #(
        .INT_WIDTH(LIDX_W), .INDEX_WIDTH(0), .LIST_LEN(TAU),
        .EXTERNAL_MEM(1)
    ) SORT (
        .clk(clk_i), .start(start_sort),
        .wr_en(delta_write), .wr_addr(delta_counter[SORT_K-1:0]), .data_in(hidden_leaf_index),
        .rd_en(sort_rd_en), .rd_addr(sort_rd_addr), .data_out(sort_data_out),
        .index_wr_en(sort_idx_wr), .index_wr_addr(sort_idx_addr), .index(sort_idx_data),
        .done(done_sort),
        .mem_rd_addr_o(sort_mem_rd_addr),
        .mem_rd_data_i(var_a_data_i[LIDX_W-1:0]),
        .mem_wr_addr_o(sort_mem_wr_addr),
        .mem_wr_data_o(sort_mem_wr_data),
        .mem_wr_en_o  (sort_mem_wr_en)
    );

    // -- var_bram port mux --
    wire si_write = (state == S_BACKUP_SORTED || state == S_BACKUP_DRAIN);
    wire restore_active = (state == S_RESTORE_PREREAD || state == S_RESTORE_SORT
                           || state == S_RESTORE_DRAIN);

    // Port A (read): backup region (commit/restore) or sort region (default)
    always_comb begin
        var_a_wr_en_o = 1'b0;
        var_a_data_o  = '0;

        if (commit_preread) begin
            var_a_addr_o = VAR_ADDR_WIDTH_COMBINED'(ORE_BACKUP_BASE + delta_counter + 1);
        end else if (sel_commit) begin
            var_a_addr_o = VAR_ADDR_WIDTH_COMBINED'(ORE_BACKUP_BASE + delta_counter);
        end else if (restore_active) begin
            var_a_addr_o = VAR_ADDR_WIDTH_COMBINED'(ORE_BACKUP_BASE + delta_counter);
        end else begin
            var_a_addr_o = VAR_ADDR_WIDTH_COMBINED'(ORE_SORT_BASE + sort_mem_rd_addr);
        end
    end

    // Port B (write): backup copy OR sort write
    always_comb begin
        if (si_write) begin
            var_b_addr_o  = VAR_ADDR_WIDTH_COMBINED'(ORE_BACKUP_BASE + delta_counter_reg);
            var_b_data_o  = VAR_DATA_WIDTH_COMBINED'(sort_data_out);
            var_b_wr_en_o = 1'b1;
        end else begin
            var_b_addr_o  = VAR_ADDR_WIDTH_COMBINED'(ORE_SORT_BASE + sort_mem_wr_addr);
            var_b_data_o  = VAR_DATA_WIDTH_COMBINED'(sort_mem_wr_data);
            var_b_wr_en_o = sort_mem_wr_en;
        end
    end

    // -- estimate_topen --
    // Acknowledge after seed write completes (estimate_topen blocks until then)
    assign done_leaf_index_reveal =
        (state == S_WRITE_REVEAL_SEED && commit_word_cnt == CMT_WORD_W'(SEED_WORDS - 1));

    estimate_topen #(
        .TAU(TAU), .KAPPA(KAPPA), .LEAVE_INDEX_WIDTH(LIDX_W), .SEED_WIDTH(LAMBDA)
    ) ETO (
        .clk_i(clk_i), .rst_i(~rst_ni), .start_i(start_estimate_topen),
        .count_only_mode_i(1'b0),
        .hidden_leaf_index_0_i(hidden_leaf_index_0),
        .hidden_leaf_index_addr_0_o(hidden_leaf_index_addr_0),
        .hidden_leaf_index_sel_o(hidden_leaf_index_sel_eto),
        .bend_nxt_index_o(bend_nxt_index), .bend_nxt_index_addr_o(bend_nxt_index_addr),
        .bend_nxt_index_en(bend_nxt_index_en),
        .done_o(done_estimate_topen), .sibling_path_size_o(sibling_path_size),
        .seed_reveal_mode_i(seed_reveal_mode),
        .leaf_index_reveal_o(leaf_index_reveal),
        .start_leaf_index_reveal_o(start_leaf_index_reveal),
        .done_leaf_index_reveal_i(done_leaf_index_reveal),
        .reveal_seed_i(reveal_seed_internal),
        .reveal_seed_o(/* unused - we write to sig_mem instead */),
        .reveal_seed_valid_o(/* unused */)
    );

    // -- GGM tree --
    // During commits: si_q = sort read data from var_bram
    wire [$clog2(2*MAX_SEEDS)-1:0] node_index =
        seed_reveal_mode ? leaf_index_reveal : si_q[$clog2(2*MAX_SEEDS)-1:0];

    wire [2*LAMBDA-1:0] ggm_commit;

    full_ggm_tree_get_leaf_seed_commit #(
        .SEED_WIDTH(LAMBDA), .MAX_SEEDS(MAX_SEEDS)
    ) GGM_TREE (
        .clk_i(clk_i), .rst_ni(rst_ni),
        .start_i(start_commit_gen | start_leaf_index_reveal),
        .seed_search_mode_i(seed_reveal_mode), .done_o(done_commit_gen),
        .node_index_i(node_index), .seed_i(root_seed_i), .salt_i(salt_i),
        .commit_o(ggm_commit), .reveal_seed_o(reveal_seed_internal),
        .enc_enable_o(enc_enable_o), .enc_key_o(enc_key_o),
        .enc_plaintext_0_o(enc_plaintext_0_o), .enc_ready_0_i(enc_ready_0_i),
        .enc_valid_0_i(enc_valid_0_i), .enc_ciphertext_0_i(enc_ciphertext_0_i),
        .enc_plaintext_1_o(enc_plaintext_1_o), .enc_ready_1_i(enc_ready_1_i),
        .enc_valid_1_i(enc_valid_1_i), .enc_ciphertext_1_i(enc_ciphertext_1_i)
    );

    // -- sig_mem write data --
    // Commit: read directly from ggm_commit (no register, AES outputs stable)
    logic [63:0] commit_data_word;
    always_comb begin
        commit_data_word = 64'b0;
        for (int w = 0; w < CMT_WORDS; w++) begin
            if (commit_word_cnt == CMT_WORD_W'(w))
                commit_data_word = ggm_commit[2*LAMBDA-1 - 64*w -: 64];
        end
    end

    // Seed: shift-out from seed_reg (top 64 bits, shift left each cycle)
    wire [63:0] seed_data_word = seed_reg[LAMBDA-1 -: 64];

    // -- seed_reg shift-out --
    logic seed_shift;
    always_ff @(posedge clk_i) begin
        if (!rst_ni)
            seed_reg <= '0;
        else if (state == S_WAIT_ESTIMATE_TOPEN_REVEAL && done_commit_gen)
            seed_reg <= reveal_seed_internal;
        else if (seed_shift)
            seed_reg <= {seed_reg[LAMBDA-65:0], 64'b0};
    end

    // -- main FSM --
    always_ff @(posedge clk_i) begin
        if (!rst_ni) begin
            state <= S_WAIT_START; done_o <= 1'b0;
            counter <= '0; hash_addr_reg <= '0; delta_counter <= '0;
            shake_cnt <= '0; start_sort <= 1'b0;
            commit_word_cnt <= '0;
            seed_write_idx <= '0; pad_word_cnt <= '0;
            sig_base_addr <= '0; pad_limit <= '0;
        end
        else case (state)

        S_WAIT_START: begin
            if (start_i) begin state <= S_OPEN_DELTA; done_o <= 1'b0; end
            counter <= '0; hash_addr_reg <= '0; delta_counter <= '0;
            shake_cnt <= '0; start_sort <= 1'b0;
            seed_write_idx <= '0;
        end

        S_OPEN_DELTA: begin
            done_o <= 1'b0;
            if (din_ready_shake_i) begin
                state <= S_LOAD_HASH_PIOP;
                hash_addr_reg <= hash_addr_reg + HPIOP_ADDR_W'(1);
            end
        end

        S_LOAD_HASH_PIOP:
            if (hash_addr_reg == HPIOP_ADDR_W'(HPIOP_WORDS - 1))
                state <= S_LOAD_HASH_PIOP_LAST;
            else if (din_ready_shake_i)
                hash_addr_reg <= hash_addr_reg + HPIOP_ADDR_W'(1);

        S_LOAD_HASH_PIOP_LAST:
            if (din_ready_shake_i) begin hash_addr_reg <= '0; state <= S_LOAD_COUNTER; end

        S_LOAD_COUNTER:
            if (din_ready_shake_i) begin state <= S_WAIT_SHAKE; shake_cnt <= '0; end

        S_WAIT_SHAKE:
            if (dout_valid_shake_i) begin
                if (shake_cnt == SHAKE_CNT_W'(SHAKE_WORD_COUNT - 1))
                    begin state <= S_CHECK_VGRIND; shake_cnt <= '0; end
                else shake_cnt <= shake_cnt + SHAKE_CNT_W'(1);
            end

        S_CHECK_VGRIND:
            if (challenge_ok) state <= S_HIDDEN_LEAVES_INDEXES;
            else begin state <= S_OPEN_DELTA; counter <= counter + 32'd1; end

        S_HIDDEN_LEAVES_INDEXES:
            if (delta_counter == ($clog2(TAU)+1)'(TAU - 1)) begin
                state <= S_SORT_INDEXES; delta_counter <= '0; start_sort <= 1'b1;
            end else delta_counter <= delta_counter + ($clog2(TAU)+1)'(1);

        S_SORT_INDEXES: begin
            start_sort <= 1'b0;
            if (done_sort) state <= S_BACKUP_PREREAD;
        end

        S_BACKUP_PREREAD:
            state <= S_BACKUP_SORTED;

        S_BACKUP_SORTED:
            if (delta_counter == ($clog2(TAU)+1)'(TAU - 1))
                state <= S_BACKUP_DRAIN;
            else
                delta_counter <= delta_counter + ($clog2(TAU)+1)'(1);

        S_BACKUP_DRAIN: begin
            delta_counter <= '0;
            state <= S_START_ESTIMATE_TOPEN;
        end

        S_START_ESTIMATE_TOPEN:
            state <= S_DONE_ESTIMATE_TOPEN;

        S_DONE_ESTIMATE_TOPEN:
            if (done_estimate_topen) begin
                if (sibling_path_size <= LIDX_W'(T_OPEN)) begin
                    state <= S_COMMIT_GENERATION; delta_counter <= '0;
                end else begin
                    state <= S_OPEN_DELTA; counter <= counter + 32'd1;
                end
            end

        S_COMMIT_GENERATION:
            if (delta_counter == ($clog2(TAU)+1)'(TAU)) begin
                state <= S_RESTORE_PREREAD; delta_counter <= '0;
            end else state <= S_GET_LEAF_SEED_COMMIT_START;

        S_GET_LEAF_SEED_COMMIT_START:
            state <= S_GET_LEAF_SEED_COMMIT_WAIT;

        S_GET_LEAF_SEED_COMMIT_WAIT:
            if (done_commit_gen) begin
                commit_word_cnt <= '0;
                sig_base_addr <= SIG_ADDR_WIDTH'(SIG_CMT_OFFSET
                                 + delta_counter * CMT_WORDS);
                state <= S_WRITE_COMMIT;
            end

        S_WRITE_COMMIT: begin
            if (commit_word_cnt == CMT_WORD_W'(CMT_WORDS - 1)) begin
                if (delta_counter + ($clog2(TAU)+1)'(1) >= ($clog2(TAU)+1)'(TAU)) begin
                    delta_counter <= '0;
                    state <= S_RESTORE_PREREAD;
                end else begin
                    delta_counter <= delta_counter + ($clog2(TAU)+1)'(1);
                    state <= S_GET_LEAF_SEED_COMMIT_WAIT;
                end
            end else
                commit_word_cnt <= commit_word_cnt + CMT_WORD_W'(1);
        end

        S_RESTORE_PREREAD:
            state <= S_RESTORE_SORT;

        S_RESTORE_SORT:
            if (delta_counter == ($clog2(TAU)+1)'(TAU - 1))
                state <= S_RESTORE_DRAIN;
            else
                delta_counter <= delta_counter + ($clog2(TAU)+1)'(1);

        S_RESTORE_DRAIN: begin
            delta_counter <= '0;
            state <= S_START_ESTIMATE_TOPEN_REVEAL;
        end

        S_START_ESTIMATE_TOPEN_REVEAL:
            state <= S_WAIT_ESTIMATE_TOPEN_REVEAL;

        S_WAIT_ESTIMATE_TOPEN_REVEAL:
            if (done_commit_gen) begin
                commit_word_cnt <= '0;
                sig_base_addr <= SIG_ADDR_WIDTH'(SIG_SIB_OFFSET
                                 + seed_write_idx * SEED_WORDS);
                state <= S_WRITE_REVEAL_SEED;
            end else if (done_estimate_topen) begin
                state <= S_WRITE_POW_CTR;
            end

        S_WRITE_REVEAL_SEED: begin
            if (commit_word_cnt == CMT_WORD_W'(SEED_WORDS - 1)) begin
                seed_write_idx <= seed_write_idx + SEED_IDX_W'(1);
                state <= S_WAIT_ESTIMATE_TOPEN_REVEAL;
            end else
                commit_word_cnt <= commit_word_cnt + CMT_WORD_W'(1);
        end

        S_WRITE_POW_CTR: begin
            pad_word_cnt <= '0;
            pad_limit <= PAD_CNT_W'((T_OPEN - seed_write_idx) * SEED_WORDS);
            sig_base_addr <= SIG_ADDR_WIDTH'(SIG_SIB_OFFSET
                             + seed_write_idx * SEED_WORDS);
            state <= S_ZERO_PAD_SIB;
        end

        S_ZERO_PAD_SIB: begin
            if (pad_word_cnt >= pad_limit) begin
                state <= S_DONE;
                done_o <= 1'b1;
            end else
                pad_word_cnt <= pad_word_cnt + PAD_CNT_W'(1);
        end

        S_DONE: begin done_o <= 1'b1; state <= S_WAIT_START; end

        default: state <= S_WAIT_START;
        endcase
    end

    // -- seed shift-out control --
    always_comb begin
        seed_shift = 1'b0;
        if (state == S_WRITE_REVEAL_SEED &&
            commit_word_cnt < CMT_WORD_W'(SEED_WORDS - 1))
            seed_shift = 1'b1;
    end

    // -- combinational outputs --
    always_comb begin
        start_shake_o = 0; mode_shake_o = 0; seed_from_output_shake_o = 0;
        din_valid_shake_o = 0; last_din_shake_o = 0; last_din_byte_shake_o = 4'd8;
        dout_ready_shake_o = 0; sel_shake_in = 0;
        delta_write = 0; start_estimate_topen = 0;
        sel_commit = 0; sel_backup = 0; start_commit_gen = 0;
        seed_reveal_mode = 0; restore_sort = 0;

        // sig_mem defaults
        sig_data_o  = 64'b0;
        sig_addr_o  = SIG_ADDR_WIDTH'(H_PIOP_SIG_OFFSET + hash_addr_reg);
        sig_wr_en_o = 1'b0;

        case (state)
        S_OPEN_DELTA: begin
            start_shake_o = 1; sel_shake_in = 1;
            sig_addr_o = SIG_ADDR_WIDTH'(H_PIOP_SIG_OFFSET);
        end

        S_LOAD_HASH_PIOP, S_LOAD_HASH_PIOP_LAST: begin
            sel_shake_in = 1;
            sig_addr_o = SIG_ADDR_WIDTH'(H_PIOP_SIG_OFFSET + hash_addr_reg);
            if (din_ready_shake_i) din_valid_shake_o = 1;
        end

        S_LOAD_COUNTER: begin
            last_din_shake_o = 1; last_din_byte_shake_o = 4'd4;
            if (din_ready_shake_i) din_valid_shake_o = 1;
        end

        S_WAIT_SHAKE: dout_ready_shake_o = 1;
        S_HIDDEN_LEAVES_INDEXES: delta_write = 1;

        S_BACKUP_PREREAD, S_BACKUP_SORTED, S_BACKUP_DRAIN: sel_backup = 1;

        S_START_ESTIMATE_TOPEN: start_estimate_topen = 1;

        S_COMMIT_GENERATION: sel_commit = 1;
        S_GET_LEAF_SEED_COMMIT_START: begin sel_commit = 1; start_commit_gen = 1; end
        S_GET_LEAF_SEED_COMMIT_WAIT: sel_commit = 1;

        S_WRITE_COMMIT: begin
            sig_wr_en_o = 1'b1;
            sig_addr_o  = sig_base_addr + SIG_ADDR_WIDTH'(commit_word_cnt);
            sig_data_o  = commit_data_word;
            if (commit_word_cnt == CMT_WORD_W'(CMT_WORDS - 1) &&
                delta_counter + ($clog2(TAU)+1)'(1) < ($clog2(TAU)+1)'(TAU))
                start_commit_gen = 1;
        end

        S_RESTORE_SORT, S_RESTORE_DRAIN: restore_sort = 1;

        S_START_ESTIMATE_TOPEN_REVEAL: begin start_estimate_topen = 1; seed_reveal_mode = 1; end
        S_WAIT_ESTIMATE_TOPEN_REVEAL: seed_reveal_mode = 1;

        S_WRITE_REVEAL_SEED: begin
            seed_reveal_mode = 1;
            sig_wr_en_o = 1'b1;
            sig_addr_o  = sig_base_addr + SIG_ADDR_WIDTH'(commit_word_cnt);
            sig_data_o  = seed_data_word;
        end

        S_WRITE_POW_CTR: begin
            sig_wr_en_o = 1'b1;
            sig_addr_o  = SIG_ADDR_WIDTH'(SIG_POW_OFFSET);
            sig_data_o  = {32'b0, counter};
        end

        S_ZERO_PAD_SIB: begin
            if (pad_word_cnt < pad_limit) begin
                sig_wr_en_o = 1'b1;
                sig_addr_o  = sig_base_addr + SIG_ADDR_WIDTH'(pad_word_cnt);
                sig_data_o  = 64'b0;
            end
        end

        default: ;
        endcase
    end

endmodule
