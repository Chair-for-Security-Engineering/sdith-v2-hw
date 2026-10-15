// SPDX-FileCopyrightText: 2026 Stef Halmans, Niklas Höher
// SPDX-License-Identifier: LicenseRef-RUB-SecEng

// generate_pwit_chunk
//
// GenerateV for HALF_POLY=0: computes one chunk of the V matrix by
// re-traversing the tree-cached GGM leaves and re-expanding each leaf's
// PRG output, extracting only the r_wit bits belonging to this chunk
// (CHUNK_BIT_SIZE bits, i-aligned). AES counter mode gives random access
// into the PRG stream: the chunk's bit range maps to one or two CTR
// blocks per leaf (it can cross a block boundary), computed on both
// cores in parallel.
//
// Called NUM_PWIT_CHUNKS times by piop with increasing chunk_idx. Each
// invocation produces chunk_size rows x (TAU*KAPPA) columns of V in
// scratchpad, column-wise; transpose_pwit follows.
//
// r_acc and r_base accumulate in scratchpad. r_base for each e-value
// writes directly into V's e-slot, so no copy-back is needed.

module generate_pwit_chunk
import sdith_params_pkg::*;
import sdith_helpers_pkg::*;
(
    input  logic clk_i,
    input  logic rst_i,

    // Control
    input  logic fsm_start_i,
    output logic fsm_done_o,
    input  logic [$clog2(NUM_PWIT_CHUNKS)-1:0] chunk_idx_i,

    // Leaf cache interface
    output logic                     get_next_leaf_o,
    input  logic                     leaf_done_i,
    output logic [GGM_TREE_DEPTH:0]  leaf_idx_o,
    output logic [GGM_TREE_DEPTH:0]  leaf_idx2_o,
    input  logic [LAMBDA-1:0]        leaf_i,
    input  logic [LAMBDA-1:0]        leaf2_i,

    // AES0 for PRG extraction
    output logic [ENC_KEYSIZE-1:0]   aes0_key_o,
    output logic [ENC_BLOCKSIZE-1:0] aes0_plaintext_o,
    input  logic [ENC_BLOCKSIZE-1:0] aes0_ciphertext_i,
    output logic                     aes0_enable_o,
    input  logic                     aes0_ready_i,
    input  logic                     aes0_valid_i,

    // AES1 for PRG extraction (second block)
    output logic [ENC_KEYSIZE-1:0]   aes1_key_o,
    output logic [ENC_BLOCKSIZE-1:0] aes1_plaintext_o,
    input  logic [ENC_BLOCKSIZE-1:0] aes1_ciphertext_i,
    output logic                     aes1_enable_o,
    input  logic                     aes1_ready_i,
    input  logic                     aes1_valid_i,

    // Signal: when high, AES is for PRG (not leaf cache)
    output logic                     prg_owns_aes_o,

    // Var BRAM dual-port
    input  logic [VAR_DATA_WIDTH_COMBINED-1:0] var_a_data_i,
    output logic [VAR_DATA_WIDTH_COMBINED-1:0] var_a_data_o,
    output logic [VAR_ADDR_WIDTH_COMBINED-1:0] var_a_addr_o,
    output logic                               var_a_wr_en_o,
    input  logic [VAR_DATA_WIDTH_COMBINED-1:0] var_b_data_i,
    output logic [VAR_DATA_WIDTH_COMBINED-1:0] var_b_data_o,
    output logic [VAR_ADDR_WIDTH_COMBINED-1:0] var_b_addr_o,
    output logic                               var_b_wr_en_o
);
  // Local parameters

  localparam CAN_DUAL = CAN_DUAL_COMBINED;
  localparam N_PAIRS = N_CAP / 2;
  localparam CW = CHUNK_WORDS;

  // Combine dual-port var reads into one 64-bit logical word
  function automatic [63:0] combine_ab;
    if (CAN_DUAL) return 64'(var_a_data_i);
    else          return {var_b_data_i, var_a_data_i};
  endfunction
  // FSM states

  typedef enum logic [3:0] {
    S_IDLE,
    S_INIT,
    S_E_INIT,
    S_LEAF_WAIT,
    S_PRG_FIRE,
    S_PRG_WAIT,
    S_ACC_RACC_RD,
    S_ACC_RACC_WR,
    S_ACC_RBASE_RD,
    S_ACC_RBASE_WR,
    S_DONE
  } state_e;

  state_e state, next_state;
  // Registers

  logic [$clog2(TAU)-1:0]    e_cnt,    next_e_cnt;
  logic [VAR_ADDR_WIDTH_COMBINED-1:0] e_base_r, next_e_base_r;
  logic [$clog2(N_PAIRS):0]  pair_cnt, next_pair_cnt;
  logic [GGM_TREE_DEPTH+1:0] leaf_base, next_leaf_base;

  // PRG parameters
  logic [$clog2(2*ENC_BLOCKSIZE)-1:0] bit_offset_reg, next_bit_offset_reg;
  logic [7:0]                          first_block_reg, next_first_block_reg;
  logic                                blocks_needed_reg, next_blocks_needed_reg;

  // PRG extracted data. For CAN_DUAL=0 also reused as racc accumulation
  // buffer. For CAN_DUAL=1, racc/rbase writes are interleaved across both
  // BRAM ports, so a separate new_racc_latched register is used instead.
  logic [LAMBDA-1:0] prg_data, next_prg_data;

  // CAN_DUAL=1: latch for new_racc computed in S_ACC_RACC_WR, consumed one
  // cycle later in S_ACC_RACC_RD or the drain cycle for rbase writeback.
  logic [63:0] new_racc_latched, next_new_racc_latched;

  logic [$clog2(CW):0] acc_w, next_acc_w;

  // Which half of pair: 0 = left (leaf1), 1 = right (leaf2)
  logic acc_half, next_acc_half;

  logic [$clog2(KAPPA)-1:0] col_reg, next_col_reg;

  logic [$clog2(KAPPA*CW+CW+1):0] clr_cnt, next_clr_cnt;
  logic leaf_done_r, next_leaf_done_r;
  // PRG bit extraction

  // Byte-swap each 64-bit word of AES ciphertext (MSB-first to LSB-first within words)
  wire [ENC_BLOCKSIZE-1:0] cipher0_swapped;
  wire [ENC_BLOCKSIZE-1:0] cipher1_swapped;

  generate
    for (genvar g = 0; g < BLOCK_DIV_64; g++) begin : gen_swap0
      assign cipher0_swapped[g*64 +: 64] =
          bswap64(aes0_ciphertext_i[(BLOCK_DIV_64-1-g)*64 +: 64]);
    end
    for (genvar g = 0; g < BLOCK_DIV_64; g++) begin : gen_swap1
      assign cipher1_swapped[g*64 +: 64] =
          bswap64(aes1_ciphertext_i[(BLOCK_DIV_64-1-g)*64 +: 64]);
    end
  endgenerate

  // Extract LAMBDA bits at bit_offset from concatenated blocks.
  // After byte-swap, PRG byte 0 is at bit 0 (LSB). Skip bit_offset bits from LSB.
  wire [2*ENC_BLOCKSIZE-1:0] prg_concat = {cipher1_swapped, cipher0_swapped};
  wire [LAMBDA-1:0] prg_extract_2blk = prg_concat[bit_offset_reg +: LAMBDA];
  wire [LAMBDA-1:0] prg_extract_1blk = cipher0_swapped[bit_offset_reg +: LAMBDA];
  wire [LAMBDA-1:0] prg_raw = blocks_needed_reg ? prg_extract_2blk : prg_extract_1blk;

  // Mask the last chunk to LAST_CHUNK_SIZE bits; other chunks use full LAMBDA
  // bits. For i-aligned HALF_POLY=0, intermediate chunks extract LAMBDA bits
  // but process_pwit only reads CHUNK_BIT_SIZE entries - the extra entries in
  // r_acc are harmless.
  localparam [LAMBDA-1:0] LAST_CHUNK_MASK = (LAMBDA'(1) << LAST_CHUNK_SIZE) - 1;
  wire is_last_chunk = (chunk_idx_i == ($clog2(NUM_PWIT_CHUNKS))'(NUM_PWIT_CHUNKS - 1));
  wire [LAMBDA-1:0] prg_extracted = is_last_chunk ? (prg_raw & LAST_CHUNK_MASK) : prg_raw;

  // AES key: for Cat3, pad 192-bit seed to 256-bit key
  wire [ENC_KEYSIZE-1:0] aes_key_cur;
  generate
    if (SECURITY_LEVEL == 3) begin : gen_cat3_key
      assign aes_key_cur = acc_half ? {64'b0, leaf2_i} : {64'b0, leaf_i};
    end else begin : gen_other_key
      assign aes_key_cur = acc_half ? ENC_KEYSIZE'(leaf2_i) : ENC_KEYSIZE'(leaf_i);
    end
  endgenerate

  // AES plaintext: counter value in LE byte order
  wire [ENC_BLOCKSIZE-1:0] plaintext_blk0 = {<<8{ENC_BLOCKSIZE'(first_block_reg)}};
  wire [ENC_BLOCKSIZE-1:0] plaintext_blk1 = {<<8{ENC_BLOCKSIZE'(first_block_reg + 1)}};
  // BRAM address helpers

  wire [VAR_ADDR_WIDTH_COMBINED-1:0] racc_log_addr = VAR_ADDR_WIDTH_COMBINED'(PWIT_RACC_OFFSET + acc_w);
  wire [VAR_ADDR_WIDTH_COMBINED-1:0] rbase_log_addr =
      VAR_ADDR_WIDTH_COMBINED'(PWIT_V_OFFSET) + e_base_r + VAR_ADDR_WIDTH_COMBINED'(col_reg * CW + acc_w);
  // Address of rbase[col][acc_w - 1]: used in S_ACC_RACC_RD at acc_w>0
  // to write back the previous word's rbase while port A issues the next racc read.
  wire [VAR_ADDR_WIDTH_COMBINED-1:0] rbase_log_addr_prev =
      VAR_ADDR_WIDTH_COMBINED'(PWIT_V_OFFSET) + e_base_r + VAR_ADDR_WIDTH_COMBINED'(col_reg * CW + (acc_w - 1));

  wire [63:0] prg_word = prg_data[acc_w*64 +: 64];
  // FSM combinational logic

  always_comb begin
    next_state = state;
    next_e_cnt = e_cnt;
    next_e_base_r = e_base_r;
    next_pair_cnt = pair_cnt;
    next_leaf_base = leaf_base;
    next_bit_offset_reg = bit_offset_reg;
    next_first_block_reg = first_block_reg;
    next_blocks_needed_reg = blocks_needed_reg;
    next_prg_data = prg_data;
    next_new_racc_latched = new_racc_latched;
    next_acc_w = acc_w;
    next_acc_half = acc_half;
    next_col_reg = col_reg;
    next_clr_cnt = clr_cnt;
    next_leaf_done_r = leaf_done_r || (leaf_done_i && state == S_E_INIT);

    // Output defaults
    fsm_done_o = 0;
    get_next_leaf_o = 0;
    // Hold leaf indices - get_leaf_combined uses leaf_idx_i combinationally
    // for cache BRAM addressing every cycle, not just at get_next_leaf.
    // During right-half processing with a prefetch pending, hold NEXT pair's indices.
    if (acc_half && pair_cnt + 1 < N_PAIRS) begin
      leaf_idx_o  = (GGM_TREE_DEPTH+1)'(leaf_base + 2 * TAU);
      leaf_idx2_o = (GGM_TREE_DEPTH+1)'(leaf_base + 2 * TAU + TAU);
    end else begin
      leaf_idx_o  = (GGM_TREE_DEPTH+1)'(leaf_base);
      leaf_idx2_o = (GGM_TREE_DEPTH+1)'(leaf_base + TAU);
    end
    aes0_key_o = '0;
    aes0_plaintext_o = '0;
    aes0_enable_o = 0;
    aes1_key_o = '0;
    aes1_plaintext_o = '0;
    aes1_enable_o = 0;
    prg_owns_aes_o = 0;
    var_a_data_o = '0;
    var_a_addr_o = '0;
    var_a_wr_en_o = 0;
    var_b_data_o = '0;
    var_b_addr_o = '0;
    var_b_wr_en_o = 0;

    case (state)
      // --------------------------------------------------------
      S_IDLE: begin
        if (fsm_start_i)
          next_state = S_INIT;
      end

      // --------------------------------------------------------
      S_INIT: begin
        // Map chunk_idx to AES-CTR random-access parameters:
        //   start_bit    = first PRG bit for this chunk in the leaf's output stream
        //   first_block  = AES block number containing start_bit
        //   bit_offset   = position within the (possibly 2-block) concatenation
        //   blocks_needed = 1 if the chunk slice spans a block boundary
        automatic logic [31:0] start_bit;
        automatic logic [31:0] cs;
        start_bit = R_WIT_OFFSET + 32'(chunk_idx_i) * CHUNK_BIT_SIZE;
        next_first_block_reg = start_bit[$clog2(ENC_BLOCKSIZE) +: 8];
        next_bit_offset_reg  = start_bit[$clog2(2*ENC_BLOCKSIZE)-1:0] & ($clog2(2*ENC_BLOCKSIZE)'(ENC_BLOCKSIZE - 1));

        cs = (chunk_idx_i == NUM_PWIT_CHUNKS - 1) ? LAST_CHUNK_SIZE : LAMBDA;
        next_blocks_needed_reg = ((start_bit & (ENC_BLOCKSIZE - 1)) + cs > ENC_BLOCKSIZE) ? 1'b1 : 1'b0;

        next_e_cnt = '0;
        next_e_base_r = '0;
        next_leaf_base = '0;
        next_clr_cnt = '0;
        next_state = S_E_INIT;
      end

      // --------------------------------------------------------
      S_E_INIT: begin
        // Clear r_acc + V[e], overlapped with first leaf fetch on clr_cnt==0.
        // leaf_idx_o defaults hold correct values (from leaf_base = e_cnt).
        automatic int total_clr = CW + KAPPA * CW;

        if (clr_cnt == 0)
          get_next_leaf_o = 1;

        if (clr_cnt < total_clr) begin
          automatic logic [VAR_ADDR_WIDTH_COMBINED-1:0] log_addr;
          if (clr_cnt < CW)
            log_addr = VAR_ADDR_WIDTH_COMBINED'(PWIT_RACC_OFFSET + clr_cnt);
          else
            log_addr = VAR_ADDR_WIDTH_COMBINED'(PWIT_V_OFFSET) + e_base_r + VAR_ADDR_WIDTH_COMBINED'(clr_cnt - CW);

          var_a_addr_o = phys_a(log_addr);
          var_b_addr_o = phys_b(log_addr);
          var_a_data_o = '0;
          var_b_data_o = '0;
          var_a_wr_en_o = 1;
          if (!CAN_DUAL) var_b_wr_en_o = 1;
          next_clr_cnt = clr_cnt + 1;
        end else begin
          next_pair_cnt = '0;
          next_acc_half = 0;
          next_state = S_LEAF_WAIT;
        end
      end

      // --------------------------------------------------------
      S_LEAF_WAIT: begin
        leaf_idx_o  = (GGM_TREE_DEPTH+1)'(leaf_base);
        leaf_idx2_o = (GGM_TREE_DEPTH+1)'(leaf_base + TAU);
        if (leaf_done_i || leaf_done_r) begin
          next_leaf_done_r = 0;
          next_acc_half = 0;  // start with left leaf
          next_state = S_PRG_FIRE;
        end
      end

      // --------------------------------------------------------
      S_PRG_FIRE: begin
        prg_owns_aes_o = 1;
        aes0_key_o = aes_key_cur;
        aes0_plaintext_o = plaintext_blk0;
        aes0_enable_o = 1;

        if (blocks_needed_reg) begin
          aes1_key_o = aes_key_cur;
          aes1_plaintext_o = plaintext_blk1;
          aes1_enable_o = 1;
        end

        next_state = S_PRG_WAIT;
      end

      // --------------------------------------------------------
      S_PRG_WAIT: begin
        prg_owns_aes_o = 1;
        if (blocks_needed_reg ? (aes0_valid_i && aes1_valid_i) : aes0_valid_i) begin
          next_prg_data = prg_extracted;
          next_acc_w = '0;

          if (!acc_half) begin
            // Left AES completed. Fire right AES immediately.
            // leaf2_i from get_leaf_combined remains stable until next get_next_leaf.
            aes0_key_o = ENC_KEYSIZE'(leaf2_i);
            aes0_plaintext_o = plaintext_blk0;
            aes0_enable_o = 1;
            if (blocks_needed_reg) begin
              aes1_key_o = ENC_KEYSIZE'(leaf2_i);
              aes1_plaintext_o = plaintext_blk1;
              aes1_enable_o = 1;
            end
          end

          next_state = S_ACC_RACC_RD;
        end
      end

      // --------------------------------------------------------
      // Accumulation phase 1: r_acc ^= prg_data (per word)
      // --------------------------------------------------------
      S_ACC_RACC_RD: begin
        // Port A: read racc[acc_w].
        var_a_addr_o = phys_a(racc_log_addr);
        prg_owns_aes_o = !acc_half;

        if (CAN_DUAL) begin
          // Compute col_reg at first word so it is available from
          // S_ACC_RACC_WR onward where port B needs the rbase address.
          if (acc_w == 0) begin
            automatic logic [$clog2(N_CAP):0] seq_pos;
            seq_pos = 2 * pair_cnt + acc_half;
            if (seq_pos + 1 == N_CAP)
              next_col_reg = ($clog2(KAPPA))'(KAPPA - 1);
            else
              next_col_reg = ctz_func(seq_pos + 1);
          end

          // For acc_w > 0, port B data holds old_rbase[col][acc_w-1] from the
          // read issued in the previous S_ACC_RACC_WR. Write new_rbase =
          // old_rbase ^ new_racc_latched back on port B while port A
          // continues with the next racc read.
          if (acc_w != 0) begin
            var_b_addr_o  = phys_b(rbase_log_addr_prev);
            var_b_data_o  = VAR_DATA_WIDTH_COMBINED'(64'(var_b_data_i) ^ new_racc_latched);
            var_b_wr_en_o = 1'b1;
          end
        end else begin
          // SEC1 (CAN_DUAL=0): port B mirrors port A (upper 32 bits of the
          // 64-bit logical word).
          var_b_addr_o = phys_b(racc_log_addr);
        end

        // Prefetch next pair's leaf at start of right racc phase while AES
        // is idle (prg_owns_aes=0 when acc_half=1).
        if (acc_half && acc_w == 0 && pair_cnt + 1 < N_PAIRS) begin
          get_next_leaf_o = 1;
          leaf_idx_o  = (GGM_TREE_DEPTH+1)'(leaf_base + 2 * TAU);
          leaf_idx2_o = (GGM_TREE_DEPTH+1)'(leaf_base + 2 * TAU + TAU);
        end

        next_state = S_ACC_RACC_WR;
      end

      S_ACC_RACC_WR: begin
        automatic logic [63:0] old_racc = combine_ab();
        automatic logic [63:0] new_racc = old_racc ^ prg_word;
        prg_owns_aes_o = !acc_half;

        var_a_addr_o  = phys_a(racc_log_addr);
        var_a_data_o  = CAN_DUAL ? VAR_DATA_WIDTH_COMBINED'(new_racc) : new_racc[31:0];
        var_a_wr_en_o = 1'b1;

        if (CAN_DUAL) begin
          // Port B issues RD for rbase[col][acc_w]. Data arrives next cycle
          // (S_ACC_RACC_RD at acc_w+1, or drain for the last word) and is
          // XORed with new_racc_latched to produce new_rbase.
          var_b_addr_o          = phys_b(rbase_log_addr);
          next_new_racc_latched = new_racc;
        end else begin
          // SEC1: port B carries upper 32 bits of the racc write.
          var_b_addr_o  = phys_b(racc_log_addr);
          var_b_data_o  = new_racc[63:32];
          var_b_wr_en_o = 1'b1;

          // Phase-2 reuse: stash new_racc in prg_data for the RBASE_WR XOR.
          next_prg_data = prg_data;
          for (int i = 0; i < CW; i++) begin
            if (acc_w == i[$clog2(CW):0])
              next_prg_data[i*64 +: 64] = new_racc;
          end
        end

        if (acc_w < CW - 1) begin
          next_acc_w = acc_w + 1;
          next_state = S_ACC_RACC_RD;
        end else begin
          if (CAN_DUAL) begin
            // CAN_DUAL=1: skip separate RBASE_RD - rbase data already arrives
            // via port B pipeline. Go directly to drain (S_ACC_RBASE_WR).
            next_state = S_ACC_RBASE_WR;
          end else begin
            // SEC1: run separate rbase phase from word 0.
            automatic logic [$clog2(N_CAP):0] seq_pos;
            seq_pos = 2 * pair_cnt + acc_half;
            if (seq_pos + 1 == N_CAP)
              next_col_reg = ($clog2(KAPPA))'(KAPPA - 1);
            else
              next_col_reg = ctz_func(seq_pos + 1);

            next_acc_w = '0;
            next_state = S_ACC_RBASE_RD;
          end
        end
      end

      // --------------------------------------------------------
      // Accumulation phase 2: r_base[col] ^= r_acc (per word)
      // --------------------------------------------------------
      S_ACC_RBASE_RD: begin
        // Read r_base[col][acc_w] - racc comes from prg_data (overwritten in phase 1)
        var_a_addr_o = phys_a(rbase_log_addr);
        var_b_addr_o = phys_b(rbase_log_addr);
        prg_owns_aes_o = !acc_half;

        next_state = S_ACC_RBASE_WR;
      end

      S_ACC_RBASE_WR: begin
        // Two behaviors sharing end-of-half transition logic:
        //   CAN_DUAL=1 (drain): entered from S_ACC_RACC_WR's last word.
        //     Port B commits the last new_rbase = old ^ new_racc_latched.
        //   CAN_DUAL=0 (iteration): entered from S_ACC_RBASE_RD.
        //     Both ports write rbase[col][acc_w] = old_rbase ^ racc.
        //     Iterates acc_w=0..CW-1.
        prg_owns_aes_o = !acc_half;

        if (CAN_DUAL) begin
          // DRAIN: PA idle, PB writes new_rbase[CW-1].
          var_b_addr_o  = phys_b(rbase_log_addr);
          var_b_data_o  = VAR_DATA_WIDTH_COMBINED'(64'(var_b_data_i) ^ new_racc_latched);
          var_b_wr_en_o = 1'b1;
        end else begin
          automatic logic [63:0] rbase_val = combine_ab();
          automatic logic [63:0] new_rbase = rbase_val ^ prg_word;

          var_a_addr_o  = phys_a(rbase_log_addr);
          var_b_addr_o  = phys_b(rbase_log_addr);
          var_a_data_o  = new_rbase[31:0];
          var_b_data_o  = new_rbase[63:32];
          var_a_wr_en_o = 1'b1;
          var_b_wr_en_o = 1'b1;
        end

        // Transition: CAN_DUAL=1 is always at the last word (DRAIN); SEC1
        // iterates until acc_w==CW-1.
        if (!CAN_DUAL && acc_w < CW - 1) begin
          next_acc_w = acc_w + 1;
          next_state = S_ACC_RBASE_RD;
        end else begin
          if (acc_half == 0) begin
            // Switch to right leaf. Right AES was already fired in S_PRG_WAIT.
            next_acc_half = 1;
            next_state = S_PRG_WAIT;
          end else begin
            next_pair_cnt = pair_cnt + 1;
            next_leaf_base = leaf_base + 2 * TAU;

            if (pair_cnt + 1 < N_PAIRS) begin
              next_acc_half = 0;
              get_next_leaf_o = 1;
              leaf_idx_o  = (GGM_TREE_DEPTH+1)'(leaf_base + 2 * TAU);
              leaf_idx2_o = (GGM_TREE_DEPTH+1)'(leaf_base + 2 * TAU + TAU);
              next_state = S_LEAF_WAIT;
            end else begin
              if (e_cnt + 1 < TAU) begin
                next_e_cnt = e_cnt + 1;
                next_e_base_r = e_base_r + VAR_ADDR_WIDTH_COMBINED'(KAPPA * CW);
                next_leaf_base = (GGM_TREE_DEPTH+2)'(e_cnt + 1);
                next_clr_cnt = '0;
                next_state = S_E_INIT;
              end else begin
                next_state = S_DONE;
              end
            end
          end
        end
      end

      // --------------------------------------------------------
      S_DONE: begin
        fsm_done_o = 1;
        next_state = S_IDLE;
      end

      default: next_state = S_IDLE;
    endcase
  end
  // Sequential logic

  always_ff @(posedge clk_i or posedge rst_i) begin
    if (rst_i) begin
      state            <= S_IDLE;
      e_cnt            <= '0;
      e_base_r         <= '0;
      pair_cnt         <= '0;
      leaf_base        <= '0;
      bit_offset_reg   <= '0;
      first_block_reg  <= '0;
      blocks_needed_reg <= 0;
      prg_data         <= '0;
      new_racc_latched <= '0;
      acc_w            <= '0;
      acc_half         <= 0;
      col_reg          <= '0;
      clr_cnt          <= '0;
      leaf_done_r      <= 0;
    end else begin
      state            <= next_state;
      e_cnt            <= next_e_cnt;
      e_base_r         <= next_e_base_r;
      pair_cnt         <= next_pair_cnt;
      leaf_base        <= next_leaf_base;
      bit_offset_reg   <= next_bit_offset_reg;
      first_block_reg  <= next_first_block_reg;
      blocks_needed_reg <= next_blocks_needed_reg;
      prg_data         <= next_prg_data;
      new_racc_latched <= next_new_racc_latched;
      acc_w            <= next_acc_w;
      acc_half         <= next_acc_half;
      col_reg          <= next_col_reg;
      clr_cnt          <= next_clr_cnt;
      leaf_done_r      <= next_leaf_done_r;
    end
  end

endmodule
