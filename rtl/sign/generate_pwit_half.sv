// SPDX-FileCopyrightText: 2026 Stef Halmans, Niklas Höher
// SPDX-License-Identifier: LicenseRef-RUB-SecEng

// generate_pwit_half
//
// GenerateV for HALF_POLY=1: the two-pass variant of generate_pwit_chunk.
//
// Extracts about half of the WIT_SIZE bits per pass (2 passes total). Each
// pass traverses all TAU x N_PAIRS leaf pairs, extracting HALF1_BITS or
// HALF2_BITS from each leaf's PRG stream and accumulating into r_acc /
// r_base in scratchpad.
//
// After each e-value's pairs are complete, a scatter phase moves the KAPPA
// r_base entries from column-wise into the row-wise V_in output region,
// freeing the r_base area for the next e-value. This scatter is the
// transpose of the HALF_POLY=1 configuration, interleaved with generation
// instead of running as a separate stage.
//
// BRAM layout (all 64-bit word addresses):
//   [0 .. HCW-1]                    racc (temp, reset per e)
//   [HCW .. ROFF-1]                 rbase[col][w] (temp, reset per e)
//   [ROFF .. ROFF+VIN_WORDS-1]      V_in[row][tw] (row-wise, cumulative)
//
// CAN_DUAL is always 1 for HALF_POLY builds (SEC1 upgrades to dual-pair).

module generate_pwit_half
import sdith_params_pkg::*;
import sdith_helpers_pkg::*;
(
    input  logic clk_i,
    input  logic rst_i,

    input  logic fsm_start_i,
    output logic fsm_done_o,
    input  logic pass_idx_i,

    output logic                     get_next_leaf_o,
    input  logic                     leaf_done_i,
    output logic [GGM_TREE_DEPTH:0]  leaf_idx_o,
    output logic [GGM_TREE_DEPTH:0]  leaf_idx2_o,
    input  logic [LAMBDA-1:0]        leaf_i,
    input  logic [LAMBDA-1:0]        leaf2_i,

    output logic [ENC_KEYSIZE-1:0]   aes0_key_o,
    output logic [ENC_BLOCKSIZE-1:0] aes0_plaintext_o,
    input  logic [ENC_BLOCKSIZE-1:0] aes0_ciphertext_i,
    output logic                     aes0_enable_o,
    input  logic                     aes0_ready_i,
    input  logic                     aes0_valid_i,

    output logic [ENC_KEYSIZE-1:0]   aes1_key_o,
    output logic [ENC_BLOCKSIZE-1:0] aes1_plaintext_o,
    input  logic [ENC_BLOCKSIZE-1:0] aes1_ciphertext_i,
    output logic                     aes1_enable_o,
    input  logic                     aes1_ready_i,
    input  logic                     aes1_valid_i,

    output logic                     prg_owns_aes_o,

    input  logic [VAR_DATA_WIDTH_COMBINED-1:0] var_a_data_i,
    output logic [VAR_DATA_WIDTH_COMBINED-1:0] var_a_data_o,
    output logic [VAR_ADDR_WIDTH_COMBINED-1:0] var_a_addr_o,
    output logic                               var_a_wr_en_o,
    input  logic [VAR_DATA_WIDTH_COMBINED-1:0] var_b_data_i,
    output logic [VAR_DATA_WIDTH_COMBINED-1:0] var_b_data_o,
    output logic [VAR_ADDR_WIDTH_COMBINED-1:0] var_b_addr_o,
    output logic                               var_b_wr_en_o
);

  // =========================================================================
  // Local parameters
  // =========================================================================

  localparam N_PAIRS  = N_CAP / 2;
  localparam HCW      = HALF_CW;
  localparam TXK      = TAU * KAPPA;
  localparam CW_R     = CW_R_HALF;
  localparam ROFF     = ROFF_HALF;
  localparam VIN_WORDS = VIN_WORDS_HALF;

  // Shared work bank: max(KAPPA, HCW) entries x 64 bits
  // Used as prg_data during pair processing, scatter_bank during scatter
  localparam BANK_ENTRIES = (KAPPA > HCW) ? KAPPA : HCW;

  localparam [7:0]  FIRST_BLOCK_P0 = PWIT_FIRST_BLOCK_P0[7:0];
  localparam [7:0]  FIRST_BLOCK_P1 = PWIT_FIRST_BLOCK_P1[7:0];
  localparam [1:0]  NUM_BLOCKS_P0  = PWIT_NUM_BLOCKS_P0[1:0];
  localparam [1:0]  NUM_BLOCKS_P1  = PWIT_NUM_BLOCKS_P1[1:0];
  localparam BO_W = $clog2(3 * ENC_BLOCKSIZE);
  localparam [BO_W-1:0] BIT_OFFSET_P0 = BO_W'(PWIT_BIT_OFFSET_P0);
  localparam [BO_W-1:0] BIT_OFFSET_P1 = BO_W'(PWIT_BIT_OFFSET_P1);
  localparam HALF_BITS_MAX = HCW * 64;
  localparam [HALF_BITS_MAX-1:0] MASK_P0 = (HALF_BITS_MAX'(1) << HALF1_BITS) - 1;
  localparam [HALF_BITS_MAX-1:0] MASK_P1 = (HALF_BITS_MAX'(1) << HALF2_BITS) - 1;

  // =========================================================================
  // Pass-dependent wires
  // =========================================================================

  wire [7:0]      first_block = pass_idx_i ? FIRST_BLOCK_P1 : FIRST_BLOCK_P0;
  wire [1:0]      num_blocks  = pass_idx_i ? NUM_BLOCKS_P1  : NUM_BLOCKS_P0;
  wire [HALF_BITS_MAX-1:0] pass_mask = pass_idx_i ? MASK_P1 : MASK_P0;

  // =========================================================================
  // FSM states
  // =========================================================================

  typedef enum logic [3:0] {
    S_IDLE,
    S_INIT,
    S_VIN_CLEAR,
    S_E_INIT,
    S_LEAF_WAIT,
    S_PRG_FIRE,
    S_PRG_WAIT,
    S_PRG_WAIT3,
    S_ACC_RACC_RD,
    S_ACC_RACC_WR,
    S_ACC_RBASE_WR,
    S_SCATTER_LOAD,
    S_SCATTER_RD,
    S_SCATTER_WR,
    S_DONE
  } state_e;

  state_e state, next_state;

  // =========================================================================
  // Registers
  // =========================================================================

  logic [$clog2(TAU)-1:0]    e_cnt,    next_e_cnt;
  logic [$clog2(N_PAIRS):0]  pair_cnt, next_pair_cnt;
  logic [GGM_TREE_DEPTH+1:0] leaf_base, next_leaf_base;
  logic [ENC_BLOCKSIZE-1:0]  cipher0_saved, next_cipher0_saved;
  logic [63:0]               new_racc_latched, next_new_racc_latched;
  logic [$clog2(HCW):0]     acc_w, next_acc_w;
  logic                      acc_half, next_acc_half;
  logic [$clog2(KAPPA)-1:0]  col_reg, next_col_reg;
  logic [$clog2(VIN_WORDS+1)-1:0] clr_cnt, next_clr_cnt;
  logic leaf_done_r, next_leaf_done_r;

  // Shared work bank (prg_data during pairs, scatter_bank during scatter)
  logic [63:0] work_bank [0:BANK_ENTRIES-1];

  // Scatter
  logic [$clog2(KAPPA+1)-1:0] scat_idx, next_scat_idx;
  logic [$clog2(KAPPA+1)-1:0] scat_issued_idx;
  logic [5:0]  scat_row, next_scat_row;
  logic        scat_hi,  next_scat_hi;
  logic        scat_port_sel, next_scat_port_sel;

  // =========================================================================
  // PRG extraction
  // =========================================================================

  wire [ENC_BLOCKSIZE-1:0] cipher0_swapped, cipher1_swapped;
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

  // PRG concatenation and extraction.
  // Constant-index part-selects (zero LUTs - pure wire routing) with a
  // 2:1 mux on pass_idx_i, instead of variable-index barrel shifters.
  localparam CONCAT_W_RAW = 3 * ENC_BLOCKSIZE;
  localparam MAX_OFF = (BIT_OFFSET_P0 > BIT_OFFSET_P1) ? BIT_OFFSET_P0 : BIT_OFFSET_P1;
  localparam CONCAT_W = (MAX_OFF + HALF_BITS_MAX > CONCAT_W_RAW)
                       ? MAX_OFF + HALF_BITS_MAX : CONCAT_W_RAW;
  wire [CONCAT_W-1:0] prg_concat_2 = CONCAT_W'({{ENC_BLOCKSIZE{1'b0}}, cipher1_swapped, cipher0_swapped});
  wire [CONCAT_W-1:0] prg_concat_3 = CONCAT_W'({cipher0_swapped, cipher1_swapped, cipher0_saved});

  wire [HALF_BITS_MAX-1:0] ext2_p0 = prg_concat_2[BIT_OFFSET_P0 +: HALF_BITS_MAX];
  wire [HALF_BITS_MAX-1:0] ext2_p1 = prg_concat_2[BIT_OFFSET_P1 +: HALF_BITS_MAX];
  wire [HALF_BITS_MAX-1:0] ext3_p0 = prg_concat_3[BIT_OFFSET_P0 +: HALF_BITS_MAX];
  wire [HALF_BITS_MAX-1:0] ext3_p1 = prg_concat_3[BIT_OFFSET_P1 +: HALF_BITS_MAX];

  wire [HALF_BITS_MAX-1:0] prg_extract_2blk = pass_idx_i ? ext2_p1 : ext2_p0;
  wire [HALF_BITS_MAX-1:0] prg_extract_3blk = pass_idx_i ? ext3_p1 : ext3_p0;

  wire [HALF_BITS_MAX-1:0] prg_masked_2 = prg_extract_2blk & pass_mask;
  wire [HALF_BITS_MAX-1:0] prg_masked_3 = prg_extract_3blk & pass_mask;

  wire [ENC_KEYSIZE-1:0] aes_key_cur;
  generate
    if (SECURITY_LEVEL == 3) begin : gen_cat3_key
      assign aes_key_cur = acc_half ? {64'b0, leaf2_i} : {64'b0, leaf_i};
    end else begin : gen_other_key
      assign aes_key_cur = acc_half ? ENC_KEYSIZE'(leaf2_i) : ENC_KEYSIZE'(leaf_i);
    end
  endgenerate

  wire [ENC_KEYSIZE-1:0] aes_key_right;
  generate
    if (SECURITY_LEVEL == 3) begin : gen_cat3_key_r
      assign aes_key_right = {64'b0, leaf2_i};
    end else begin : gen_other_key_r
      assign aes_key_right = ENC_KEYSIZE'(leaf2_i);
    end
  endgenerate

  wire [ENC_BLOCKSIZE-1:0] plaintext_blk0 = {<<8{ENC_BLOCKSIZE'(first_block)}};
  wire [ENC_BLOCKSIZE-1:0] plaintext_blk1 = {<<8{ENC_BLOCKSIZE'(first_block + 8'd1)}};
  wire [ENC_BLOCKSIZE-1:0] plaintext_blk2 = {<<8{ENC_BLOCKSIZE'(first_block + 8'd2)}};

  // =========================================================================
  // BRAM address helpers - accumulation
  // =========================================================================

  wire [VAR_ADDR_WIDTH_COMBINED-1:0] racc_log_addr =
      VAR_ADDR_WIDTH_COMBINED'(acc_w);

  wire [VAR_ADDR_WIDTH_COMBINED-1:0] rbase_log_addr =
      VAR_ADDR_WIDTH_COMBINED'(HCW + col_reg * HCW + acc_w);
  wire [VAR_ADDR_WIDTH_COMBINED-1:0] rbase_log_addr_prev =
      VAR_ADDR_WIDTH_COMBINED'(HCW + col_reg * HCW + (acc_w - 1));

  wire [63:0] prg_word = work_bank[acc_w];

  // =========================================================================
  // Scatter helpers
  // =========================================================================

  // Extract bit scat_row from each work_bank entry (used as scatter_bank)
  wire [KAPPA-1:0] scat_extracted;
  generate
    for (genvar g = 0; g < KAPPA; g++) begin : gen_scat_ext
      assign scat_extracted[g] = work_bank[g][scat_row];
    end
  endgenerate

  wire [15:0] e_kappa_prod = 16'(e_cnt) * 16'(KAPPA);
  wire [$clog2(CW_R+1)-1:0] scat_tw_lo = ($clog2(CW_R+1))'(e_kappa_prod >> 6);
  wire [5:0] scat_shift = e_kappa_prod[5:0];
  wire scat_crosses = (scat_shift + KAPPA > 64);

  wire [63:0] scat_lo_slice = 64'(scat_extracted) << scat_shift;
  wire [63:0] scat_hi_slice = (scat_shift != 0)
                             ? (64'(scat_extracted) >> (6'd64 - scat_shift))
                             : 64'd0;
  wire [63:0] scat_merge_val = scat_hi ? scat_hi_slice : scat_lo_slice;

  wire [VAR_ADDR_WIDTH_COMBINED-1:0] scat_vin_addr =
      VAR_ADDR_WIDTH_COMBINED'(ROFF + (acc_w * 64 + scat_row) * CW_R
                               + scat_tw_lo + scat_hi);

  // Odd-BRAM var_bram configs (Case 3/5) have a single-port upper region
  // that cannot serve independent port-0 and port-1 accesses simultaneously.
  // When the scatter write address lands there, skip dual-port pipelining
  // and fall back to S_SCATTER_RD for a serialized read.
  localparam int DUAL_PORT_LIMIT =
      (VAR_NUM_BRAMS_COMBINED / 2) * BRAM_TDP_DEPTH_32;
  localparam int HAS_UPPER_SP =
      (VAR_NUM_BRAMS_COMBINED % 2 == 1 && VAR_DATA_WIDTH_COMBINED >= 64) ? 1 : 0;
  wire scat_in_upper = HAS_UPPER_SP != 0 &&
      (scat_vin_addr >= VAR_ADDR_WIDTH_COMBINED'(DUAL_PORT_LIMIT));

  wire [VAR_ADDR_WIDTH_COMBINED-1:0] scat_rbase_addr =
      VAR_ADDR_WIDTH_COMBINED'(HCW + scat_idx * HCW + acc_w);

  wire [63:0] scat_rd_data = scat_port_sel ? 64'(var_b_data_i) : 64'(var_a_data_i);

  // =========================================================================
  // FSM combinational logic
  // =========================================================================

  always_comb begin
    next_state          = state;
    next_e_cnt          = e_cnt;
    next_pair_cnt       = pair_cnt;
    next_leaf_base      = leaf_base;
    next_cipher0_saved  = cipher0_saved;
    next_new_racc_latched = new_racc_latched;
    next_acc_w          = acc_w;
    next_acc_half       = acc_half;
    next_col_reg        = col_reg;
    next_clr_cnt        = clr_cnt;
    next_leaf_done_r    = leaf_done_r || (leaf_done_i && state == S_E_INIT);
    next_scat_idx       = scat_idx;
    next_scat_row       = scat_row;
    next_scat_hi        = scat_hi;
    next_scat_port_sel  = scat_port_sel;

    fsm_done_o      = 0;
    get_next_leaf_o = 0;

    if (acc_half && pair_cnt + 1 < N_PAIRS) begin
      leaf_idx_o  = (GGM_TREE_DEPTH+1)'(leaf_base + 2 * TAU);
      leaf_idx2_o = (GGM_TREE_DEPTH+1)'(leaf_base + 2 * TAU + TAU);
    end else begin
      leaf_idx_o  = (GGM_TREE_DEPTH+1)'(leaf_base);
      leaf_idx2_o = (GGM_TREE_DEPTH+1)'(leaf_base + TAU);
    end

    aes0_key_o       = '0;
    aes0_plaintext_o = '0;
    aes0_enable_o    = 0;
    aes1_key_o       = '0;
    aes1_plaintext_o = '0;
    aes1_enable_o    = 0;
    prg_owns_aes_o   = 0;
    var_a_data_o     = '0;
    var_a_addr_o     = '0;
    var_a_wr_en_o    = 0;
    var_b_data_o     = '0;
    var_b_addr_o     = '0;
    var_b_wr_en_o    = 0;

    case (state)

      S_IDLE: begin
        if (fsm_start_i)
          next_state = S_INIT;
      end

      S_INIT: begin
        next_e_cnt     = '0;
        next_leaf_base = '0;
        next_clr_cnt   = '0;
        next_state     = S_VIN_CLEAR;
      end

      // -- Clear V_in ----------------------------------------------
      S_VIN_CLEAR: begin
        if (clr_cnt < VIN_WORDS) begin
          automatic logic [VAR_ADDR_WIDTH_COMBINED-1:0] la;
          la = VAR_ADDR_WIDTH_COMBINED'(ROFF + clr_cnt);
          var_a_addr_o  = phys_a(la);
          var_a_data_o  = '0;
          var_a_wr_en_o = 1;
          next_clr_cnt  = clr_cnt + 1;
        end else begin
          next_clr_cnt = '0;
          next_state   = S_E_INIT;
        end
      end

      // -- Clear racc + rbase, overlap first leaf fetch ------------
      // redundant pulse for e>0; leaf ignores it while busy
      S_E_INIT: begin
        automatic int total_clr = (KAPPA + 1) * HCW;

        if (clr_cnt == 0)
          get_next_leaf_o = 1;

        if (clr_cnt < total_clr) begin
          var_a_addr_o  = phys_a(VAR_ADDR_WIDTH_COMBINED'(clr_cnt));
          var_a_data_o  = '0;
          var_a_wr_en_o = 1;
          next_clr_cnt  = clr_cnt + 1;
        end else begin
          next_pair_cnt = '0;
          next_acc_half = 0;
          next_state    = S_LEAF_WAIT;
        end
      end

      S_LEAF_WAIT: begin
        leaf_idx_o  = (GGM_TREE_DEPTH+1)'(leaf_base);
        leaf_idx2_o = (GGM_TREE_DEPTH+1)'(leaf_base + TAU);
        if (leaf_done_i || leaf_done_r) begin
          next_leaf_done_r = 0;
          next_acc_half = 0;
          next_state    = S_PRG_FIRE;
        end
      end

      S_PRG_FIRE: begin
        prg_owns_aes_o  = 1;
        aes0_key_o       = aes_key_cur;
        aes0_plaintext_o = plaintext_blk0;
        aes0_enable_o    = 1;
        aes1_key_o       = aes_key_cur;
        aes1_plaintext_o = plaintext_blk1;
        aes1_enable_o    = 1;
        next_state       = S_PRG_WAIT;
      end

      S_PRG_WAIT: begin
        prg_owns_aes_o = 1;
        if (aes0_valid_i && aes1_valid_i) begin
          if (num_blocks == 2'd2) begin
            // 2-block: extract and load work_bank in sequential block
            next_acc_w = '0;
            if (!acc_half) begin
              aes0_key_o       = aes_key_right;
              aes0_plaintext_o = plaintext_blk0;
              aes0_enable_o    = 1;
              aes1_key_o       = aes_key_right;
              aes1_plaintext_o = plaintext_blk1;
              aes1_enable_o    = 1;
            end
            next_state = S_ACC_RACC_RD;
          end else begin
            next_cipher0_saved = cipher0_swapped;
            aes0_key_o         = aes_key_cur;
            aes0_plaintext_o   = plaintext_blk2;
            aes0_enable_o      = 1;
            next_state         = S_PRG_WAIT3;
          end
        end
      end

      S_PRG_WAIT3: begin
        prg_owns_aes_o = 1;
        if (aes0_valid_i) begin
          // 3-block: extract and load work_bank in sequential block
          next_acc_w = '0;
          if (!acc_half) begin
            aes0_key_o       = aes_key_right;
            aes0_plaintext_o = plaintext_blk0;
            aes0_enable_o    = 1;
            aes1_key_o       = aes_key_right;
            aes1_plaintext_o = plaintext_blk1;
            aes1_enable_o    = 1;
          end
          next_state = S_ACC_RACC_RD;
        end
      end

      // -- Accumulation: r_acc ^= prg_data, then r_base[col] ^= r_acc
      // Dual-port pipeline: PA reads/writes racc, PB reads/writes rbase
      // in the same cycle pair. Rbase write is one word behind racc.
      S_ACC_RACC_RD: begin
        var_a_addr_o = phys_a(racc_log_addr);
        prg_owns_aes_o = !acc_half;

        if (acc_w == 0) begin
          automatic logic [$clog2(N_CAP):0] seq_pos;
          seq_pos = 2 * pair_cnt + acc_half;
          if (seq_pos + 1 == N_CAP)
            next_col_reg = ($clog2(KAPPA))'(KAPPA - 1);
          else
            next_col_reg = ctz_func(seq_pos + 1);
        end

        if (acc_w != 0) begin
          var_b_addr_o  = phys_b(rbase_log_addr_prev);
          var_b_data_o  = VAR_DATA_WIDTH_COMBINED'(64'(var_b_data_i) ^ new_racc_latched);
          var_b_wr_en_o = 1'b1;
        end

        if (acc_half && acc_w == 0 && pair_cnt + 1 < N_PAIRS) begin
          get_next_leaf_o = 1;
          leaf_idx_o  = (GGM_TREE_DEPTH+1)'(leaf_base + 2 * TAU);
          leaf_idx2_o = (GGM_TREE_DEPTH+1)'(leaf_base + 2 * TAU + TAU);
        end

        next_state = S_ACC_RACC_WR;
      end

      S_ACC_RACC_WR: begin
        automatic logic [63:0] old_racc = 64'(var_a_data_i);
        automatic logic [63:0] new_racc = old_racc ^ prg_word;
        prg_owns_aes_o = !acc_half;

        var_a_addr_o  = phys_a(racc_log_addr);
        var_a_data_o  = VAR_DATA_WIDTH_COMBINED'(new_racc);
        var_a_wr_en_o = 1'b1;

        var_b_addr_o          = phys_b(rbase_log_addr);
        next_new_racc_latched = new_racc;

        if (acc_w < HCW - 1) begin
          next_acc_w = acc_w + 1;
          next_state = S_ACC_RACC_RD;
        end else begin
          // Drain: write last rbase word via S_ACC_RBASE_WR
          next_state = S_ACC_RBASE_WR;
        end
      end

      // Drain: write last rbase word from port B data
      S_ACC_RBASE_WR: begin
        prg_owns_aes_o = !acc_half;
        var_b_addr_o  = phys_b(rbase_log_addr);
        var_b_data_o  = VAR_DATA_WIDTH_COMBINED'(64'(var_b_data_i) ^ new_racc_latched);
        var_b_wr_en_o = 1'b1;

        if (acc_half == 0) begin
          next_acc_half = 1;
          next_state    = S_PRG_WAIT;
        end else begin
          next_pair_cnt  = pair_cnt + 1;
          next_leaf_base = leaf_base + 2 * TAU;

          if (pair_cnt + 1 < N_PAIRS) begin
            next_acc_half = 0;
            get_next_leaf_o = 1;
            leaf_idx_o  = (GGM_TREE_DEPTH+1)'(leaf_base + 2 * TAU);
            leaf_idx2_o = (GGM_TREE_DEPTH+1)'(leaf_base + 2 * TAU + TAU);
            next_state  = S_LEAF_WAIT;
          end else begin
            // All pairs done for e_cnt -> scatter
            next_acc_w        = '0;
            next_scat_idx     = '0;
            next_scat_hi      = 0;
            next_scat_port_sel = 0;
            next_state        = S_SCATTER_LOAD;
          end
        end
      end

      // -- Scatter: load rbase into work_bank ---------------------
      // Fire next e-value's leaf fetch at start of scatter (acc_w==0,
      // scat_idx==0). Leaf cache uses separate BRAM + AES - no conflict.
      S_SCATTER_LOAD: begin
        var_a_addr_o = phys_a(scat_rbase_addr);

        if (acc_w == 0 && scat_idx == 0 && e_cnt + 1 < TAU) begin
          get_next_leaf_o = 1;
          leaf_idx_o  = (GGM_TREE_DEPTH+1)'(e_cnt + 1);
          leaf_idx2_o = (GGM_TREE_DEPTH+1)'(e_cnt + 1 + TAU);
        end

        if (scat_idx + 1 < KAPPA) begin
          next_scat_idx = scat_idx + 1;
          next_state    = S_SCATTER_LOAD;
        end else begin
          next_scat_row      = '0;
          next_scat_hi       = 0;
          next_scat_port_sel = 0;
          next_state         = S_SCATTER_RD;
        end
      end

      // -- Scatter: RMW read V_in word ----------------------------
      // Dual-port pipeline: in S_SCATTER_WR, the write goes to one port
      // while the read for the next row issues on the other port.
      // scat_port_sel tracks which port has the read data.
      S_SCATTER_RD: begin
        // Initial read always on port A
        var_a_addr_o = phys_a(scat_vin_addr);
        next_scat_port_sel = 0;
        next_state = S_SCATTER_WR;
      end

      // -- Scatter: merge + write, pipeline next read -------------
      S_SCATTER_WR: begin
        automatic logic [63:0] old_vin = scat_rd_data;
        automatic logic [63:0] new_vin = old_vin | scat_merge_val;

        // Write on the port that has the old data
        if (!scat_port_sel) begin
          var_a_addr_o  = phys_a(scat_vin_addr);
          var_a_data_o  = VAR_DATA_WIDTH_COMBINED'(new_vin);
          var_a_wr_en_o = 1'b1;
        end else begin
          var_b_addr_o  = phys_b(scat_vin_addr);
          var_b_data_o  = VAR_DATA_WIDTH_COMBINED'(new_vin);
          var_b_wr_en_o = 1'b1;
        end

        if (scat_crosses && !scat_hi) begin
          next_scat_hi = 1;
          if (scat_in_upper) begin
            next_state = S_SCATTER_RD;
          end else begin
            if (!scat_port_sel) begin
              var_b_addr_o = phys_b(VAR_ADDR_WIDTH_COMBINED'(
                  ROFF + (acc_w * 64 + scat_row) * CW_R + scat_tw_lo + 1));
              next_scat_port_sel = 1;
            end else begin
              var_a_addr_o = phys_a(VAR_ADDR_WIDTH_COMBINED'(
                  ROFF + (acc_w * 64 + scat_row) * CW_R + scat_tw_lo + 1));
              next_scat_port_sel = 0;
            end
            next_state = S_SCATTER_WR;
          end
        end else if (scat_row < 6'd63) begin
          next_scat_hi  = 0;
          next_scat_row = scat_row + 1;
          if (scat_in_upper) begin
            next_state = S_SCATTER_RD;
          end else begin
            if (!scat_port_sel) begin
              var_b_addr_o = phys_b(VAR_ADDR_WIDTH_COMBINED'(
                  ROFF + (acc_w * 64 + scat_row + 1) * CW_R + scat_tw_lo));
              next_scat_port_sel = 1;
            end else begin
              var_a_addr_o = phys_a(VAR_ADDR_WIDTH_COMBINED'(
                  ROFF + (acc_w * 64 + scat_row + 1) * CW_R + scat_tw_lo));
              next_scat_port_sel = 0;
            end
            next_state = S_SCATTER_WR;
          end
        end else begin
          // Word-group done
          next_scat_hi = 0;
          if (acc_w + 1 < HCW) begin
            next_acc_w    = acc_w + 1;
            next_scat_idx = '0;
            next_state    = S_SCATTER_LOAD;
          end else begin
            if (e_cnt + 1 < TAU) begin
              next_e_cnt     = e_cnt + 1;
              next_leaf_base = (GGM_TREE_DEPTH+2)'(e_cnt + 1);
              next_clr_cnt   = '0;
              next_state     = S_E_INIT;
            end else begin
              next_state = S_DONE;
            end
          end
        end
      end

      S_DONE: begin
        fsm_done_o = 1;
        next_state = S_IDLE;
      end

      default: next_state = S_IDLE;
    endcase
  end

  // =========================================================================
  // Sequential logic
  // =========================================================================

  state_e state_d;

  always_ff @(posedge clk_i or posedge rst_i) begin
    if (rst_i) begin
      state            <= S_IDLE;
      state_d          <= S_IDLE;
      e_cnt            <= '0;
      pair_cnt         <= '0;
      leaf_base        <= '0;
      cipher0_saved    <= '0;
      new_racc_latched <= '0;
      acc_w            <= '0;
      acc_half         <= 0;
      col_reg          <= '0;
      clr_cnt          <= '0;
      scat_idx         <= '0;
      scat_issued_idx  <= '0;
      scat_row         <= '0;
      scat_hi          <= 0;
      scat_port_sel    <= 0;
      leaf_done_r      <= 0;
      for (int i = 0; i < BANK_ENTRIES; i++) work_bank[i] <= '0;
    end else begin
      state            <= next_state;
      state_d          <= state;
      e_cnt            <= next_e_cnt;
      pair_cnt         <= next_pair_cnt;
      leaf_base        <= next_leaf_base;
      cipher0_saved    <= next_cipher0_saved;
      new_racc_latched <= next_new_racc_latched;
      acc_w            <= next_acc_w;
      acc_half         <= next_acc_half;
      col_reg          <= next_col_reg;
      clr_cnt          <= next_clr_cnt;
      leaf_done_r      <= next_leaf_done_r;
      scat_idx         <= next_scat_idx;
      scat_row         <= next_scat_row;
      scat_hi          <= next_scat_hi;
      scat_port_sel    <= next_scat_port_sel;
      // The scatter merge value stays combinational: work_bank can be
      // written in the same cycle, so pre-registering it would race.
      scat_issued_idx  <= scat_idx;

      // Scatter bank capture from BRAM
      if (state_d == S_SCATTER_LOAD)
        work_bank[scat_issued_idx] <= 64'(var_a_data_i);

      // PRG extraction -> load work_bank with masked PRG words
      if (state == S_PRG_WAIT && aes0_valid_i && aes1_valid_i && num_blocks == 2'd2) begin
        for (int i = 0; i < HCW; i++)
          work_bank[i] <= prg_masked_2[i*64 +: 64];
      end
      if (state == S_PRG_WAIT3 && aes0_valid_i) begin
        for (int i = 0; i < HCW; i++)
          work_bank[i] <= prg_masked_3[i*64 +: 64];
      end

    end
  end

endmodule
