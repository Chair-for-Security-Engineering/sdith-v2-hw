// SPDX-FileCopyrightText: 2026 Stef Halmans, Niklas Höher
// SPDX-License-Identifier: LicenseRef-RUB-SecEng

// transpose_pwit - in-place bit-level transpose of the V matrix (TransposeV)
//
// Converts column-wise V[flat_idx][w] in scratchpad to row-wise
// V_row[row][tw]. Needed because V is PRG-sampled column-wise but
// consumed row-wise by process_pwit. HALF_POLY=0 only.
//
// The V matrix is tiled into CW x CW_R blocks of 64x64 bits.
// For each off-diagonal pair {(i,j),(j,i)}: the blocks swap content
// with bit-level transpose applied. Block (i,j) gets bit_transpose
// of original block (j,i) and vice versa. Source and dest addresses
// are at different block locations, so no collision.
//
// For diagonal blocks (i,i): copy to scratch, then transpose from
// scratch back to V. No collision (reads scratch, writes V).
//
// Uses 8-word register bank (512 FFs) + 64-word BRAM scratch.

module transpose_pwit
import sdith_params_pkg::*;
import sdith_helpers_pkg::*;
(
    input  logic clk_i,
    input  logic rst_i,

    input  logic fsm_start_i,
    output logic fsm_done_o,

    input  logic [VAR_DATA_WIDTH_COMBINED-1:0] var_a_data_i,
    output logic [VAR_DATA_WIDTH_COMBINED-1:0] var_a_data_o,
    output logic [VAR_ADDR_WIDTH_COMBINED-1:0] var_a_addr_o,
    output logic                               var_a_wr_en_o,
    input  logic [VAR_DATA_WIDTH_COMBINED-1:0] var_b_data_i,
    output logic [VAR_DATA_WIDTH_COMBINED-1:0] var_b_data_o,
    output logic [VAR_ADDR_WIDTH_COMBINED-1:0] var_b_addr_o,
    output logic                               var_b_wr_en_o
);

  localparam CAN_DUAL    = CAN_DUAL_COMBINED;
  localparam TXK         = TAU * KAPPA;
  localparam CW_R        = (TXK + 63) / 64;

  // Mode-dependent dimensions: chunk (HALF_POLY=0) vs half-poly (HALF_POLY=1)
  localparam CW          = (HALF_POLY == 0) ? CHUNK_WORDS : HALF_CW;
  localparam V_OFF       = (HALF_POLY == 0) ? PWIT_V_OFFSET : HALF_CW;
  localparam NROWS       = (HALF_POLY == 0) ? LAMBDA : HALF_CW * 64;
  localparam V_TOTAL     = (HALF_POLY == 0) ? PWIT_V_WORDS : PWIT_V_WORDS_HALF;
  localparam ROWWISE_WORDS = NROWS * CW_R;
  localparam SCRATCH_OFF = V_OFF + (V_TOTAL > ROWWISE_WORDS ? V_TOTAL : ROWWISE_WORDS);
  localparam LAST_BLK    = TXK - (CW_R - 1) * 64;

  logic [63:0] reg_bank [0:7];

  function automatic [63:0] combine_ab();
    if (CAN_DUAL) return 64'(var_a_data_i);
    else          return {var_b_data_i, var_a_data_i};
  endfunction

  typedef enum logic [3:0] {
    S_IDLE,
    S_PAIR_INIT,
    S_COPY_RD,
    S_COPY_CAP,
    S_SUB_INIT,
    S_LOAD_RD,
    S_LOAD_CAP,
    S_WR_DST,
    S_RMW_RD,
    S_RMW_CAP,
    S_NEXT_SUB,
    S_NEXT_HALF,
    S_NEXT_PAIR,
    S_DONE
  } state_e;

  state_e state, nstate;

  // Pair iteration: (blk_i, blk_j) with blk_i <= blk_j
  logic [$clog2(CW_R+1)-1:0] blk_i, n_blk_i;
  logic [$clog2(CW_R+1)-1:0] blk_j, n_blk_j;

  // Within a pair, half=0 processes (j,i)->(i,j), half=1 processes scratch->(j,i)
  // For diagonal: only half=0 (scratch->(i,i))
  logic                       half,   n_half;
  logic [2:0]                 sub_k,  n_sub_k;
  logic [3:0]                 f_cnt,  n_f_cnt;
  logic [5:0]                 r_cnt,  n_r_cnt;
  logic [6:0]                 cp_cnt, n_cp_cnt;

  // Current source and dest block coordinates depend on half:
  // half=0: source block = (blk_j, blk_i), dest block = (blk_i, blk_j)
  // half=1: source = scratch, dest block = (blk_j, blk_i)
  // diagonal: source = scratch, dest block = (blk_i, blk_i)
  wire is_diag = (blk_i == blk_j);

  wire [$clog2(CW_R+1)-1:0] src_tw = is_diag ? blk_i : (half ? blk_i : blk_j);
  wire [$clog2(CW+1)-1:0]   src_w  = is_diag ? ($clog2(CW+1))'(blk_i)
                                              : (half ? ($clog2(CW+1))'(blk_j)
                                                      : ($clog2(CW+1))'(blk_i));
  wire [$clog2(CW_R+1)-1:0] dst_tw = half ? blk_i : blk_j;
  wire [$clog2(CW+1)-1:0]   dst_w  = half ? ($clog2(CW+1))'(blk_j) : ($clog2(CW+1))'(blk_i);

  // Number of entries in source block column
  wire [6:0] src_entries = (src_tw == ($clog2(CW_R+1))'(CW_R - 1)) ? LAST_BLK[6:0] : 7'd64;
  wire [6:0] dst_entries = 7'd64; // dest block rows are always 0..63

  wire [6:0] sub_start = {4'b0, sub_k} * 8;
  wire [3:0] sub_ent   = (sub_start + 8 <= src_entries) ? 4'd8
                        : (sub_start < src_entries)      ? src_entries[3:0] - sub_start[3:0]
                        : 4'd0;

  wire [VAR_ADDR_WIDTH_COMBINED-1:0] v_src_addr =
      VAR_ADDR_WIDTH_COMBINED'(V_OFF + (64 * src_tw + sub_start + f_cnt) * CW + src_w);

  // Scratch address for loading (used when half=1 or diagonal)
  wire [VAR_ADDR_WIDTH_COMBINED-1:0] scratch_load_addr =
      VAR_ADDR_WIDTH_COMBINED'(SCRATCH_OFF + sub_start + f_cnt);

  // Source address: V for half=0 off-diag, scratch for half=1 or diagonal
  wire use_scratch = half || is_diag;
  wire [VAR_ADDR_WIDTH_COMBINED-1:0] load_addr = use_scratch ? scratch_load_addr : v_src_addr;

  wire [VAR_ADDR_WIDTH_COMBINED-1:0] v_dst_addr =
      VAR_ADDR_WIDTH_COMBINED'(V_OFF + (64 * dst_w + r_cnt) * CW_R + dst_tw);

  // Copy addresses: always copy block (blk_i, blk_j) to scratch
  wire [VAR_ADDR_WIDTH_COMBINED-1:0] copy_src =
      VAR_ADDR_WIDTH_COMBINED'(V_OFF + (64 * blk_i + cp_cnt) * CW + blk_j);
  wire [VAR_ADDR_WIDTH_COMBINED-1:0] copy_dst =
      VAR_ADDR_WIDTH_COMBINED'(SCRATCH_OFF + cp_cnt);

  // Bit extraction
  wire [7:0] extracted;
  generate
    for (genvar g = 0; g < 8; g++) begin : gen_ext
      assign extracted[g] = reg_bank[g][r_cnt];
    end
  endgenerate

  wire [63:0] slice_pos  = 64'(extracted) << ({3'b0, sub_k} * 8);
  wire [63:0] slice_mask = 64'hFF << ({3'b0, sub_k} * 8);
  wire [63:0] old_word   = combine_ab();
  wire [63:0] merged     = (old_word & ~slice_mask) | slice_pos;

  // last block column is partial
  wire [6:0] copy_entries = (blk_i == ($clog2(CW_R+1))'(CW_R - 1)) ? LAST_BLK[6:0] : 7'd64;

  always_comb begin
    nstate   = state;
    n_blk_i  = blk_i;
    n_blk_j  = blk_j;
    n_half   = half;
    n_sub_k  = sub_k;
    n_f_cnt  = f_cnt;
    n_r_cnt  = r_cnt;
    n_cp_cnt = cp_cnt;

    fsm_done_o    = 1'b0;
    var_a_data_o  = '0;
    var_a_addr_o  = '0;
    var_a_wr_en_o = 1'b0;
    var_b_data_o  = '0;
    var_b_addr_o  = '0;
    var_b_wr_en_o = 1'b0;

    case (state)
      S_IDLE: begin
        if (fsm_start_i) begin
          n_blk_i = '0;
          n_blk_j = '0;
          nstate  = S_PAIR_INIT;
        end
      end

      // -- Pair init: copy block (i,j) to scratch ------
      S_PAIR_INIT: begin
        n_cp_cnt = '0;
        nstate   = S_COPY_RD;
      end

      S_COPY_RD: begin
        var_a_addr_o = phys_a(copy_src);
        if (!CAN_DUAL) var_b_addr_o = phys_b(copy_src);
        nstate = S_COPY_CAP;
      end

      S_COPY_CAP: begin
        var_a_addr_o  = phys_a(copy_dst);
        var_a_data_o  = CAN_DUAL ? VAR_DATA_WIDTH_COMBINED'(combine_ab()) : var_a_data_i;
        var_a_wr_en_o = 1'b1;
        if (!CAN_DUAL) begin
          var_b_addr_o  = phys_b(copy_dst);
          var_b_data_o  = var_b_data_i;
          var_b_wr_en_o = 1'b1;
        end
        if (cp_cnt + 1 < copy_entries) begin
          n_cp_cnt = cp_cnt + 1;
          nstate   = S_COPY_RD;
        end else begin
          // Copy done. For off-diag: half=0 processes (j,i)->(i,j) from V.
          // For diagonal: half=0 processes scratch->(i,i).
          n_half  = 1'b0;
          nstate  = S_SUB_INIT;
        end
      end

      // -- Start sub-bank processing -------------------
      S_SUB_INIT: begin
        n_sub_k = '0;
        n_f_cnt = '0;
        nstate  = S_LOAD_RD;
      end

      // -- Load source words into register bank --------
      S_LOAD_RD: begin
        var_a_addr_o = phys_a(load_addr);
        if (!CAN_DUAL) var_b_addr_o = phys_b(load_addr);
        nstate = S_LOAD_CAP;
      end

      S_LOAD_CAP: begin
        if (f_cnt + 1 < sub_ent) begin
          n_f_cnt = f_cnt + 1;
          var_a_addr_o = phys_a(use_scratch
              ? VAR_ADDR_WIDTH_COMBINED'(SCRATCH_OFF + sub_start + f_cnt + 1)
              : VAR_ADDR_WIDTH_COMBINED'(V_OFF + (64 * src_tw + sub_start + f_cnt + 1) * CW + src_w));
          if (!CAN_DUAL) var_b_addr_o = phys_b(use_scratch
              ? VAR_ADDR_WIDTH_COMBINED'(SCRATCH_OFF + sub_start + f_cnt + 1)
              : VAR_ADDR_WIDTH_COMBINED'(V_OFF + (64 * src_tw + sub_start + f_cnt + 1) * CW + src_w));
          nstate = S_LOAD_CAP;
        end else begin
          n_r_cnt = '0;
          nstate  = (sub_k == 3'd0) ? S_WR_DST : S_RMW_RD;
        end
      end

      // -- Write-only (sub_k=0) ------------------------
      S_WR_DST: begin
        var_a_addr_o  = phys_a(v_dst_addr);
        var_a_data_o  = split_a(slice_pos);
        var_a_wr_en_o = 1'b1;
        if (!CAN_DUAL) begin
          var_b_addr_o  = phys_b(v_dst_addr);
          var_b_data_o  = split_b(slice_pos);
          var_b_wr_en_o = 1'b1;
        end
        if (r_cnt < 6'd63) n_r_cnt = r_cnt + 1;
        else                nstate  = S_NEXT_SUB;
      end

      // -- RMW read ------------------------------------
      S_RMW_RD: begin
        var_a_addr_o = phys_a(v_dst_addr);
        if (!CAN_DUAL) var_b_addr_o = phys_b(v_dst_addr);
        nstate = S_RMW_CAP;
      end

      // -- RMW write -----------------------------------
      S_RMW_CAP: begin
        var_a_addr_o  = phys_a(v_dst_addr);
        var_a_data_o  = split_a(merged);
        var_a_wr_en_o = 1'b1;
        if (!CAN_DUAL) begin
          var_b_addr_o  = phys_b(v_dst_addr);
          var_b_data_o  = split_b(merged);
          var_b_wr_en_o = 1'b1;
        end
        if (r_cnt < 6'd63) begin
          n_r_cnt = r_cnt + 1;
          nstate  = S_RMW_RD;
        end else begin
          nstate = S_NEXT_SUB;
        end
      end

      // -- Advance sub-bank ----------------------------
      S_NEXT_SUB: begin
        if (sub_k < 3'd7 && sub_start + 8 < src_entries) begin
          n_sub_k = sub_k + 1;
          n_f_cnt = '0;
          nstate  = S_LOAD_RD;
        end else begin
          nstate = S_NEXT_HALF;
        end
      end

      // -- Advance half (off-diag: 2 halves, diag: 1) -
      S_NEXT_HALF: begin
        if (!is_diag && half == 1'b0) begin
          // Off-diagonal: second half processes scratch -> (j,i)
          n_half = 1'b1;
          nstate = S_SUB_INIT;
        end else begin
          nstate = S_NEXT_PAIR;
        end
      end

      // -- Advance to next pair ------------------------
      S_NEXT_PAIR: begin
        if (blk_j + 1 < CW_R) begin
          n_blk_j = blk_j + 1;
          nstate  = S_PAIR_INIT;
        end else if (blk_i + 1 < CW_R) begin
          n_blk_i = blk_i + 1;
          n_blk_j = blk_i + 1;
          nstate  = S_PAIR_INIT;
        end else begin
          nstate = S_DONE;
        end
      end

      S_DONE: begin
        fsm_done_o = 1'b1;
        nstate     = S_IDLE;
      end

      default: nstate = S_IDLE;
    endcase
  end

  always_ff @(posedge clk_i or posedge rst_i) begin
    if (rst_i) begin
      state  <= S_IDLE;
      blk_i  <= '0;
      blk_j  <= '0;
      half   <= 1'b0;
      sub_k  <= '0;
      f_cnt  <= '0;
      r_cnt  <= '0;
      cp_cnt <= '0;
      for (int i = 0; i < 8; i++) reg_bank[i] <= '0;
    end else begin
      state  <= nstate;
      blk_i  <= n_blk_i;
      blk_j  <= n_blk_j;
      half   <= n_half;
      sub_k  <= n_sub_k;
      f_cnt  <= n_f_cnt;
      r_cnt  <= n_r_cnt;
      cp_cnt <= n_cp_cnt;
      if (state == S_LOAD_RD)
        for (int i = 0; i < 8; i++) reg_bank[i] <= '0;
      if (state == S_LOAD_CAP)
        reg_bank[f_cnt] <= combine_ab();
    end
  end

endmodule
