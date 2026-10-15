// SPDX-FileCopyrightText: 2026 Stef Halmans, Niklas Höher
// SPDX-License-Identifier: LicenseRef-RUB-SecEng

import sdith_params_pkg::*;
import sdith_helpers_pkg::*;

// gen_rbase
//
// GenerateRbase: the shared inner loop of the Haux and Hlines stages.
// Runs N_CAP iterations; for each leaf i of repetition e it fetches a
// leaf pair, expands the leaf into r_acc (racc), and XORs the shifted
// r_acc into one r_base column.
//
// Column selection uses the Gray-code identity: gray(i) XOR gray(i+1)
// has Hamming weight 1, so exactly one column j = ctz(gray(i) XOR
// gray(i+1)) is updated per leaf instead of every set bit of gray(i).
//
// compose_shifted inserts the zero padding that aligns the two column
// partitions (the first lambda+B bits and the M-multiplied remainder)
// to 64-bit word boundaries, so later passes never straddle words.
//
// build_rbase_i=0 runs racc only (no XOR), for the aux extraction in
// phase12. build_rbase_i=1 runs the full racc + XOR loop.
//
// Includes dual-leaf prefetch (the second leaf of each fetched pair is
// buffered for the next iteration), an early racc fire that hides the
// AES latency behind the tail of the XOR loop, and USE_CACHE_OVERFLOW
// routing that places column KAPPA-1 in spare tree-cache memory.

module gen_rbase (
    input  logic clk_i,
    input  logic rst_i,
    input  logic var_stall_i,

    // Control
    input  logic                          start_i,
    output logic                          done_o,
    output logic                          active_o,

    // Configuration (held stable from start_i until done_o)
    input  logic [$clog2(TAU+1)-1:0]     e_i,
    input  logic [VAR_ADDR_WIDTH_COMBINED-1:0] rbase_write_base_i,
    input  logic [BRAM_ADDR_SIZE:0]       racc_slot_offset_i,
    input  logic                          build_rbase_i,

    // Leaf interface
    output logic                          get_next_leaf_o,
    output logic [GGM_TREE_DEPTH:0]       leaf_idx_o,
    output logic [GGM_TREE_DEPTH:0]       leaf_idx2_o,
    input  logic                          leaf_done_i,
    input  logic [LAMBDA-1:0]             leaf_i,
    input  logic [LAMBDA-1:0]             leaf2_i,

    // Racc control
    output logic                          racc_enable_o,
    output logic [LAMBDA-1:0]             racc_seed_o,
    output logic                          racc_first_run_o,
    output logic                          racc_owns_mem_o,
    output logic [BRAM_ADDR_SIZE:0]       racc_slot_offset_o,
    input  logic                          racc_done_i,

    // Var BRAM dual-port
    input  logic [VAR_DATA_WIDTH_COMBINED-1:0] var_a_data_i,
    output logic [VAR_DATA_WIDTH_COMBINED-1:0] var_a_data_o,
    output logic [VAR_ADDR_WIDTH_COMBINED-1:0] var_a_addr_o,
    output logic                               var_a_wr_en_o,
    input  logic [VAR_DATA_WIDTH_COMBINED-1:0] var_b_data_i,
    output logic [VAR_DATA_WIDTH_COMBINED-1:0] var_b_data_o,
    output logic [VAR_ADDR_WIDTH_COMBINED-1:0] var_b_addr_o,
    output logic                               var_b_wr_en_o,

    // Cache BRAM (USE_CACHE_OVERFLOW: rbase column KAPPA-1)
    input  logic [63:0]             cache_data_i,
    output logic [63:0]             cache_data_o,
    output logic [CACHE_ADDR_WIDTH-1:0] cache_addr_o,
    output logic                    cache_wr_en_o,
    output logic                    cache_active_o
);
  localparam CAN_DUAL = CAN_DUAL_COMBINED;
  localparam USE_CACHE = USE_CACHE_OVERFLOW;

  localparam RBASE_PARTS_OFFSET_L = R_ACC_PARTS + 1;
  localparam ALPHA_COL_BITS_L     = LAMBDA + B;
  localparam M_WORD_OFFSET_GR     = ALPHA_COL_BITS_L / 64;
  localparam M_BIT_OFFSET_GR      = ALPHA_COL_BITS_L % 64;
  localparam CARRY_BITS_GR        = 64 - M_BIT_OFFSET_GR;
  localparam [63:0] IDENTITY_MASK_GR = (M_BIT_OFFSET_GR == 0) ?
      64'hFFFFFFFF_FFFFFFFF : ((64'h1 << M_BIT_OFFSET_GR) - 1);

  localparam NR_GR = (ENC_BLOCKSIZE > 128 || ENC_KEYSIZE > 128) ? 14 : 10;
  localparam T_AES_GR = NR_GR + 2;
  localparam EARLY_FIRE_W_NORMAL = (R_ACC_PARTS - 1) - (T_AES_GR - 6) / 3;
  localparam EARLY_FIRE_W_FIRST  = (R_ACC_PARTS - 1) - (T_AES_GR - 4) / 2;

  function automatic [63:0] combine_ab;
    if (CAN_DUAL) return 64'(var_a_data_i);
    else          return {var_b_data_i, var_a_data_i};
  endfunction

  function automatic logic [63:0] compose_shifted(
      input logic [63:0]            racc_data,
      input logic [CARRY_BITS_GR-1:0] carry_in,
      input logic [$clog2(RBASE_PARTS_OFFSET_L+1)-1:0] word_idx
  );
    if (word_idx >= ($clog2(RBASE_PARTS_OFFSET_L+1))'(R_ACC_PARTS))
      return 64'(carry_in);
    else if (word_idx < M_WORD_OFFSET_GR)
      return racc_data;
    else if (word_idx == M_WORD_OFFSET_GR)
      return racc_data & IDENTITY_MASK_GR;
    else
      return {racc_data[M_BIT_OFFSET_GR-1:0], carry_in};
  endfunction

  typedef enum logic [2:0] {
    S_IDLE,
    S_GET_LEAF,
    S_RACC,
    S_XOR,
    S_DONE
  } state_t;

  state_t state, next_state;

  // Latched config (captured on start_i, stable until done_o)
  logic [VAR_ADDR_WIDTH_COMBINED-1:0] rbase_base_r;
  logic [BRAM_ADDR_SIZE:0]            slot_offset_r;
  logic                               build_rbase_r;

  logic [$clog2(N_CAP):0]                      i, next_i;
  logic [GGM_TREE_DEPTH:0]                     leaf_acc, next_leaf_acc;
  logic [LAMBDA-1:0]                           leaf_buf, next_leaf_buf;
  logic                                        leaf_buf_valid, next_leaf_buf_valid;
  logic                                        leaf_ready, next_leaf_ready;
  logic                                        racc_prefired, next_racc_prefired;
  logic [$clog2(KAPPA)-1:0]                    j_reg, next_j_reg;
  logic [$clog2(RBASE_PARTS_OFFSET_L+1)-1:0]  w, next_w;
  logic [CARRY_BITS_GR-1:0]                    carry, next_carry;
  logic [1:0]                                  xor_phase, next_xor_phase;
  logic [63:0]                                 r_acc_val, next_r_acc_val;

  // Pre-registered is_first_write: breaks carry chain on the critical path
  logic is_first_write;
  always_ff @(posedge clk_i or posedge rst_i) begin
    if (rst_i)
      is_first_write <= 1'b0;
    else if (!var_stall_i)
      is_first_write <= (next_i == (($clog2(N_CAP)+1)'(1) << next_j_reg));
  end

  // Gray code column selection
  logic [KAPPA-1:0] ip1_k;
  assign ip1_k = (KAPPA)'(i + 1);

  logic [KAPPA-1:0] gray_i, gray_ip1, gray_diff;
  assign gray_i   = (KAPPA)'(i) ^ ((KAPPA)'(i) >> 1);
  assign gray_ip1 = ip1_k ^ (ip1_k >> 1);
  assign gray_diff = gray_i ^ gray_ip1;

  logic [$clog2(KAPPA)-1:0] j_comb;
  always_comb begin
    if (i == N_CAP - 1)
      j_comb = ($clog2(KAPPA))'(KAPPA - 1);
    else begin
      j_comb = 0;
      for (int k = 0; k < KAPPA; k++) begin
        if (gray_diff[k]) begin
          j_comb = k[$clog2(KAPPA)-1:0];
          break;
        end
      end
    end
  end

  // Leaf index (accumulator-based: leaf_acc = i*TAU + e)
  wire [GGM_TREE_DEPTH:0] base_leaf_idx =
      (state == S_RACC || (state == S_XOR && racc_prefired)) ?
      leaf_acc + (GGM_TREE_DEPTH+1)'(TAU) : leaf_acc;

  assign leaf_idx_o  = base_leaf_idx;
  assign leaf_idx2_o = base_leaf_idx + (GGM_TREE_DEPTH+1)'(TAU);

  // Racc seed select
  logic use_buf;
  wire [LAMBDA-1:0] racc_seed = use_buf ? leaf_buf : leaf_i;

  assign racc_seed_o     = racc_seed;
  assign racc_first_run_o = (i == 0);
  assign racc_owns_mem_o  = (state == S_RACC);
  assign racc_slot_offset_o = slot_offset_r;
  assign active_o         = (state != S_IDLE) && (state != S_DONE);

  // XOR address helpers
  wire [VAR_ADDR_WIDTH_COMBINED-1:0] racc_rd_addr =
      VAR_ADDR_WIDTH_COMBINED'(slot_offset_r) + VAR_ADDR_WIDTH_COMBINED'(w);
  wire [VAR_ADDR_WIDTH_COMBINED-1:0] rbase_addr =
      rbase_base_r + VAR_ADDR_WIDTH_COMBINED'(j_reg * RBASE_PARTS_OFFSET_L + w);
  wire is_tail_word = (w == ($clog2(RBASE_PARTS_OFFSET_L+1))'(R_ACC_PARTS));
  wire writes_cache = USE_CACHE && (j_reg == ($clog2(KAPPA))'(KAPPA - 1));
  wire [CACHE_ADDR_WIDTH-1:0] cache_rbase_addr = (CACHE_ADDR_WIDTH)'(CACHE_RBASE_OFFSET + w);

  // Factored rbase read data
  wire [63:0] rbase_rd = writes_cache ? cache_data_i :
      (CAN_DUAL ? (is_tail_word ? 64'(var_a_data_i) : 64'(var_b_data_i))
                : combine_ab());

  // Pre-computed compose_shifted results
  wire [63:0] composed_data    = compose_shifted(combine_ab(), carry, w);
  wire [63:0] composed_zero    = compose_shifted(64'b0, carry, w);
  wire [63:0] composed_latched = compose_shifted(r_acc_val, carry, w);

  // Early racc fire condition
  wire early_fire_ok = build_rbase_r && !racc_prefired && i < N_CAP &&
      (leaf_ready || leaf_done_i || leaf_buf_valid) && xor_phase == 2'd0 &&
      ((!is_first_write &&
        w == ($clog2(RBASE_PARTS_OFFSET_L+1))'(EARLY_FIRE_W_NORMAL)) ||
       (is_first_write &&
        w == ($clog2(RBASE_PARTS_OFFSET_L+1))'(EARLY_FIRE_W_FIRST)));

  // Internal var memory bus (before port assignment)
  logic [63:0]             int_var_a_data, int_var_b_data;
  logic [VAR_ADDR_WIDTH_COMBINED-1:0] int_var_a_addr, int_var_b_addr;
  logic                    int_var_a_wr, int_var_b_wr;

  always_comb begin
    if (state == S_RACC) begin
      var_a_data_o  = '0;
      var_a_addr_o  = '0;
      var_a_wr_en_o = 1'b0;
      var_b_data_o  = '0;
      var_b_addr_o  = '0;
      var_b_wr_en_o = 1'b0;
    end else begin
      var_a_data_o  = split_a(int_var_a_data);
      var_a_addr_o  = phys_a(int_var_a_addr);
      var_a_wr_en_o = int_var_a_wr;
      var_b_data_o  = split_b(int_var_b_data);
      var_b_addr_o  = phys_b(int_var_b_addr);
      var_b_wr_en_o = int_var_b_wr;
    end
  end

  // Temporary variables for FSM combinational logic
  logic [63:0] _xor_result;

  // FSM
  always_comb begin
    next_state     = state;
    next_i         = i;
    next_leaf_acc  = leaf_acc;
    next_leaf_buf  = leaf_buf;
    next_leaf_buf_valid = leaf_buf_valid;
    next_leaf_ready = leaf_ready;
    next_racc_prefired = racc_prefired;
    next_j_reg     = j_reg;
    next_w         = w;
    next_carry     = carry;
    next_xor_phase = xor_phase;
    next_r_acc_val = r_acc_val;

    done_o           = 1'b0;
    racc_enable_o    = 1'b0;
    get_next_leaf_o  = 1'b0;
    use_buf          = 1'b0;

    int_var_a_data = 64'b0;
    int_var_a_addr = '0;
    int_var_a_wr   = 1'b0;
    int_var_b_data = 64'b0;
    int_var_b_addr = '0;
    int_var_b_wr   = 1'b0;

    cache_data_o   = 64'b0;
    cache_addr_o   = '0;
    cache_wr_en_o  = 1'b0;
    cache_active_o = (state == S_XOR && writes_cache) ? 1'b1 : 1'b0;

    case (state)

      // ========================================================
      S_IDLE: begin
        if (start_i) begin
          next_i              = 0;
          next_leaf_acc       = (GGM_TREE_DEPTH+1)'(e_i);
          next_leaf_buf_valid = 1'b0;
          next_leaf_ready     = 1'b0;
          next_racc_prefired  = 1'b0;
          next_state          = S_GET_LEAF;
        end
      end

      // ========================================================
      S_GET_LEAF: begin
        if (leaf_buf_valid) begin
          racc_enable_o       = 1'b1;
          use_buf             = 1'b1;
          next_leaf_buf_valid = 1'b0;
          next_leaf_ready     = 1'b0;
          next_state          = S_RACC;
        end else if (leaf_ready) begin
          racc_enable_o   = 1'b1;
          next_leaf_ready = 1'b0;
          if ((i + 1) < N_CAP) begin
            next_leaf_buf       = leaf2_i;
            next_leaf_buf_valid = 1'b1;
          end
          next_state = S_RACC;
        end else begin
          get_next_leaf_o = 1'b1;
          if (leaf_done_i) begin
            racc_enable_o   = 1'b1;
            next_leaf_ready = 1'b0;
            if ((i + 1) < N_CAP) begin
              next_leaf_buf       = leaf2_i;
              next_leaf_buf_valid = 1'b1;
            end
            next_state = S_RACC;
          end
        end
      end

      // ========================================================
      S_RACC: begin
        // Leaf prefetch during racc (only if there's a next iteration)
        if (!leaf_buf_valid && !leaf_ready && (i + 1) < N_CAP)
          get_next_leaf_o = 1'b1;
        if (leaf_done_i) begin
          next_leaf_ready = 1'b1;
          if ((i + 2) < N_CAP) begin
            next_leaf_buf       = leaf2_i;
            next_leaf_buf_valid = 1'b1;
          end
        end

        if (racc_done_i) begin
          next_i        = i + 1;
          next_leaf_acc = leaf_acc + (GGM_TREE_DEPTH+1)'(TAU);
          if (build_rbase_r) begin
            next_j_reg    = j_comb;
            next_w        = '0;
            next_carry    = '0;
            next_xor_phase = 2'd0;
            next_state    = S_XOR;
          end else if ((i + 1) < N_CAP) begin
            next_state = S_GET_LEAF;
          end else begin
            next_state = S_DONE;
          end
        end
      end

      // ========================================================
      // XOR loop: compose_shifted(r_acc[w]) into rbase[j][w]
      // ========================================================
      S_XOR: begin
        // Leaf prefetch during XOR
        if (!leaf_buf_valid && !leaf_ready && !racc_prefired && i < N_CAP)
          get_next_leaf_o = 1'b1;
        if (leaf_done_i) begin
          next_leaf_ready = 1'b1;
          if ((i + 1) < N_CAP) begin
            next_leaf_buf       = leaf2_i;
            next_leaf_buf_valid = 1'b1;
          end
        end

        // Early racc fire
        if (early_fire_ok) begin
          racc_enable_o      = 1'b1;
          next_racc_prefired = 1'b1;
          if (leaf_buf_valid && !leaf_ready && !leaf_done_i) begin
            use_buf             = 1'b1;
            next_leaf_buf_valid = 1'b0;
          end else begin
            next_leaf_ready = 1'b0;
          end
        end

        // ---- XOR computation ----
        begin
          logic column_done;
          column_done = 1'b0;

          if (is_first_write) begin
            // First write: compose and write directly (no read-modify-write)
            if (CAN_DUAL) begin
              case (xor_phase)
                2'd0: begin
                  if (is_tail_word) begin
                    if (writes_cache) begin
                      cache_addr_o  = cache_rbase_addr;
                      cache_data_o  = composed_zero;
                      cache_wr_en_o = 1'b1;
                    end else begin
                      int_var_a_addr = rbase_addr;
                      int_var_a_data = composed_zero;
                      int_var_a_wr   = 1'b1;
                    end
                    column_done = 1'b1;
                  end else begin
                    int_var_a_addr = racc_rd_addr;
                    next_xor_phase = 2'd1;
                  end
                end
                2'd1: begin
                  if (writes_cache) begin
                    cache_addr_o  = cache_rbase_addr;
                    cache_data_o  = composed_data;
                    cache_wr_en_o = 1'b1;
                  end else begin
                    int_var_a_addr = rbase_addr;
                    int_var_a_data = composed_data;
                    int_var_a_wr   = 1'b1;
                  end
                  if (w >= ($clog2(RBASE_PARTS_OFFSET_L+1))'(M_WORD_OFFSET_GR))
                    next_carry = combine_ab() >> M_BIT_OFFSET_GR;
                  next_w         = w + 1;
                  next_xor_phase = 2'd0;
                end
                default: ;
              endcase
            end else begin
              // CAN_DUAL=0: 2 cycles/word
              case (xor_phase)
                2'd0: begin
                  if (is_tail_word) begin
                    if (writes_cache) begin
                      cache_addr_o  = cache_rbase_addr;
                      cache_data_o  = composed_zero;
                      cache_wr_en_o = 1'b1;
                    end else begin
                      int_var_a_addr = rbase_addr;
                      int_var_b_addr = rbase_addr;
                      int_var_a_data = composed_zero;
                      int_var_b_data = composed_zero;
                      int_var_a_wr   = 1'b1;
                      int_var_b_wr   = 1'b1;
                    end
                    column_done = 1'b1;
                  end else begin
                    int_var_a_addr = racc_rd_addr;
                    int_var_b_addr = racc_rd_addr;
                    next_xor_phase = 2'd1;
                  end
                end
                2'd1: begin
                  if (writes_cache) begin
                    cache_addr_o  = cache_rbase_addr;
                    cache_data_o  = composed_data;
                    cache_wr_en_o = 1'b1;
                  end else begin
                    int_var_a_addr = rbase_addr;
                    int_var_b_addr = rbase_addr;
                    int_var_a_data = composed_data;
                    int_var_b_data = composed_data;
                    int_var_a_wr   = 1'b1;
                    int_var_b_wr   = 1'b1;
                  end
                  if (w >= ($clog2(RBASE_PARTS_OFFSET_L+1))'(M_WORD_OFFSET_GR))
                    next_carry = combine_ab() >> M_BIT_OFFSET_GR;
                  next_w         = w + 1;
                  next_xor_phase = 2'd0;
                end
                default: ;
              endcase
            end

          end else begin
            // Normal XOR: read-modify-write
            if (CAN_DUAL) begin
              // 2-cycle pipeline: Port A reads racc, Port B reads rbase (parallel)
              case (xor_phase)
                2'd0: begin
                  if (is_tail_word) begin
                    if (writes_cache)
                      cache_addr_o = cache_rbase_addr;
                    else
                      int_var_a_addr = rbase_addr;
                    next_xor_phase = 2'd2;
                  end else begin
                    int_var_a_addr = racc_rd_addr;
                    if (writes_cache)
                      cache_addr_o = cache_rbase_addr;
                    else
                      int_var_b_addr = rbase_addr;
                    next_xor_phase = 2'd1;
                  end
                end
                2'd1: begin
                  _xor_result = composed_data ^ rbase_rd;
                  if (writes_cache) begin
                    cache_addr_o  = cache_rbase_addr;
                    cache_data_o  = _xor_result;
                    cache_wr_en_o = 1'b1;
                  end else begin
                    int_var_a_addr = rbase_addr;
                    int_var_a_data = _xor_result;
                    int_var_a_wr   = 1'b1;
                  end
                  if (w >= ($clog2(RBASE_PARTS_OFFSET_L+1))'(M_WORD_OFFSET_GR))
                    next_carry = 64'(var_a_data_i) >> M_BIT_OFFSET_GR;
                  if (w == ($clog2(RBASE_PARTS_OFFSET_L+1))'(RBASE_PARTS_OFFSET_L - 1))
                    column_done = 1'b1;
                  else begin
                    next_w         = w + 1;
                    next_xor_phase = 2'd0;
                  end
                end
                2'd2: begin
                  // Tail word: rbase available, XOR with carry
                  _xor_result = 64'(carry) ^ rbase_rd;
                  if (writes_cache) begin
                    cache_addr_o  = cache_rbase_addr;
                    cache_data_o  = _xor_result;
                    cache_wr_en_o = 1'b1;
                  end else begin
                    int_var_a_addr = rbase_addr;
                    int_var_a_data = _xor_result;
                    int_var_a_wr   = 1'b1;
                  end
                  column_done = 1'b1;
                end
                default: ;
              endcase
            end else begin
              // CAN_DUAL=0: 3-cycle pipeline
              case (xor_phase)
                2'd0: begin
                  if (is_tail_word) begin
                    if (writes_cache)
                      cache_addr_o = cache_rbase_addr;
                    else begin
                      int_var_a_addr = rbase_addr;
                      int_var_b_addr = rbase_addr;
                    end
                    next_xor_phase = 2'd2;
                  end else begin
                    int_var_a_addr = racc_rd_addr;
                    int_var_b_addr = racc_rd_addr;
                    next_xor_phase = 2'd1;
                  end
                end
                2'd1: begin
                  // Latch racc, issue rbase read
                  next_r_acc_val = combine_ab();
                  if (writes_cache)
                    cache_addr_o = cache_rbase_addr;
                  else begin
                    int_var_a_addr = rbase_addr;
                    int_var_b_addr = rbase_addr;
                  end
                  next_xor_phase = 2'd2;
                end
                2'd2: begin
                  if (is_tail_word)
                    _xor_result = 64'(carry) ^ rbase_rd;
                  else
                    _xor_result = composed_latched ^ rbase_rd;
                  if (writes_cache) begin
                    cache_addr_o  = cache_rbase_addr;
                    cache_data_o  = _xor_result;
                    cache_wr_en_o = 1'b1;
                  end else begin
                    int_var_a_addr = rbase_addr;
                    int_var_b_addr = rbase_addr;
                    int_var_a_data = _xor_result;
                    int_var_b_data = _xor_result;
                    int_var_a_wr   = 1'b1;
                    int_var_b_wr   = 1'b1;
                  end
                  if (!is_tail_word && w >= ($clog2(RBASE_PARTS_OFFSET_L+1))'(M_WORD_OFFSET_GR))
                    next_carry = r_acc_val >> M_BIT_OFFSET_GR;
                  if (is_tail_word || w == ($clog2(RBASE_PARTS_OFFSET_L+1))'(RBASE_PARTS_OFFSET_L - 1))
                    column_done = 1'b1;
                  else begin
                    next_w         = w + 1;
                    next_xor_phase = 2'd0;
                  end
                end
                default: ;
              endcase
            end
          end

          // Column completion transition
          if (column_done) begin
            if (racc_prefired) begin
              next_racc_prefired = 1'b0;
              next_w         = 0;
              next_xor_phase = 2'd0;
              next_carry     = '0;
              next_state     = S_RACC;
            end else if (i >= N_CAP) begin
              next_state = S_DONE;
            end else if (leaf_ready || leaf_done_i) begin
              racc_enable_o   = 1'b1;
              next_leaf_ready = 1'b0;
              next_w          = 0;
              next_xor_phase  = 2'd0;
              next_carry      = '0;
              next_state      = S_RACC;
            end else if (leaf_buf_valid) begin
              racc_enable_o       = 1'b1;
              use_buf             = 1'b1;
              next_leaf_buf_valid = 1'b0;
              next_w              = 0;
              next_xor_phase      = 2'd0;
              next_carry          = '0;
              next_state          = S_RACC;
            end else begin
              next_state = S_GET_LEAF;
            end
          end
        end
      end

      // ========================================================
      S_DONE: begin
        done_o     = 1'b1;
        next_state = S_IDLE;
      end

      default: ;
    endcase
  end

  // Sequential logic
  always_ff @(posedge clk_i or posedge rst_i) begin
    if (rst_i) begin
      state          <= S_IDLE;
      i              <= 0;
      leaf_acc       <= '0;
      leaf_buf       <= '0;
      leaf_buf_valid <= 1'b0;
      leaf_ready     <= 1'b0;
      racc_prefired  <= 1'b0;
      j_reg          <= 0;
      w              <= 0;
      carry          <= '0;
      xor_phase      <= 2'd0;
      r_acc_val      <= 64'd0;
      rbase_base_r   <= '0;
      slot_offset_r  <= '0;
      build_rbase_r  <= 1'b0;
    end else if (!var_stall_i) begin
      state          <= next_state;
      i              <= next_i;
      leaf_acc       <= next_leaf_acc;
      leaf_buf       <= next_leaf_buf;
      leaf_buf_valid <= next_leaf_buf_valid;
      leaf_ready     <= next_leaf_ready;
      racc_prefired  <= next_racc_prefired;
      j_reg          <= next_j_reg;
      w              <= next_w;
      carry          <= next_carry;
      xor_phase      <= next_xor_phase;
      r_acc_val      <= next_r_acc_val;
      if (start_i && state == S_IDLE) begin
        rbase_base_r  <= rbase_write_base_i;
        slot_offset_r <= racc_slot_offset_i;
        build_rbase_r <= build_rbase_i;
      end
    end
  end

endmodule
