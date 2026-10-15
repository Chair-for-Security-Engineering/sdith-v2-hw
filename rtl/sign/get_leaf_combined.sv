// SPDX-FileCopyrightText: 2026 Stef Halmans, Niklas Höher
// SPDX-License-Identifier: LicenseRef-RUB-SecEng

import sdith_params_pkg::*;
import sdith_helpers_pkg::*;

// get_leaf_combined
//
// GGM tree walker: two mutually exclusive modes sharing one register set.
// DFS mode (Tree.InitCache + h_com): one depth-first pass over the full
// tree; writes cache-depth nodes to the tree-cache BRAM, commits each
// leaf, and absorbs the commits into h_com (squeezed to HCOM_VAR_OFFSET).
// Cache mode (Tree.GetLeafPair): fetches two leaf seeds in parallel, one
// per Rijndael core, descending from their cached ancestors.

module get_leaf_combined #(
    parameter MEM_SIZE = 64
) (
    input logic clk_i,
    input logic rst_i,

    // DFS control
    input  logic fsm_start_i,
    input  logic [LAMBDA-1:0] rseed_i,
    // Cache control
    input  logic get_next_leaf_i,
    input  logic [GGM_TREE_DEPTH:0] leaf_idx_i,
    input  logic [GGM_TREE_DEPTH:0] leaf_idx2_i,
    output logic [LAMBDA-1:0] leaf_o,
    output logic [LAMBDA-1:0] leaf2_o,

    // Shared
    input  logic [LAMBDA-1:0] salt_i,
    output logic fsm_done_o,

    // AES engine 1
    output logic [ENC_KEYSIZE-1:0]   aes1_key_o,
    output logic [ENC_BLOCKSIZE-1:0] aes1_plaintext_o,
    input  logic [ENC_BLOCKSIZE-1:0] aes1_ciphertext_i,
    output logic                     aes1_enable_o,
    input  logic                     aes1_ready_i,
    input  logic                     aes1_valid_i,

    // AES engine 2
    output logic [ENC_KEYSIZE-1:0]   aes2_key_o,
    output logic [ENC_BLOCKSIZE-1:0] aes2_plaintext_o,
    input  logic [ENC_BLOCKSIZE-1:0] aes2_ciphertext_i,
    output logic                     aes2_enable_o,
    input  logic                     aes2_ready_i,
    input  logic                     aes2_valid_i,

    // Fire accepted (cache mode; tied to 1 in DFS by dfs_mode)
    input  logic fire_accepted1_i,
    input  logic fire_accepted2_i,

    // Tree-cache BRAM (DFS writes the cache-depth nodes, cache mode reads them)
    input  logic [MEM_SIZE-1:0]     cache_data_i,
    output logic [MEM_SIZE-1:0]     cache_data_o,
    output logic [CACHE_ADDR_WIDTH-1:0] cache_addr_o,
    output logic                    cache_wr_en_o,

    // Scratchpad (var_bram): sibling scratch during DFS, h_com output during squeeze
    input  logic [VAR_DATA_WIDTH_COMBINED-1:0] var_a_data_i,
    output logic [VAR_DATA_WIDTH_COMBINED-1:0] var_a_data_o,
    output logic [VAR_ADDR_WIDTH_COMBINED-1:0] var_a_addr_o,
    output logic                               var_a_wr_en_o,
    input  logic [VAR_DATA_WIDTH_COMBINED-1:0] var_b_data_i,
    output logic [VAR_DATA_WIDTH_COMBINED-1:0] var_b_data_o,
    output logic [VAR_ADDR_WIDTH_COMBINED-1:0] var_b_addr_o,
    output logic                               var_b_wr_en_o,

    // SHAKE (DFS only)
    output logic        shake_start_o,
    output logic [63:0] shake_din_o,
    output logic        shake_din_valid_o,
    output logic        shake_last_din_o,
    output logic [ 3:0] shake_last_din_byte_o,
    input  logic        shake_din_ready_i,
    output logic        shake_dout_ready_o,
    input  logic [63:0] shake_dout_i,
    input  logic        shake_dout_valid_i
);
  // Parameters

  localparam logic unsigned [31:0] NR_STORE = LAMBDA / MEM_SIZE;
  localparam IDX_BITS = GGM_TREE_DEPTH + 2;
  localparam DEPTH_BITS = $clog2(GGM_TREE_DEPTH + 2);
  localparam int ZERO_DESCENT = (CACHE_TREE_DEPTH >= GGM_TREE_DEPTH - 1) ? 1 : 0;
  localparam HASH_IDX_BITS = $clog2(LAMBDA_DIV_64 + 1);
  localparam SQUEEZE_WORDS = 2 * LAMBDA_DIV_64;
  localparam SQUEEZE_IDX_BITS = $clog2(SQUEEZE_WORDS + 1);

  // Scratchpad port helpers phys_a/phys_b/split_a/split_b come from sdith_helpers_pkg
  localparam CAN_DUAL = CAN_DUAL_COMBINED;

  // Reconstruct 64-bit sibling word from var_bram read ports
  wire [63:0] var_sib_word;
  generate
    if (CAN_DUAL) begin : g_sib_64
      assign var_sib_word = var_a_data_i[63:0];
    end else begin : g_sib_32
      assign var_sib_word = {var_b_data_i, var_a_data_i};
    end
  endgenerate
  // State encoding: cache 0-5, DFS 6-15, C_FETCH_SETUP=20.
  // dfs_mode detection relies on this numeric partitioning.
  // fsm_encoding="none" preserves binary encoding for synthesis constraints.
  typedef enum logic [4:0] {
    // Cache states
    C_IDLE             = 5'd0,
    C_GET_PARENT       = 5'd1,  // also handles AES1 fire retry (load_idx==0)
    C_GET_PARENT2_WAIT = 5'd2,
    C_GET_PARENT2      = 5'd3,  // also handles AES2 fire retry (load_idx2==0)
    C_STEP             = 5'd4,
    C_DONE             = 5'd5,
    // DFS states
    S_IDLE             = 5'd6,
    S_DESC_PRNG        = 5'd7,
    S_DESC_STEP        = 5'd8,
    S_DESC_WRITE       = 5'd9,
    S_COMMIT_FIRE      = 5'd10,
    S_COMMIT_WAIT      = 5'd11,
    S_HASH_COMMIT      = 5'd12,
    S_FINALIZE_HASH    = 5'd13,
    S_SQUEEZE          = 5'd14,
    S_DONE             = 5'd15,
    // Cache setup state; see cache_idx_shift_r.
    C_FETCH_SETUP      = 5'd20
  } state_t;

  (* fsm_encoding = "none" *) state_t state;
  state_t next_state;

  // C_FETCH_SETUP (20) is cache mode
  wire dfs_mode = (state >= 5'd6) && (state <= 5'd15);

  // Shared LAMBDA-width registers
  reg [LAMBDA-1:0] parent, next_parent;
  reg [LAMBDA-1:0] parent2, next_parent2;
  reg [LAMBDA-1:0] leaf_stored2, next_leaf_stored2;

  // Shared index registers
  reg [IDX_BITS-1:0] idx, next_idx;
  reg [IDX_BITS-1:0] idx2, next_idx2;
  reg [GGM_TREE_DEPTH:0] leaf_idx, next_leaf_idx;
  reg [GGM_TREE_DEPTH:0] leaf_idx_2, next_leaf_idx_2;
  reg [3:0] load_idx, next_load_idx;
  reg [3:0] load_idx2, next_load_idx2;

  // DFS-only registers
  reg [DEPTH_BITS-1:0] descent_depth, next_descent_depth;
  reg [DEPTH_BITS-1:0] leaf_depth, next_leaf_depth;
  reg at_leaf, next_at_leaf;
  reg [DEPTH_BITS-1:0] diverge_depth_r, next_diverge_depth_r;
  reg [DEPTH_BITS-1:0] recompute_levels_r, next_recompute_levels_r;
  reg [1:0] cache_write_phase, next_cache_write_phase;
  reg advance_done, next_advance_done;
  reg last_leaf_r, next_last_leaf_r;
  reg commit_is_right, next_commit_is_right;
  reg [HASH_IDX_BITS-1:0] hash_idx, next_hash_idx;
  reg [7:0] last_byte_prev, next_last_byte_prev;
  reg [SQUEEZE_IDX_BITS-1:0] squeeze_idx, next_squeeze_idx;

  // Cache-only registers
  reg leaf1_done, next_leaf1_done;
  reg leaf2_done, next_leaf2_done;

  // Registered cache_idx_shift: captured in C_IDLE, used throughout the fetch.
  // Pipelines the leaf_idx -> BRAM addr path into two register-bounded stages.
  reg [CACHE_ADDR_WIDTH-1:0] cache_idx_shift_r,  next_cache_idx_shift_r;
  reg [CACHE_ADDR_WIDTH-1:0] cache_idx_shift2_r, next_cache_idx_shift2_r;

  // Pre-registered next tree indices for C_STEP's AES plaintext computation.
  // Updated every cycle; stable during C_STEP's AES wait since idx/dir_bit
  // are unchanged. Breaks the combinational chain from idx through the FSM
  // into the wide adder.
  logic [IDX_BITS-1:0] c_step_next_idx_reg;
  logic [IDX_BITS-1:0] c_step_next_idx2_reg;
  // Registered idx copies for the non-C_STEP cache-mode AES path. Avoids a
  // long combinational path from idx through all next_idx branches to the adder.
  logic [IDX_BITS-1:0] cache_xor_idx_r;
  logic [IDX_BITS-1:0] cache_xor_idx2_r;
  // Combinational wires

  // GGM tree has 2 leaf levels: nodes at depth D-1 and depth D (when
  // TAU*N_CAP is not a power of 2). CUTOFF = 2^D separates them: tree
  // indices < CUTOFF are at depth D-1, >= CUTOFF are at depth D.
  // This affects cache index shift amounts (off by 1 between levels).
  wire [GGM_TREE_DEPTH:0] CUTOFF = (GGM_TREE_DEPTH + 1)'(1) << GGM_TREE_DEPTH;

  // DFS advance wires
  wire [GGM_TREE_DEPTH:0] next_idx_wire = (GGM_TREE_DEPTH + 1)'(idx) + (GGM_TREE_DEPTH + 1)'(1);
  wire is_last_leaf = (next_idx_wire >= (GGM_TREE_DEPTH + 1)'(2 * GGM_TREE_SIZE));

  logic [DEPTH_BITS-1:0] trailing_zeros;
  always_comb begin
    trailing_zeros = '0;
    for (int k = 0; k <= GGM_TREE_DEPTH; k++) begin
      if (next_idx_wire[k]) break;
      trailing_zeros = DEPTH_BITS'(k + 1);
    end
  end

  // Direction bits
  wire dir_bit  = leaf_idx[GGM_TREE_DEPTH];
  wire dir_bit2 = leaf_idx_2[GGM_TREE_DEPTH];
  wire msb_next  = next_leaf_idx[GGM_TREE_DEPTH];
  wire msb_next2 = next_leaf_idx_2[GGM_TREE_DEPTH];

  // DFS child extraction (left from AES1, right from AES2)
  wire [LAMBDA-1:0] left_child = (LAMBDA)'(aes1_ciphertext_i);
  wire [LAMBDA-1:0] right_child;
  generate
    if (SECURITY_LEVEL == 3) begin : sec3_extract
      assign right_child = aes2_ciphertext_i[ENC_BLOCKSIZE-1:64];
    end else begin : sec1_5_extract
      assign right_child = (LAMBDA)'(aes2_ciphertext_i);
    end
  endgenerate

  wire [LAMBDA-1:0] path_child = dir_bit ? right_child : left_child;
  wire [LAMBDA-1:0] sib_child  = dir_bit ? left_child  : right_child;

  // Cache child extraction (one child per AES, direction-dependent)
  wire [LAMBDA-1:0] cache_child1, cache_child2;
  generate
    if (SECURITY_LEVEL == 3) begin : sec3_cache
      assign cache_child1 = dir_bit  ? aes1_ciphertext_i[ENC_BLOCKSIZE-1:64] : (LAMBDA)'(aes1_ciphertext_i);
      assign cache_child2 = dir_bit2 ? aes2_ciphertext_i[ENC_BLOCKSIZE-1:64] : (LAMBDA)'(aes2_ciphertext_i);
    end else begin : sec1_5_cache
      assign cache_child1 = (LAMBDA)'(aes1_ciphertext_i);
      assign cache_child2 = (LAMBDA)'(aes2_ciphertext_i);
    end
  endgenerate

  // -- AES plaintext --
  wire [ENC_BLOCKSIZE-1:0] salt_shifted = (ENC_BLOCKSIZE)'(salt_i) << (SECURITY_LEVEL == 3 ? 64 : 0);
  wire [IDX_BITS:0] next_idx2_comb = IDX_BITS'(2 * idx2) + IDX_BITS'(dir_bit);

  // Combinational next-index values for C_STEP, registered each cycle.
  // Correct during C_STEP because idx/idx2 are stable through the AES wait.
  wire [IDX_BITS-1:0] c_step_next_idx_comb  = IDX_BITS'(2 * idx  + IDX_BITS'(dir_bit));
  wire [IDX_BITS-1:0] c_step_next_idx2_comb = IDX_BITS'(2 * idx2 + IDX_BITS'(dir_bit2));

  // Cache-mode xor_val source: uses pre-registered index values to avoid
  // long combinational paths. C_STEP uses c_step_next_idx_reg; other states
  // use cache_xor_idx_r (1-cycle-delayed next_idx).
  wire [IDX_BITS-1:0] cache_aes1_xor_idx  = (state == C_STEP) ? c_step_next_idx_reg  : cache_xor_idx_r;
  wire [IDX_BITS-1:0] cache_aes2_xor_idx2 = (state == C_STEP) ? c_step_next_idx2_reg : cache_xor_idx2_r;

  // idx2 == idx before S_COMMIT_FIRE, so 2*idx2 is already the commit
  // plaintext. DFS-mode AES fires from S_DESC_PRNG with registered idx2
  // to avoid a long combinational path.
  wire [IDX_BITS:0] aes1_xor_val = dfs_mode ?
      (IDX_BITS+1)'(2 * idx2) :
      (IDX_BITS+1)'(2 * cache_aes1_xor_idx);

  wire [IDX_BITS:0] aes2_xor_val = dfs_mode ? aes1_xor_val : (IDX_BITS+1)'(2 * cache_aes2_xor_idx2);

  wire aes1_offset_bit = dfs_mode ? 1'b0 : msb_next;
  wire aes2_offset_bit = dfs_mode ? 1'b1 : msb_next2;

  // Carry-select adder for (salt_i ^ xor) + offset_bit. Splits the
  // ENC_BLOCKSIZE-wide ripple into 64-bit chunks that precompute +0 and +1
  // in parallel, with a short carry cascade selecting between them.
  // Only enabled for 128-bit (SEC1) where the adder is on the critical path.
  wire [ENC_BLOCKSIZE-1:0] aes1_pt_pre;
  wire [ENC_BLOCKSIZE-1:0] aes2_pt_pre;

  generate
    if (ENC_BLOCKSIZE == 128) begin : g_optk_en
      localparam int K_NCHUNK = ENC_BLOCKSIZE / 64;

      wire [ENC_BLOCKSIZE-1:0] aes1_base_k = salt_shifted ^ (ENC_BLOCKSIZE)'(aes1_xor_val);
      wire [ENC_BLOCKSIZE-1:0] aes2_base_k = salt_shifted ^ (ENC_BLOCKSIZE)'(aes2_xor_val);

      wire [K_NCHUNK-1:0][63:0] aes1_k_p1;
      wire [K_NCHUNK-1:0][63:0] aes2_k_p1;
      wire [K_NCHUNK-1:0]       aes1_k_co;
      wire [K_NCHUNK-1:0]       aes2_k_co;
      wire [K_NCHUNK:0]         aes1_k_c;
      wire [K_NCHUNK:0]         aes2_k_c;

      assign aes1_k_c[0] = aes1_offset_bit;
      assign aes2_k_c[0] = aes2_offset_bit;

      for (genvar gk = 0; gk < K_NCHUNK; gk++) begin : g_optk
        assign {aes1_k_co[gk], aes1_k_p1[gk]} = {1'b0, aes1_base_k[64*gk +: 64]} + 65'd1;
        assign {aes2_k_co[gk], aes2_k_p1[gk]} = {1'b0, aes2_base_k[64*gk +: 64]} + 65'd1;
        assign aes1_k_c[gk+1] = aes1_k_c[gk] & aes1_k_co[gk];
        assign aes2_k_c[gk+1] = aes2_k_c[gk] & aes2_k_co[gk];
        assign aes1_pt_pre[64*gk +: 64] = aes1_k_c[gk] ? aes1_k_p1[gk] : aes1_base_k[64*gk +: 64];
        assign aes2_pt_pre[64*gk +: 64] = aes2_k_c[gk] ? aes2_k_p1[gk] : aes2_base_k[64*gk +: 64];
      end
    end else begin : g_optk_dis
      assign aes1_pt_pre = (salt_shifted ^ (ENC_BLOCKSIZE)'(aes1_xor_val))
                            + (ENC_BLOCKSIZE)'(aes1_offset_bit);
      assign aes2_pt_pre = (salt_shifted ^ (ENC_BLOCKSIZE)'(aes2_xor_val))
                            + (ENC_BLOCKSIZE)'(aes2_offset_bit);
    end
  endgenerate

  // Byte-reverse: AES expects big-endian, arithmetic above is little-endian
  assign aes1_plaintext_o = {<<8{aes1_pt_pre}};
  assign aes2_plaintext_o = {<<8{aes2_pt_pre}};

  // -- AES key and enable --
  logic [ENC_KEYSIZE-1:0] aes1_key_int, aes2_key_int;
  logic aes1_enable_int, aes2_enable_int;

  assign aes1_key_o    = aes1_key_int;
  assign aes2_key_o    = aes2_key_int;
  assign aes1_enable_o = aes1_enable_int;
  assign aes2_enable_o = aes2_enable_int;

  // -- Fire accepted (DFS: always 1) --
  wire eff_fire_accepted1 = dfs_mode ? 1'b1 : fire_accepted1_i;
  wire eff_fire_accepted2 = dfs_mode ? 1'b1 : fire_accepted2_i;

  // -- Outputs --
  assign leaf_o     = parent;
  assign leaf2_o    = leaf_stored2;

  // -- BRAM output wires (unified: sibling + cache share one BRAM port) --
  logic [MEM_SIZE-1:0] cache_data_int;
  logic [CACHE_ADDR_WIDTH-1:0] cache_addr_int;
  logic cache_wr_en_int;
  assign cache_data_o  = cache_data_int;
  assign cache_addr_o  = cache_addr_int;
  assign cache_wr_en_o = cache_wr_en_int;

  // -- DFS SHAKE / hash wires --
  // commit_half is always parent2: left commit lives there naturally,
  // right commit is copied in from leaf_stored2 when switching halves.
  wire [LAMBDA+7:0] padded = {last_byte_prev, parent2};
  wire [63:0] hash_word = padded[(LAMBDA+7) - hash_idx*64 -: 64];

  // -- DFS advance computations --
  logic [DEPTH_BITS-1:0] next_leaf_depth_comb, recompute_levels_comb, diverge_depth_comb;
  always_comb begin
    if (next_idx_wire < CUTOFF)
      next_leaf_depth_comb = DEPTH_BITS'(GGM_TREE_DEPTH - 1);
    else
      next_leaf_depth_comb = DEPTH_BITS'(GGM_TREE_DEPTH);

    if (trailing_zeros < next_leaf_depth_comb)
      recompute_levels_comb = trailing_zeros;
    else
      recompute_levels_comb = next_leaf_depth_comb;

    diverge_depth_comb = next_leaf_depth_comb - recompute_levels_comb;
  end

  // -- Cache BRAM index computation --
  wire [GGM_TREE_DEPTH:0] leaf_idx_tree  = leaf_idx_i  + GGM_TREE_SIZE;
  wire [GGM_TREE_DEPTH:0] leaf_idx_tree2 = leaf_idx2_i + GGM_TREE_SIZE;

  wire [CACHE_ADDR_WIDTH-1:0] cache_idx_shift = (leaf_idx_tree < CUTOFF) ?
      (leaf_idx_tree >> (GGM_TREE_DEPTH - CACHE_TREE_DEPTH - 1)) :
      (leaf_idx_tree >> (GGM_TREE_DEPTH - CACHE_TREE_DEPTH));
  // cache_idx_shift is always in [2^K, 2^(K+1)-1], so bit K is always set.
  // Subtraction is replaced by a bitmask (clear bit K) to avoid a carry chain.
  wire [CACHE_ADDR_WIDTH-1:0] cache_idx  = cache_idx_shift  & ~(CACHE_ADDR_WIDTH'(1 << CACHE_TREE_DEPTH));

  wire [CACHE_ADDR_WIDTH-1:0] cache_idx_shift2 = (leaf_idx_tree2 < CUTOFF) ?
      (leaf_idx_tree2 >> (GGM_TREE_DEPTH - CACHE_TREE_DEPTH - 1)) :
      (leaf_idx_tree2 >> (GGM_TREE_DEPTH - CACHE_TREE_DEPTH));
  wire [CACHE_ADDR_WIDTH-1:0] cache_idx2 = cache_idx_shift2 & ~(CACHE_ADDR_WIDTH'(1 << CACHE_TREE_DEPTH));

  wire [CACHE_ADDR_WIDTH-1:0] cache_mem_addr  = load_idx  + NR_STORE * cache_idx;
  wire [CACHE_ADDR_WIDTH-1:0] cache_mem_addr2 = load_idx2 + NR_STORE * cache_idx2;

  // Registered-source versions (used in C_FETCH_SETUP onwards, not in C_IDLE).
  // Breaks the long combinational path from phase12/hlines registers through
  // the leaf_idx -> cache_idx_shift chain; the register divides it in two.
  wire [CACHE_ADDR_WIDTH-1:0] cache_idx_r       = cache_idx_shift_r  & ~(CACHE_ADDR_WIDTH'(1 << CACHE_TREE_DEPTH));
  wire [CACHE_ADDR_WIDTH-1:0] cache_idx2_r      = cache_idx_shift2_r & ~(CACHE_ADDR_WIDTH'(1 << CACHE_TREE_DEPTH));
  wire [CACHE_ADDR_WIDTH-1:0] cache_mem_addr_rr  = load_idx  + NR_STORE * cache_idx_r;
  wire [CACHE_ADDR_WIDTH-1:0] cache_mem_addr2_rr = load_idx2 + NR_STORE * cache_idx2_r;
  // State machine

  always_comb begin
    // -- Defaults --
    next_state = state;
    next_parent = parent;
    next_parent2 = parent2;
    next_leaf_stored2 = leaf_stored2;
    next_idx = idx;
    next_idx2 = idx2;
    next_leaf_idx = leaf_idx;
    next_leaf_idx_2 = leaf_idx_2;
    next_load_idx = load_idx;
    next_load_idx2 = load_idx2;
    next_descent_depth = descent_depth;
    next_leaf_depth = leaf_depth;
    next_at_leaf = at_leaf;
    next_diverge_depth_r = diverge_depth_r;
    next_recompute_levels_r = recompute_levels_r;
    next_cache_write_phase = cache_write_phase;
    next_advance_done = advance_done;
    next_last_leaf_r = last_leaf_r;
    next_commit_is_right = commit_is_right;
    next_hash_idx = hash_idx;
    next_last_byte_prev = last_byte_prev;
    next_squeeze_idx = squeeze_idx;
    next_leaf1_done = leaf1_done;
    next_leaf2_done = leaf2_done;
    next_cache_idx_shift_r  = cache_idx_shift_r;
    next_cache_idx_shift2_r = cache_idx_shift2_r;

    aes1_key_int    = (ENC_KEYSIZE)'(parent);
    aes2_key_int    = (ENC_KEYSIZE)'(parent);
    aes1_enable_int = 0;
    aes2_enable_int = 0;

    fsm_done_o = 0;

    cache_data_int  = '0;
    cache_addr_int  = '0;
    cache_wr_en_int = 0;

    var_a_data_o  = '0;
    var_a_addr_o  = '0;
    var_a_wr_en_o = 1'b0;
    var_b_data_o  = '0;
    var_b_addr_o  = '0;
    var_b_wr_en_o = 1'b0;

    shake_start_o         = 0;
    shake_din_o           = '0;
    shake_din_valid_o     = 0;
    shake_last_din_o      = 0;
    shake_last_din_byte_o = '0;
    shake_dout_ready_o    = 0;

    case (state)

      // ========================================================
      // CACHE STATES (0-5)
      // ========================================================

      C_IDLE: begin
        if (get_next_leaf_i) begin
          // Capture cache_idx_shift; BRAM read starts in C_FETCH_SETUP.
          next_cache_idx_shift_r  = cache_idx_shift;
          next_cache_idx_shift2_r = cache_idx_shift2;

          if (leaf_idx_i + GGM_TREE_SIZE < CUTOFF)
            next_leaf_idx = (leaf_idx_tree << (2 + CACHE_TREE_DEPTH));
          else
            next_leaf_idx = (leaf_idx_tree << (1 + CACHE_TREE_DEPTH));

          if (leaf_idx2_i + GGM_TREE_SIZE < CUTOFF)
            next_leaf_idx_2 = (leaf_idx_tree2 << (2 + CACHE_TREE_DEPTH));
          else
            next_leaf_idx_2 = (leaf_idx_tree2 << (1 + CACHE_TREE_DEPTH));

          next_leaf1_done = 0;
          next_leaf2_done = 0;
          next_load_idx = 0;
          next_state = C_FETCH_SETUP;
        end
      end

      // Start BRAM read from registered cache_idx_r (+1 cycle per fetch;
      // see cache_idx_shift_r).
      C_FETCH_SETUP: begin
        cache_addr_int = NR_STORE[CACHE_ADDR_WIDTH-1:0] * cache_idx_r;
        next_load_idx  = 1;
        next_state     = C_GET_PARENT;
      end

      // Load parent 1 from cache BRAM; also handles AES1 fire retry (load_idx==0)
      C_GET_PARENT: begin
        cache_addr_int = cache_mem_addr_rr;

        if (load_idx == 0) begin
          if (ZERO_DESCENT) begin
            next_state = C_GET_PARENT2_WAIT;
          end else begin
            aes1_key_int = (ENC_KEYSIZE)'(parent);
            if (aes1_ready_i) aes1_enable_int = 1;
            if (eff_fire_accepted1) next_state = C_GET_PARENT2_WAIT;
          end
        end else if (load_idx == 1) begin
          next_load_idx = load_idx + 1;
          next_parent   = (LAMBDA)'(cache_data_i);
        end else if (load_idx < NR_STORE) begin
          next_parent   = parent ^ ((LAMBDA)'(cache_data_i) << ((load_idx - 1) * MEM_SIZE));
          next_load_idx = load_idx + 1;
        end else begin
          // re-enter at load_idx=0 to fire AES1 from registered values
          next_parent = parent ^ ((LAMBDA)'(cache_data_i) << ((load_idx - 1) * MEM_SIZE));
          next_load_idx = 0;
          next_load_idx2 = 0;
          next_idx = IDX_BITS'(cache_idx_shift_r);
          next_state = C_GET_PARENT;
        end
      end

      C_GET_PARENT2_WAIT: begin
        aes1_key_int = (ENC_KEYSIZE)'(parent);
        cache_addr_int = cache_mem_addr2_rr;
        next_load_idx2 = 1;
        next_state = C_GET_PARENT2;
      end

      // Load parent 2 from cache BRAM; also handles AES2 fire retry (load_idx2==0)
      C_GET_PARENT2: begin
        aes1_key_int = (ENC_KEYSIZE)'(parent);
        cache_addr_int = cache_mem_addr2_rr;

        if (load_idx2 == 0) begin
          if (ZERO_DESCENT) begin
            next_leaf_stored2 = parent2;
            next_state = C_DONE;
          end else begin
            aes2_key_int = (ENC_KEYSIZE)'(parent2);
            if (aes2_ready_i) aes2_enable_int = 1;
            if (eff_fire_accepted2) next_state = C_STEP;
          end
        end else if (load_idx2 == 1) begin
          next_load_idx2 = load_idx2 + 1;
          next_parent2   = (LAMBDA)'(cache_data_i);
        end else if (load_idx2 < NR_STORE) begin
          next_parent2   = parent2 ^ ((LAMBDA)'(cache_data_i) << ((load_idx2 - 1) * MEM_SIZE));
          next_load_idx2 = load_idx2 + 1;
        end else begin
          // re-enter at load_idx2=0 to fire AES2 from registered values
          next_parent2 = parent2 ^ ((LAMBDA)'(cache_data_i) << ((load_idx2 - 1) * MEM_SIZE));
          next_load_idx2 = 0;
          next_idx2 = IDX_BITS'(cache_idx_shift2_r);
          next_state = C_GET_PARENT2;
        end
      end

      // Parallel dual-leaf descent
      C_STEP: begin
        aes1_key_int = (ENC_KEYSIZE)'(parent);
        aes2_key_int = (ENC_KEYSIZE)'(parent2);

        if ((leaf1_done || aes1_valid_i) && (leaf2_done || aes2_valid_i)) begin
          if (!leaf1_done) begin
            next_idx = IDX_BITS'(2 * idx + IDX_BITS'(dir_bit));
            next_parent = cache_child1;
            next_leaf_idx = leaf_idx << 1;

            if (IDX_BITS'(2 * idx + IDX_BITS'(dir_bit)) < IDX_BITS'(leaf_idx_tree)) begin
              aes1_enable_int = 1;
              aes1_key_int = (ENC_KEYSIZE)'(cache_child1);
            end else begin
              next_leaf1_done = 1;
            end
          end

          if (!leaf2_done) begin
            next_idx2 = IDX_BITS'(2 * idx2 + IDX_BITS'(dir_bit2));
            next_parent2 = cache_child2;
            next_leaf_idx_2 = leaf_idx_2 << 1;

            if (IDX_BITS'(2 * idx2 + IDX_BITS'(dir_bit2)) < IDX_BITS'(leaf_idx_tree2)) begin
              aes2_enable_int = 1;
              aes2_key_int = (ENC_KEYSIZE)'(cache_child2);
            end else begin
              next_leaf_stored2 = cache_child2;
              next_leaf2_done = 1;
            end
          end

          if (next_leaf1_done && next_leaf2_done)
            next_state = C_DONE;
        end
      end

      C_DONE: begin
        fsm_done_o = 1;
        next_state = C_IDLE;
        next_leaf1_done = 0;
        next_leaf2_done = 0;
      end

      // ========================================================
      // DFS STATES (6-15)
      // ========================================================

      S_IDLE: begin
        if (fsm_start_i) begin
          next_idx = IDX_BITS'(GGM_TREE_SIZE);
          next_parent = rseed_i;
          next_idx2 = IDX_BITS'(1);
          next_descent_depth = '0;

          if ((GGM_TREE_DEPTH + 1)'(GGM_TREE_SIZE) < CUTOFF) begin
            next_leaf_depth = DEPTH_BITS'(GGM_TREE_DEPTH - 1);
            next_leaf_idx = (GGM_TREE_DEPTH + 1)'(GGM_TREE_SIZE) << 2;
          end else begin
            next_leaf_depth = DEPTH_BITS'(GGM_TREE_DEPTH);
            next_leaf_idx = (GGM_TREE_DEPTH + 1)'(GGM_TREE_SIZE) << 1;
          end

          shake_start_o = 1;
          next_last_byte_prev = HASH_BAVC_PREFIX;

          next_state = S_DESC_PRNG;
        end
      end

      S_DESC_PRNG: begin
        if (aes1_ready_i && aes2_ready_i) begin
          aes1_enable_int = 1;
          aes2_enable_int = 1;
          next_state = S_DESC_STEP;
        end
      end

      S_DESC_STEP: begin
        if (aes1_valid_i && aes2_valid_i) begin
          next_parent = path_child;
          next_parent2 = sib_child;
          next_leaf_idx = leaf_idx << 1;
          next_descent_depth = descent_depth + DEPTH_BITS'(1);
          next_idx2 = next_idx2_comb;
          next_at_leaf = (descent_depth + DEPTH_BITS'(1) == leaf_depth);

          next_load_idx = '0;
          next_state = S_DESC_WRITE;
        end
      end

      S_DESC_WRITE: begin
        // cache_write_phase: 0 = write sibling to scratchpad
        //                    1 = write path node to tree-cache BRAM (cache depth only)
        //                    2 = write sibling node to tree-cache BRAM (cache depth only)
        if (cache_write_phase == 2'd0) begin
          // Phase 0: write sibling (parent2) to var_bram scratch region
          var_a_addr_o  = phys_a(VAR_ADDR_WIDTH_COMBINED'(descent_depth * LAMBDA_DIV_64 + load_idx));
          var_a_data_o  = split_a(parent2[load_idx * 64 +: 64]);
          var_a_wr_en_o = 1'b1;
          var_b_addr_o  = phys_b(VAR_ADDR_WIDTH_COMBINED'(descent_depth * LAMBDA_DIV_64 + load_idx));
          var_b_data_o  = split_b(parent2[load_idx * 64 +: 64]);
          var_b_wr_en_o = CAN_DUAL ? 1'b0 : 1'b1;

          if (load_idx < NR_STORE[3:0] - 4'd1) begin
            next_load_idx = load_idx + 4'd1;
          end else begin
            if (descent_depth == DEPTH_BITS'(CACHE_TREE_DEPTH)) begin
              next_cache_write_phase = 2'd1;
              next_load_idx = '0;
            end else begin
              if (at_leaf) begin
                next_idx2 = idx;
                next_state = S_COMMIT_FIRE;
              end else
                next_state = S_DESC_PRNG;
            end
          end
        end else if (cache_write_phase == 2'd1) begin
          // Phase 1: write path node (parent) to cache tree region
          cache_wr_en_int = 1;
          cache_addr_int = CACHE_ADDR_WIDTH'(idx2 - (1 << CACHE_TREE_DEPTH))
                         * NR_STORE[CACHE_ADDR_WIDTH-1:0]
                         + CACHE_ADDR_WIDTH'(load_idx);
          cache_data_int = parent[load_idx * MEM_SIZE +: MEM_SIZE];

          if (load_idx < NR_STORE[3:0] - 4'd1) begin
            next_load_idx = load_idx + 4'd1;
          end else begin
            next_cache_write_phase = 2'd2;
            next_load_idx = '0;
          end
        end else begin
          // Phase 2: write sibling (parent2) to its cache tree slot
          cache_wr_en_int = 1;
          cache_addr_int = CACHE_ADDR_WIDTH'((idx2 ^ IDX_BITS'(1)) - (1 << CACHE_TREE_DEPTH))
                         * NR_STORE[CACHE_ADDR_WIDTH-1:0]
                         + CACHE_ADDR_WIDTH'(load_idx);
          cache_data_int = parent2[load_idx * MEM_SIZE +: MEM_SIZE];

          if (load_idx < NR_STORE[3:0] - 4'd1) begin
            next_load_idx = load_idx + 4'd1;
          end else begin
            next_cache_write_phase = 2'd0;
            if (at_leaf) begin
              next_idx2 = idx;
              next_state = S_COMMIT_FIRE;
            end else
              next_state = S_DESC_PRNG;
          end
        end
      end

      S_COMMIT_FIRE: begin
        // AES key = parent (default), which equals the leaf value at this point

        if (aes1_ready_i && aes2_ready_i) begin
          aes1_enable_int = 1;
          aes2_enable_int = 1;

          next_last_leaf_r = is_last_leaf;

          if (!is_last_leaf) begin
            next_idx = IDX_BITS'(next_idx_wire);
            next_leaf_depth = next_leaf_depth_comb;
            next_recompute_levels_r = recompute_levels_comb;
            next_diverge_depth_r = diverge_depth_comb;

            if (diverge_depth_comb == '0) begin
              next_parent = rseed_i;
              next_idx2 = IDX_BITS'(1);
              next_descent_depth = '0;
              if (next_idx_wire < CUTOFF)
                next_leaf_idx = (GGM_TREE_DEPTH + 1)'(next_idx_wire) << 2;
              else
                next_leaf_idx = (GGM_TREE_DEPTH + 1)'(next_idx_wire) << 1;
              next_advance_done = 1;
            end else begin
              next_load_idx = 4'd0;
              next_advance_done = 0;
            end
          end else begin
            next_advance_done = 1;
          end

          next_state = S_COMMIT_WAIT;
        end
      end

      S_COMMIT_WAIT: begin
        // AES key: already latched at fire time. Wire value irrelevant.

        // Parallel var_bram read for advance (sibling stored in var_bram scratch)
        if (!advance_done) begin
          var_a_addr_o = phys_a(VAR_ADDR_WIDTH_COMBINED'(diverge_depth_r * LAMBDA_DIV_64 + load_idx));
          var_b_addr_o = phys_b(VAR_ADDR_WIDTH_COMBINED'(diverge_depth_r * LAMBDA_DIV_64 + load_idx));

          if (load_idx == 4'd0) begin
            next_load_idx = 4'd1;
          end else if (load_idx == 4'd1) begin
            next_parent = (LAMBDA)'(var_sib_word);
            next_load_idx = load_idx + 4'd1;
          end else if (load_idx < NR_STORE[3:0]) begin
            next_parent = parent ^ ((LAMBDA)'(var_sib_word) << ((load_idx - 4'd1) * 64));
            next_load_idx = load_idx + 4'd1;
          end else begin
            next_parent = parent ^ ((LAMBDA)'(var_sib_word) << ((load_idx - 4'd1) * 64));

            if (recompute_levels_r == '0) begin
              next_idx2 = idx;  // set idx2=tree_idx for next commit plaintext
            end else begin
              next_descent_depth = diverge_depth_r;
              next_idx2 = IDX_BITS'(idx >> recompute_levels_r);
              if (idx < IDX_BITS'(CUTOFF))
                next_leaf_idx = (GGM_TREE_DEPTH + 1)'(idx) << (2 + diverge_depth_r);
              else
                next_leaf_idx = (GGM_TREE_DEPTH + 1)'(idx) << (1 + diverge_depth_r);
            end
            next_advance_done = 1;
          end
        end

        if (aes1_valid_i && aes2_valid_i && advance_done) begin
          next_parent2 = left_child;
          next_leaf_stored2 = right_child;
          next_commit_is_right = 0;
          next_hash_idx = '0;
          next_state = S_HASH_COMMIT;
        end
      end

      S_HASH_COMMIT: begin
        shake_din_valid_o = 1;
        shake_din_o = hash_word;

        if (shake_din_ready_i) begin
          if (hash_idx == HASH_IDX_BITS'(LAMBDA_DIV_64 - 1)) begin
            next_last_byte_prev = parent2[7:0];

            if (!commit_is_right) begin
              next_commit_is_right = 1;
              next_hash_idx = '0;
              next_parent2 = leaf_stored2;  // copy right commit into parent2
            end else begin
              next_commit_is_right = 0;
              if (last_leaf_r)
                next_state = S_FINALIZE_HASH;
              else if (recompute_levels_r == '0)
                next_state = S_COMMIT_FIRE;
              else
                next_state = S_DESC_PRNG;
            end
          end else begin
            next_hash_idx = hash_idx + HASH_IDX_BITS'(1);
          end
        end
      end

      S_FINALIZE_HASH: begin
        shake_din_valid_o     = 1;
        shake_din_o           = {last_byte_prev, 56'b0};
        shake_last_din_o      = 1;
        shake_last_din_byte_o = 4'd1;

        if (shake_din_ready_i) begin
          next_squeeze_idx = '0;
          next_state = S_SQUEEZE;
        end
      end

      S_SQUEEZE: begin
        shake_dout_ready_o = 1;

        if (shake_dout_valid_i) begin
          var_a_data_o  = split_a(shake_dout_i);
          var_a_addr_o  = phys_a(VAR_ADDR_WIDTH_COMBINED'(HCOM_VAR_OFFSET + squeeze_idx));
          var_a_wr_en_o = 1'b1;
          var_b_data_o  = split_b(shake_dout_i);
          var_b_addr_o  = phys_b(VAR_ADDR_WIDTH_COMBINED'(HCOM_VAR_OFFSET + squeeze_idx));
          var_b_wr_en_o = CAN_DUAL ? 1'b0 : 1'b1;

          if (squeeze_idx == SQUEEZE_IDX_BITS'(SQUEEZE_WORDS - 1))
            next_state = S_DONE;
          else
            next_squeeze_idx = squeeze_idx + SQUEEZE_IDX_BITS'(1);
        end
      end

      S_DONE: begin
        fsm_done_o = 1;
        next_state = C_IDLE;
      end

      default: next_state = S_IDLE;
    endcase
  end
  // Register update

  always_ff @(posedge clk_i or posedge rst_i) begin
    if (rst_i) begin
      state           <= S_IDLE;
      parent          <= '0;
      parent2         <= '0;
      leaf_stored2    <= '0;
      idx             <= IDX_BITS'(1);
      idx2            <= IDX_BITS'(1);
      leaf_idx        <= '0;
      leaf_idx_2      <= '0;
      load_idx        <= '0;
      load_idx2       <= '0;
      descent_depth   <= '0;
      leaf_depth      <= '0;
      at_leaf         <= 0;
      diverge_depth_r <= '0;
      recompute_levels_r <= '0;
      cache_write_phase  <= 2'd0;
      advance_done    <= 0;
      last_leaf_r     <= 0;
      commit_is_right <= 0;
      hash_idx        <= '0;
      last_byte_prev  <= '0;
      squeeze_idx     <= '0;
      leaf1_done      <= 0;
      leaf2_done      <= 0;
      cache_idx_shift_r  <= '0;
      cache_idx_shift2_r <= '0;
      c_step_next_idx_reg  <= '0;
      c_step_next_idx2_reg <= '0;
    end else begin
      state           <= next_state;
      parent          <= next_parent;
      parent2         <= next_parent2;
      leaf_stored2    <= next_leaf_stored2;
      idx             <= next_idx;
      idx2            <= next_idx2;
      leaf_idx        <= next_leaf_idx;
      leaf_idx_2      <= next_leaf_idx_2;
      load_idx        <= next_load_idx;
      load_idx2       <= next_load_idx2;
      descent_depth   <= next_descent_depth;
      leaf_depth      <= next_leaf_depth;
      at_leaf         <= next_at_leaf;
      diverge_depth_r <= next_diverge_depth_r;
      recompute_levels_r <= next_recompute_levels_r;
      cache_write_phase  <= next_cache_write_phase;
      advance_done    <= next_advance_done;
      last_leaf_r     <= next_last_leaf_r;
      commit_is_right <= next_commit_is_right;
      hash_idx        <= next_hash_idx;
      last_byte_prev  <= next_last_byte_prev;
      squeeze_idx     <= next_squeeze_idx;
      leaf1_done      <= next_leaf1_done;
      leaf2_done      <= next_leaf2_done;
      cache_idx_shift_r  <= next_cache_idx_shift_r;
      cache_idx_shift2_r <= next_cache_idx_shift2_r;
      c_step_next_idx_reg  <= c_step_next_idx_comb;
      c_step_next_idx2_reg <= c_step_next_idx2_comb;
      cache_xor_idx_r      <= next_idx;
      cache_xor_idx2_r     <= next_idx2;
    end
  end

endmodule
