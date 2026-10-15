// SPDX-FileCopyrightText: 2026 Stef Halmans, Niklas Höher
// SPDX-License-Identifier: LicenseRef-RUB-SecEng

import sdith_params_pkg::*;

// get_leaf_combined_nohcom
//
// BFS tree-cache builder + cache-mode dual-leaf fetcher.
// Used when HCOM_IN_PHASE12=1, where commit hashing is done downstream in
// blc_commit_phase12_hcom. This path is not KAT-faithful (the h_com
// absorption order differs from the reference implementation).
//
// Build stage (S_BFS_*): level-order walk down to the tree-cache depth.
// For each internal node, fires both AES cores to produce the left and
// right children and writes them into the tree-cache BRAM. Modular
// indexing reuses memory positions so that position p ends up holding the
// node at tree index (CACHE_ENTRIES + p).
//
// Cache-mode states (C_*) are identical to get_leaf_combined: descend
// from cached nodes to produce leaf seeds for racc/commit in phase12.
//
// Cycle estimate per parent: 1 (fire) + AES_LATENCY + 3*NR_STORE + 2.
// Total build: (CACHE_ENTRIES-1) x (AES_LAT + 3*NR_STORE + 2) cycles.

module get_leaf_combined_nohcom #(
    parameter MEM_SIZE = 64
) (
    input logic clk_i,
    input logic rst_i,

    // Tree-cache build control
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

    // AES engine 1 (left child in BFS, leaf 1 in cache mode)
    output logic [ENC_KEYSIZE-1:0]   aes1_key_o,
    output logic [ENC_BLOCKSIZE-1:0] aes1_plaintext_o,
    input  logic [ENC_BLOCKSIZE-1:0] aes1_ciphertext_i,
    output logic                     aes1_enable_o,
    input  logic                     aes1_ready_i,
    input  logic                     aes1_valid_i,

    // AES engine 2 (right child in BFS, leaf 2 in cache mode)
    output logic [ENC_KEYSIZE-1:0]   aes2_key_o,
    output logic [ENC_BLOCKSIZE-1:0] aes2_plaintext_o,
    input  logic [ENC_BLOCKSIZE-1:0] aes2_ciphertext_i,
    output logic                     aes2_enable_o,
    input  logic                     aes2_ready_i,
    input  logic                     aes2_valid_i,

    // Fire accepted (cache mode; tied to 1 in BFS by bfs_mode)
    input  logic fire_accepted1_i,
    input  logic fire_accepted2_i,

    // Tree-cache BRAM (single-port; build stage writes children, cache mode reads)
    input  logic [MEM_SIZE-1:0]     cache_data_i,
    output logic [MEM_SIZE-1:0]     cache_data_o,
    output logic [CACHE_ADDR_WIDTH-1:0] cache_addr_o,
    output logic                    cache_wr_en_o
);
  // Parameters

  localparam int NR_STORE     = LAMBDA / MEM_SIZE;
  localparam int IDX_BITS     = GGM_TREE_DEPTH + 2;
  localparam int BFS_IDX_BITS = CACHE_TREE_DEPTH + 1;
  localparam int ZERO_DESCENT = (CACHE_TREE_DEPTH >= GGM_TREE_DEPTH - 1) ? 1 : 0;
  localparam int CACHE_LEAVES = CACHE_ENTRIES;
  // For BFS, internal nodes are 0..CACHE_LEAVES-2 (total CACHE_LEAVES-1 nodes).
  // The root is bfs_idx=0 with parent register seeded by rseed_i in S_IDLE.
  // State encoding preserved exactly (cache states 0-5 + 20, BFS states 6-11, done=15).
  // fsm_encoding="none" preserves binary encoding for synthesis constraints.
  typedef enum logic [4:0] {
    // Cache-mode states
    C_IDLE             = 5'd0,
    C_GET_PARENT       = 5'd1,
    C_GET_PARENT2_WAIT = 5'd2,
    C_GET_PARENT2      = 5'd3,
    C_STEP             = 5'd4,
    C_DONE             = 5'd5,
    // BFS-mode states (populate cache tree only - no leaf-level descent)
    S_IDLE             = 5'd6,
    S_BFS_FIRE         = 5'd7,
    S_BFS_WAIT         = 5'd8,
    S_BFS_WR_L         = 5'd9,
    S_BFS_WR_R         = 5'd10,
    S_BFS_NEXT         = 5'd11,
    S_DONE             = 5'd15,
    C_FETCH_SETUP      = 5'd20    // pipelines cache_idx_shift
  } state_t;

  (* fsm_encoding = "none" *) state_t state;
  state_t next_state;

  // bfs_mode covers all states that drive AES with parent/BFS-derived plaintext.
  wire bfs_mode = (state == S_BFS_FIRE) || (state == S_BFS_WAIT);

  // Parent seed - holds rseed_i initially, then loaded from cache in S_BFS_NEXT
  reg [LAMBDA-1:0] parent, next_parent;

  // Second parent register for cache mode (the C_* states track two
  // independent descents).
  reg [LAMBDA-1:0] parent2, next_parent2;

  // Cache-mode leaf outputs
  reg [LAMBDA-1:0] leaf_stored2, next_leaf_stored2;

  // Cache-mode index registers (shared with cache descent tracking)
  reg [IDX_BITS-1:0] idx,  next_idx;
  reg [IDX_BITS-1:0] idx2, next_idx2;
  reg [GGM_TREE_DEPTH:0] leaf_idx,   next_leaf_idx;
  reg [GGM_TREE_DEPTH:0] leaf_idx_2, next_leaf_idx_2;
  reg [3:0] load_idx,  next_load_idx;
  reg [3:0] load_idx2, next_load_idx2;

  // BFS-mode registers
  reg [BFS_IDX_BITS-1:0] bfs_idx,    next_bfs_idx;
  reg [LAMBDA-1:0]       left_child_r,  next_left_child_r;
  reg [LAMBDA-1:0]       right_child_r, next_right_child_r;

  // Cache-mode completion flags
  reg leaf1_done, next_leaf1_done;
  reg leaf2_done, next_leaf2_done;

  // Cache pipeline registers (registered cache_idx_shift - breaks long path)
  reg [CACHE_ADDR_WIDTH-1:0] cache_idx_shift_r,  next_cache_idx_shift_r;
  reg [CACHE_ADDR_WIDTH-1:0] cache_idx_shift2_r, next_cache_idx_shift2_r;
  // Shared combinational wires

  wire [GGM_TREE_DEPTH:0] CUTOFF = (GGM_TREE_DEPTH + 1)'(1) << GGM_TREE_DEPTH;

  // Cache-mode direction bits. dir_bit/dir_bit2 use the CURRENT leaf_idx MSB
  // (for extracting child halves in C_STEP); msb_next/msb_next2 use the
  // next-cycle MSB for the pipelined plaintext computation.
  wire dir_bit   = leaf_idx[GGM_TREE_DEPTH];
  wire dir_bit2  = leaf_idx_2[GGM_TREE_DEPTH];
  wire msb_next  = next_leaf_idx[GGM_TREE_DEPTH];
  wire msb_next2 = next_leaf_idx_2[GGM_TREE_DEPTH];

  // Cache-mode child extraction (direction-dependent slice per engine).
  wire [LAMBDA-1:0] cache_child1, cache_child2;
  generate
    if (SECURITY_LEVEL == 3) begin : g_cache_sec3
      assign cache_child1 = dir_bit  ? aes1_ciphertext_i[ENC_BLOCKSIZE-1:64] : (LAMBDA)'(aes1_ciphertext_i);
      assign cache_child2 = dir_bit2 ? aes2_ciphertext_i[ENC_BLOCKSIZE-1:64] : (LAMBDA)'(aes2_ciphertext_i);
    end else begin : g_cache_sec1_5
      assign cache_child1 = (LAMBDA)'(aes1_ciphertext_i);
      assign cache_child2 = (LAMBDA)'(aes2_ciphertext_i);
    end
  endgenerate

  // Build-mode child extraction (left from AES1, right from AES2).
  // Slicing matches the descent PRG in the reference sdith_prng.c for SEC3:
  // left child from the high 192 bits of block 0, right child from the low
  // 192 bits of block 1. In the big-endian SV byte convention,
  // (LAMBDA)'(ct) selects the high bytes and ct[BLOCK-1:64] the low bytes.
  wire [LAMBDA-1:0] bfs_left_child  = (LAMBDA)'(aes1_ciphertext_i);
  wire [LAMBDA-1:0] bfs_right_child;
  generate
    if (SECURITY_LEVEL == 3) begin : g_bfs_sec3
      assign bfs_right_child = aes2_ciphertext_i[ENC_BLOCKSIZE-1:64];
    end else begin : g_bfs_sec1_5
      assign bfs_right_child = (LAMBDA)'(aes2_ciphertext_i);
    end
  endgenerate
  // AES plaintext synthesis

  // Salt shifted into the high bytes for SEC3 (matches C's
  // memcpy(ctr256.v8+8, salt192, 24) which places salt_i at bytes [8..31]).
  wire [ENC_BLOCKSIZE-1:0] salt_shifted = (ENC_BLOCKSIZE)'(salt_i) << (SECURITY_LEVEL == 3 ? 64 : 0);

  // BFS mode: both AES use the same parent-tree-index as XOR value.
  // Parent tree index (root=1) = bfs_idx + 1. CTR value = 2 * (bfs_idx + 1).
  // offset_bit 0 -> AES1 (left), 1 -> AES2 (right).
  wire [IDX_BITS:0] bfs_xor_val  = (IDX_BITS+1)'(2 * (bfs_idx + 1));

  // Cache mode: plaintext per cache descent step - uses next_idx/next_idx2
  // and the MSB of the shifting leaf_idx/leaf_idx_2 (direction bit for the
  // NEXT descent step).
  wire [IDX_BITS:0] cache_xor_val1 = (IDX_BITS+1)'(2 * next_idx);
  wire [IDX_BITS:0] cache_xor_val2 = (IDX_BITS+1)'(2 * next_idx2);

  wire [IDX_BITS:0] aes1_xor_val = bfs_mode ? bfs_xor_val  : cache_xor_val1;
  wire [IDX_BITS:0] aes2_xor_val = bfs_mode ? bfs_xor_val  : cache_xor_val2;

  wire aes1_offset_bit = bfs_mode ? 1'b0 : msb_next;
  wire aes2_offset_bit = bfs_mode ? 1'b1 : msb_next2;

  // Offset bit applied with XOR rather than the arithmetic add used by the
  // reference implementation (which can carry when salt_i bit 0 is set). This
  // path is not KAT-faithful anyway, and every expansion in this module uses
  // the same XOR form, so the resulting tree is self-consistent.
  wire [ENC_BLOCKSIZE-1:0] aes1_pt_pre = salt_shifted
                                        ^ (ENC_BLOCKSIZE)'(aes1_xor_val)
                                        ^ (ENC_BLOCKSIZE)'(aes1_offset_bit);
  wire [ENC_BLOCKSIZE-1:0] aes2_pt_pre = salt_shifted
                                        ^ (ENC_BLOCKSIZE)'(aes2_xor_val)
                                        ^ (ENC_BLOCKSIZE)'(aes2_offset_bit);

  assign aes1_plaintext_o = {<<8{aes1_pt_pre}};
  assign aes2_plaintext_o = {<<8{aes2_pt_pre}};

  // AES keys and enables driven by FSM below
  logic [ENC_KEYSIZE-1:0] aes1_key_int, aes2_key_int;
  logic aes1_enable_int, aes2_enable_int;
  assign aes1_key_o    = aes1_key_int;
  assign aes2_key_o    = aes2_key_int;
  assign aes1_enable_o = aes1_enable_int;
  assign aes2_enable_o = aes2_enable_int;

  // Fire-accepted (BFS: always 1; cache: driven from top-level mux).
  wire eff_fire_accepted1 = bfs_mode ? 1'b1 : fire_accepted1_i;
  wire eff_fire_accepted2 = bfs_mode ? 1'b1 : fire_accepted2_i;

  // Leaf outputs
  assign leaf_o  = parent;
  assign leaf2_o = leaf_stored2;
  // Cache BRAM output

  logic [MEM_SIZE-1:0]     cache_data_int;
  logic [CACHE_ADDR_WIDTH-1:0] cache_addr_int;
  logic                    cache_wr_en_int;
  assign cache_data_o  = cache_data_int;
  assign cache_addr_o  = cache_addr_int;
  assign cache_wr_en_o = cache_wr_en_int;
  // BFS child indices (0-indexed BFS, modular to fit in CACHE_LEAVES slots)

  // bfs_child1 = 2*bfs_idx + 1, bfs_child2 = bfs_child1 + 1. Internal
  // children (idx < CACHE_LEAVES-1) are stored at their BFS index and later
  // overwritten by their own children; leaf children wrap to
  // idx + 1 - CACHE_LEAVES, so positions 0..CACHE_LEAVES-1 end up holding
  // the leaves in order (matches cache_mem_addr = position * NR_STORE).
  wire [BFS_IDX_BITS:0] bfs_child1 = (BFS_IDX_BITS+1)'({bfs_idx, 1'b1});
  wire [BFS_IDX_BITS:0] bfs_child2 = bfs_child1 + (BFS_IDX_BITS+1)'(1);

  wire [BFS_IDX_BITS:0] CACHE_LEAVES_VEC = (BFS_IDX_BITS+1)'(CACHE_LEAVES);
  wire [BFS_IDX_BITS:0] CACHE_LEAVES_MINUS_1 = (BFS_IDX_BITS+1)'(CACHE_LEAVES - 1);

  wire [BFS_IDX_BITS-1:0] bfs_child1_mod =
      (bfs_child1 < CACHE_LEAVES_MINUS_1)
          ? BFS_IDX_BITS'(bfs_child1)
          : BFS_IDX_BITS'(bfs_child1 + (BFS_IDX_BITS+1)'(1) - CACHE_LEAVES_VEC);
  wire [BFS_IDX_BITS-1:0] bfs_child2_mod =
      (bfs_child2 < CACHE_LEAVES_MINUS_1)
          ? BFS_IDX_BITS'(bfs_child2)
          : BFS_IDX_BITS'(bfs_child2 + (BFS_IDX_BITS+1)'(1) - CACHE_LEAVES_VEC);

  wire [CACHE_ADDR_WIDTH-1:0] bfs_wr_l_addr =
      CACHE_ADDR_WIDTH'(bfs_child1_mod) * NR_STORE[CACHE_ADDR_WIDTH-1:0]
      + CACHE_ADDR_WIDTH'(load_idx);
  wire [CACHE_ADDR_WIDTH-1:0] bfs_wr_r_addr =
      CACHE_ADDR_WIDTH'(bfs_child2_mod) * NR_STORE[CACHE_ADDR_WIDTH-1:0]
      + CACHE_ADDR_WIDTH'(load_idx);
  // Next-parent read: parent at BFS position bfs_idx (already incremented in
  // S_BFS_WR_R -> S_BFS_NEXT transition) lives at position bfs_idx * NR_STORE.
  wire [CACHE_ADDR_WIDTH-1:0] bfs_rd_parent_addr =
      CACHE_ADDR_WIDTH'(bfs_idx) * NR_STORE[CACHE_ADDR_WIDTH-1:0]
      + CACHE_ADDR_WIDTH'(load_idx);
  // Cache-mode BRAM addr

  wire [GGM_TREE_DEPTH:0] leaf_idx_tree  = leaf_idx_i  + GGM_TREE_SIZE;
  wire [GGM_TREE_DEPTH:0] leaf_idx_tree2 = leaf_idx2_i + GGM_TREE_SIZE;

  wire [CACHE_ADDR_WIDTH-1:0] cache_idx_shift = (leaf_idx_tree < CUTOFF) ?
      (leaf_idx_tree >> (GGM_TREE_DEPTH - CACHE_TREE_DEPTH - 1)) :
      (leaf_idx_tree >> (GGM_TREE_DEPTH - CACHE_TREE_DEPTH));
  wire [CACHE_ADDR_WIDTH-1:0] cache_idx  = cache_idx_shift  & ~(CACHE_ADDR_WIDTH'(1 << CACHE_TREE_DEPTH));

  wire [CACHE_ADDR_WIDTH-1:0] cache_idx_shift2 = (leaf_idx_tree2 < CUTOFF) ?
      (leaf_idx_tree2 >> (GGM_TREE_DEPTH - CACHE_TREE_DEPTH - 1)) :
      (leaf_idx_tree2 >> (GGM_TREE_DEPTH - CACHE_TREE_DEPTH));
  wire [CACHE_ADDR_WIDTH-1:0] cache_idx2 = cache_idx_shift2 & ~(CACHE_ADDR_WIDTH'(1 << CACHE_TREE_DEPTH));

  wire [CACHE_ADDR_WIDTH-1:0] cache_idx_r  = cache_idx_shift_r  & ~(CACHE_ADDR_WIDTH'(1 << CACHE_TREE_DEPTH));
  wire [CACHE_ADDR_WIDTH-1:0] cache_idx2_r = cache_idx_shift2_r & ~(CACHE_ADDR_WIDTH'(1 << CACHE_TREE_DEPTH));
  wire [CACHE_ADDR_WIDTH-1:0] cache_mem_addr_rr  = load_idx  + NR_STORE * cache_idx_r;
  wire [CACHE_ADDR_WIDTH-1:0] cache_mem_addr2_rr = load_idx2 + NR_STORE * cache_idx2_r;
  // FSM

  always_comb begin
    next_state               = state;
    next_parent              = parent;
    next_parent2             = parent2;
    next_leaf_stored2        = leaf_stored2;
    next_idx                 = idx;
    next_idx2                = idx2;
    next_leaf_idx            = leaf_idx;
    next_leaf_idx_2          = leaf_idx_2;
    next_load_idx            = load_idx;
    next_load_idx2           = load_idx2;
    next_bfs_idx             = bfs_idx;
    next_left_child_r        = left_child_r;
    next_right_child_r       = right_child_r;
    next_leaf1_done          = leaf1_done;
    next_leaf2_done          = leaf2_done;
    next_cache_idx_shift_r   = cache_idx_shift_r;
    next_cache_idx_shift2_r  = cache_idx_shift2_r;

    aes1_key_int    = (ENC_KEYSIZE)'(parent);
    aes2_key_int    = (ENC_KEYSIZE)'(parent);
    aes1_enable_int = 1'b0;
    aes2_enable_int = 1'b0;

    fsm_done_o      = 1'b0;
    cache_data_int  = '0;
    cache_addr_int  = '0;
    cache_wr_en_int = 1'b0;

    case (state)

      // ========================================================
      // CACHE STATES
      // ========================================================

      C_IDLE: begin
        if (get_next_leaf_i) begin
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

          next_leaf1_done = 1'b0;
          next_leaf2_done = 1'b0;
          next_load_idx   = 4'd0;
          next_state      = C_FETCH_SETUP;
        end
      end

      C_FETCH_SETUP: begin
        cache_addr_int = NR_STORE[CACHE_ADDR_WIDTH-1:0] * cache_idx_r;
        next_load_idx  = 4'd1;
        next_state     = C_GET_PARENT;
      end

      C_GET_PARENT: begin
        cache_addr_int = cache_mem_addr_rr;

        if (load_idx == 4'd0) begin
          if (ZERO_DESCENT) begin
            next_state = C_GET_PARENT2_WAIT;
          end else begin
            aes1_key_int = (ENC_KEYSIZE)'(parent);
            if (aes1_ready_i) aes1_enable_int = 1'b1;
            if (eff_fire_accepted1) next_state = C_GET_PARENT2_WAIT;
          end
        end else if (load_idx == 4'd1) begin
          next_load_idx = load_idx + 4'd1;
          next_parent   = (LAMBDA)'(cache_data_i);
        end else if (load_idx < NR_STORE[3:0]) begin
          next_parent   = parent ^ ((LAMBDA)'(cache_data_i) << ((load_idx - 4'd1) * MEM_SIZE));
          next_load_idx = load_idx + 4'd1;
        end else begin
          next_parent    = parent ^ ((LAMBDA)'(cache_data_i) << ((load_idx - 4'd1) * MEM_SIZE));
          next_load_idx  = 4'd0;
          next_load_idx2 = 4'd0;
          next_idx       = IDX_BITS'(cache_idx_shift_r);
          next_state     = C_GET_PARENT;
        end
      end

      C_GET_PARENT2_WAIT: begin
        aes1_key_int   = (ENC_KEYSIZE)'(parent);
        cache_addr_int = cache_mem_addr2_rr;
        next_load_idx2 = 4'd1;
        next_state     = C_GET_PARENT2;
      end

      C_GET_PARENT2: begin
        aes1_key_int   = (ENC_KEYSIZE)'(parent);
        cache_addr_int = cache_mem_addr2_rr;

        if (load_idx2 == 4'd0) begin
          if (ZERO_DESCENT) begin
            next_leaf_stored2 = parent2;
            next_state = C_DONE;
          end else begin
            aes2_key_int = (ENC_KEYSIZE)'(parent2);
            if (aes2_ready_i) aes2_enable_int = 1'b1;
            if (eff_fire_accepted2) next_state = C_STEP;
          end
        end else if (load_idx2 == 4'd1) begin
          next_load_idx2 = load_idx2 + 4'd1;
          next_parent2   = (LAMBDA)'(cache_data_i);
        end else if (load_idx2 < NR_STORE[3:0]) begin
          next_parent2   = parent2 ^ ((LAMBDA)'(cache_data_i) << ((load_idx2 - 4'd1) * MEM_SIZE));
          next_load_idx2 = load_idx2 + 4'd1;
        end else begin
          next_parent2   = parent2 ^ ((LAMBDA)'(cache_data_i) << ((load_idx2 - 4'd1) * MEM_SIZE));
          next_load_idx2 = 4'd0;
          next_idx2      = IDX_BITS'(cache_idx_shift2_r);
          next_state     = C_GET_PARENT2;
        end
      end

      C_STEP: begin
        aes1_key_int = (ENC_KEYSIZE)'(parent);
        aes2_key_int = (ENC_KEYSIZE)'(parent2);

        if ((leaf1_done || aes1_valid_i) && (leaf2_done || aes2_valid_i)) begin
          if (!leaf1_done) begin
            next_idx      = IDX_BITS'(2 * idx + IDX_BITS'(dir_bit));
            next_parent   = cache_child1;
            next_leaf_idx = leaf_idx << 1;

            if (IDX_BITS'(2 * idx + IDX_BITS'(dir_bit)) < IDX_BITS'(leaf_idx_tree)) begin
              aes1_enable_int = 1'b1;
              aes1_key_int    = (ENC_KEYSIZE)'(cache_child1);
            end else begin
              next_leaf1_done = 1'b1;
            end
          end

          if (!leaf2_done) begin
            next_idx2       = IDX_BITS'(2 * idx2 + IDX_BITS'(dir_bit2));
            next_parent2    = cache_child2;
            next_leaf_idx_2 = leaf_idx_2 << 1;

            if (IDX_BITS'(2 * idx2 + IDX_BITS'(dir_bit2)) < IDX_BITS'(leaf_idx_tree2)) begin
              aes2_enable_int = 1'b1;
              aes2_key_int    = (ENC_KEYSIZE)'(cache_child2);
            end else begin
              next_leaf_stored2 = cache_child2;
              next_leaf2_done   = 1'b1;
            end
          end

          if (next_leaf1_done && next_leaf2_done)
            next_state = C_DONE;
        end
      end

      C_DONE: begin
        fsm_done_o       = 1'b1;
        next_state       = C_IDLE;
        next_leaf1_done  = 1'b0;
        next_leaf2_done  = 1'b0;
      end

      // ========================================================
      // BFS STATES (cache-tree build only)
      // ========================================================

      S_IDLE: begin
        if (fsm_start_i) begin
          next_parent      = rseed_i;
          next_bfs_idx     = '0;
          next_load_idx    = 4'd0;
          next_state       = S_BFS_FIRE;
        end
      end

      S_BFS_FIRE: begin
        aes1_key_int = (ENC_KEYSIZE)'(parent);
        aes2_key_int = (ENC_KEYSIZE)'(parent);
        if (aes1_ready_i && aes2_ready_i) begin
          aes1_enable_int = 1'b1;
          aes2_enable_int = 1'b1;
          next_state      = S_BFS_WAIT;
        end
      end

      S_BFS_WAIT: begin
        aes1_key_int = (ENC_KEYSIZE)'(parent);
        aes2_key_int = (ENC_KEYSIZE)'(parent);
        if (aes1_valid_i && aes2_valid_i) begin
          next_left_child_r  = bfs_left_child;
          next_right_child_r = bfs_right_child;
          next_load_idx      = 4'd0;
          next_state         = S_BFS_WR_L;
        end
      end

      S_BFS_WR_L: begin
        cache_wr_en_int = 1'b1;
        cache_addr_int  = bfs_wr_l_addr;
        cache_data_int  = left_child_r[load_idx * MEM_SIZE +: MEM_SIZE];
        if (load_idx < NR_STORE[3:0] - 4'd1) begin
          next_load_idx = load_idx + 4'd1;
        end else begin
          next_load_idx = 4'd0;
          next_state    = S_BFS_WR_R;
        end
      end

      S_BFS_WR_R: begin
        cache_wr_en_int = 1'b1;
        cache_addr_int  = bfs_wr_r_addr;
        cache_data_int  = right_child_r[load_idx * MEM_SIZE +: MEM_SIZE];
        if (load_idx < NR_STORE[3:0] - 4'd1) begin
          next_load_idx = load_idx + 4'd1;
        end else begin
          next_load_idx = 4'd0;
          if (bfs_idx == BFS_IDX_BITS'(CACHE_LEAVES - 2)) begin
            // last internal node
            next_state = S_DONE;
          end else begin
            next_bfs_idx = bfs_idx + BFS_IDX_BITS'(1);
            next_state   = S_BFS_NEXT;
          end
        end
      end

      // Pipeline: cycle k (load_idx=k, k=0..NR_STORE-1) issues addr for word k
      //           and LATCHES data for word (k-1) into parent.
      //           At k=NR_STORE (one cycle after last addr issue), latch the
      //           final word and transition to S_BFS_FIRE.
      S_BFS_NEXT: begin
        if (load_idx < NR_STORE[3:0]) begin
          cache_addr_int = bfs_rd_parent_addr;
        end

        if (load_idx == 4'd0) begin
          next_load_idx = load_idx + 4'd1;
        end else if (load_idx == 4'd1) begin
          next_parent   = (LAMBDA)'(cache_data_i);
          next_load_idx = load_idx + 4'd1;
        end else if (load_idx < NR_STORE[3:0]) begin
          next_parent   = parent ^ ((LAMBDA)'(cache_data_i) << ((load_idx - 4'd1) * MEM_SIZE));
          next_load_idx = load_idx + 4'd1;
        end else begin
          next_parent   = parent ^ ((LAMBDA)'(cache_data_i) << ((NR_STORE[3:0] - 4'd1) * MEM_SIZE));
          next_load_idx = 4'd0;
          next_state    = S_BFS_FIRE;
        end
      end

      S_DONE: begin
        fsm_done_o = 1'b1;
        next_state = C_IDLE;
      end

      default: next_state = S_IDLE;
    endcase
  end
  // Sequential update

  always_ff @(posedge clk_i or posedge rst_i) begin
    if (rst_i) begin
      state              <= S_IDLE;
      parent             <= '0;
      parent2            <= '0;
      leaf_stored2       <= '0;
      idx                <= IDX_BITS'(1);
      idx2               <= IDX_BITS'(1);
      leaf_idx           <= '0;
      leaf_idx_2         <= '0;
      load_idx           <= 4'd0;
      load_idx2          <= 4'd0;
      bfs_idx            <= '0;
      left_child_r       <= '0;
      right_child_r      <= '0;
      leaf1_done         <= 1'b0;
      leaf2_done         <= 1'b0;
      cache_idx_shift_r  <= '0;
      cache_idx_shift2_r <= '0;
    end else begin
      state              <= next_state;
      parent             <= next_parent;
      parent2            <= next_parent2;
      leaf_stored2       <= next_leaf_stored2;
      idx                <= next_idx;
      idx2               <= next_idx2;
      leaf_idx           <= next_leaf_idx;
      leaf_idx_2         <= next_leaf_idx_2;
      load_idx           <= next_load_idx;
      load_idx2          <= next_load_idx2;
      bfs_idx            <= next_bfs_idx;
      left_child_r       <= next_left_child_r;
      right_child_r      <= next_right_child_r;
      leaf1_done         <= next_leaf1_done;
      leaf2_done         <= next_leaf2_done;
      cache_idx_shift_r  <= next_cache_idx_shift_r;
      cache_idx_shift2_r <= next_cache_idx_shift2_r;
    end
  end

endmodule
