// SPDX-FileCopyrightText: 2026 Stef Halmans, Niklas Höher
// SPDX-License-Identifier: LicenseRef-RUB-SecEng

import sdith_params_pkg::*;
import sdith_helpers_pkg::*;

// process_pwit
//
// Inline PIOP prover engine (Algorithm 17 of the SDitH v2 spec).
//
// Palpha accumulation strategy:
//   Palpha[1..DEGREE] are accumulated in-place in sig memory at
//   PALPHA_SIG_OFFSET, starting from the P0 values already written there
//   by blc_commit_hlines. The final sig memory content is therefore
//   P0[c] XOR Palpha[c+1] - the check-zero gate output - with no separate
//   read-back step.  Palpha[0] (the y[gamma] constant term) is skipped: it
//   never enters the signature (spec eq. 1: Q[c] = Palpha[c+1] XOR P0[c]).
//
// One `gf_mul_serial` instance shared across layer-1 v*delta,
// layer-1 AES gamma*H' reduction, deep-layer v*diff folds, and UC.
// V limbs are loaded on-demand from BRAM via S_V_LIMB_RD.

module process_pwit (
    input  logic clk_i,
    input  logic rst_i,

    // Control
    input  logic fsm_start_i,
    output logic fsm_done_o,
    input  logic [$clog2(NUM_PWIT_CHUNKS)-1:0] chunk_idx_i,

    // SHAKE
    output logic        shake_start_o,
    output logic        shake_mode_o,
    output logic [63:0] shake_din_o,
    output logic        shake_din_valid_o,
    output logic        shake_last_din_o,
    output logic [ 3:0] shake_last_din_byte_o,
    output logic        shake_dout_ready_o,
    input  logic        shake_din_ready_i,
    input  logic [63:0] shake_dout_i,
    input  logic        shake_dout_valid_i,

    // Key memory (read-only)
    input  logic [63:0]             key_data_i,
    output logic [BRAM_ADDR_SIZE:0] key_addr_o,

    // Var BRAM dual-port
    input  logic [VAR_DATA_WIDTH_COMBINED-1:0] var_a_data_i,
    output logic [VAR_DATA_WIDTH_COMBINED-1:0] var_a_data_o,
    output logic [VAR_ADDR_WIDTH_COMBINED-1:0] var_a_addr_o,
    output logic                               var_a_wr_en_o,
    input  logic [VAR_DATA_WIDTH_COMBINED-1:0] var_b_data_i,
    output logic [VAR_DATA_WIDTH_COMBINED-1:0] var_b_data_o,
    output logic [VAR_ADDR_WIDTH_COMBINED-1:0] var_b_addr_o,
    output logic                               var_b_wr_en_o,

    // hash_lines seed for gamma, gamma' derivation.
    input  logic [2*LAMBDA-1:0] hlines_i,

    // Signature memory (RMW: reads P0, writes Palpha on final chunk).
    input  logic [63:0]                sig_data_i,
    output logic [63:0]                sig_data_o,
    output logic [SIG_ADDR_WIDTH-1:0]  sig_addr_o,
    output logic                       sig_wr_en_o,

    // Dual AES cores (H' column expansion via AES-CTR ping-pong)
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

    // Debug controls
    input  logic [I_CW-1:0]        dbg_i_limit_i,  // debug iteration cap: '1 = uncapped (normal, tied in piop.sv); 0 stops after first gamma' squeeze

    // Debug taps
    output logic [4*LAMBDA-1:0]     dbg_gamma_o,
    output logic [LAMBDA-1:0]       dbg_gamma_p_o,
    output logic [$clog2(W+1)-1:0]  dbg_i_cnt_o,

    // Layer-1 debug taps
    output logic [5:0]              dbg_state_o,
    output logic [LAMBDA-1:0]       dbg_delta_o,
    output logic [LAMBDA-1:0]       dbg_acc1_o,
    output logic [LAMBDA-1:0]       dbg_v_lo_o,
    output logic [LAMBDA-1:0]       dbg_base_o,
    output logic [LAMBDA-1:0]       dbg_mul_out_o,
    output logic                    dbg_mul_out_valid_o
);

  // =========================================================================
  // Derived constants
  // =========================================================================
  localparam int HLINES_WORDS   = 2 * LAMBDA_DIV_64;
  localparam int GAMMA_WORDS    = 4 * LAMBDA_DIV_64;
  localparam logic SHAKE_MODE_C = 1'b1;  // XOF mode for all security levels

  localparam int L1_V_BASE         = (HALF_POLY != 0) ? ROFF_HALF : CHUNK_WORDS;
  localparam int CW_R_L            = (TAU * KAPPA + 63) / 64;
  localparam int NODE_L1_WORDS_PER_TUPLE = 2 * CHUNK_WORDS;
  localparam int NUM_OUT_L1        = (M + MU1 - 1) / MU1;

  // Deep-layer geometry
  localparam int NUM_OUT_L2        = (NUM_OUT_L1 + MU2 - 1) / MU2;
  localparam int NUM_OUT_L3        = (NUM_OUT_L2 + MU3 - 1) / MU3;

  // c_pos[d] = sum_{d'<d} (arity[d']-1)  - flat index into control-bit array
  localparam int C_POS_D1 = MU1 - 1;
  localparam int C_POS_D2 = MU1 + MU2 - 2;
  localparam int C_POS_D3 = MU1 + MU2 + MU3 - 3;

  // DFS node buffer sizes
  localparam int DFS_L1_WORDS   = MU2 * 2 * CHUNK_WORDS;
  localparam int DFS_L2_WORDS   = MU3 * 3 * CHUNK_WORDS;
  localparam int DFS_L3_WORDS   = MU4 * 4 * CHUNK_WORDS;
  localparam int DFS_NODE_TOTAL = DFS_L1_WORDS + DFS_L2_WORDS + DFS_L3_WORDS;

  // V region sizing
  localparam int V_MAX_HALF        = (HALF1_BITS > HALF2_BITS) ? HALF1_BITS : HALF2_BITS;
  localparam int V_HALF_NODE_TOTAL = CHUNK_WORDS + V_MAX_HALF * CW_R_L + DFS_NODE_TOTAL;
  localparam int V_ENTRIES_MAX     = (HALF_POLY != 0 && V_HALF_NODE_TOTAL <= VAR_MEM_DEPTH_COMBINED)
      ? V_MAX_HALF : LAMBDA;
  localparam int ROW_V_WORDS_L     = V_ENTRIES_MAX * CW_R_L;

  // -- Var BRAM scratchpad layout --
  //
  // Scratchpad is packed directly after the V matrix output to minimise
  // the high-water mark (useful for ASIC memory sizing).
  //
  // HP=0: LJ scratch + DFS nodes overwrite the transpose scratch region
  //       (which is only used during GenV). Gamma is placed after
  //       TRANSPOSE_SCRATCH_END so GenV's next pass cannot corrupt it.
  // HP=1: DFS_L1 + lj_res + lj_a0 + uc_coeff remain below V in the
  //       freed racc/rbase region [0, ROFF_HALF).
  //       DFS_L2 + DFS_L3 + gamma are glued directly after V_in scatter.
  localparam int TRANSPOSE_SCRATCH_OFF =
      L1_V_BASE + ((PWIT_V_WORDS > ROW_V_WORDS_L) ? PWIT_V_WORDS : ROW_V_WORDS_L);
  localparam int TRANSPOSE_SCRATCH_END = TRANSPOSE_SCRATCH_OFF + 64;
  localparam int GEN_HALF_TOP = (HALF_POLY != 0) ? ROFF_HALF + VIN_WORDS_HALF : 0;

  localparam int UC_COEFF_BRAM_BASE = (HALF_POLY != 0)
      ? 0
      : TRANSPOSE_SCRATCH_OFF;
  localparam int LJ_A0_BRAM_BASE = (HALF_POLY != 0)
      ? CHUNK_WORDS
      : UC_COEFF_BRAM_BASE + CHUNK_WORDS;
  localparam int LJ_RES_BRAM_BASE = (HALF_POLY != 0)
      ? DEGREE * CHUNK_WORDS + CHUNK_WORDS
      : LJ_A0_BRAM_BASE + DEGREE * CHUNK_WORDS;
  localparam int DFS_L1_BASE = (HALF_POLY != 0)
      ? (DEGREE + 1) * CHUNK_WORDS + DEGREE * CHUNK_WORDS + CHUNK_WORDS
      : LJ_RES_BRAM_BASE + (DEGREE + 1) * CHUNK_WORDS;
  localparam int DFS_L2_BASE = (HALF_POLY != 0)
      ? GEN_HALF_TOP
      : DFS_L1_BASE + DFS_L1_WORDS;
  localparam int DFS_L3_BASE      = DFS_L2_BASE + DFS_L2_WORDS;
  localparam int GAMMA_BRAM_BASE_RAW = DFS_L3_BASE + DFS_L3_WORDS;
  localparam int GAMMA_BRAM_BASE  = (HALF_POLY == 0 && GAMMA_BRAM_BASE_RAW < TRANSPOSE_SCRATCH_END)
      ? TRANSPOSE_SCRATCH_END : GAMMA_BRAM_BASE_RAW;
  localparam int SCRATCHPAD_TOP   = GAMMA_BRAM_BASE + GAMMA_WORDS - 1;

  // synthesis translate_off
  initial if (HALF_POLY != 0)
      assert (DFS_L1_BASE + DFS_L1_WORDS <= L1_V_BASE)
          else $fatal(1, "Lower scratchpad overlaps V: TOP=%0d, V_BASE=%0d",
                      DFS_L1_BASE + DFS_L1_WORDS, L1_V_BASE);
  initial if (HALF_POLY != 0)
      assert (DFS_L2_BASE >= GEN_HALF_TOP)
          else $fatal(1, "Upper scratchpad overlaps V_in: DFS_L2=%0d, GEN_TOP=%0d",
                      DFS_L2_BASE, GEN_HALF_TOP);
  initial assert (SCRATCHPAD_TOP < VAR_MEM_DEPTH_COMBINED)
      else $fatal(1, "Scratchpad overflows BRAM: TOP=%0d, DEPTH=%0d",
                  SCRATCHPAD_TOP, VAR_MEM_DEPTH_COMBINED);
  // synthesis translate_on

  // Maximum output coefficients across deep layers (DEGREE+1 at d=3)
  localparam int LJ_MAX_OUT_COEFS = DEGREE + 1;
  localparam int LJ_MAX_OUT_WORDS = LJ_MAX_OUT_COEFS * CHUNK_WORDS;

  // AES H' column generation constants
  localparam int RSD_CODIM       = N_MINUS_K_RSD;
  localparam int RSD_CODIM_LIMBS = (RSD_CODIM + LAMBDA - 1) / LAMBDA;
  localparam int AES_TOTAL_BLOCKS = (K_RSD * RSD_CODIM + ENC_BLOCKSIZE - 1) / ENC_BLOCKSIZE + 4;
  localparam int AES_CTR_W       = (AES_TOTAL_BLOCKS <= 1) ? 1 : $clog2(AES_TOTAL_BLOCKS);
  localparam int AES_R_CW        = (RSD_CODIM_LIMBS <= 1) ? 1 : $clog2(RSD_CODIM_LIMBS);
  localparam int AES_BIT_OFF_CW  = $clog2(ENC_BLOCKSIZE);
  localparam int AES_COMBINED_WORDS = 2 * BLOCK_DIV_64;
  localparam int AES_COMBINED_CW = $clog2(AES_COMBINED_WORDS);
  localparam int COL_ABS_CW      = $clog2(N + 1);

  // Witness batch base counter width (unit: 64-bit words)
  localparam int WBB_CW = $clog2(WIT_WORDS + CHUNK_WORDS + 1);

  // Per-pass iteration limit (last i-index, inclusive).
  // HALF_POLY=1: pass 0 -> HALF1_ITERS, pass 1 -> W.
  // HALF_POLY=0: i-aligned - exactly CHUNK_MAX_I i's per chunk (no spanning).
  function automatic logic [I_CW-1:0] pass_i_end;
    if (HALF_POLY != 0) begin
      return (chunk_idx_i == '0) ? I_CW'(HALF1_ITERS) : I_CW'(W);
    end else begin
      automatic int last_i = (int'(chunk_idx_i) + 1) * CHUNK_MAX_I;
      return I_CW'((last_i > W) ? W : last_i);
    end
  endfunction

  // Pass-relative bit base (V index offset for this pass).
  // HALF_POLY=0: aligned to i-boundaries (CHUNK_BIT_SIZE per chunk).
  wire [WIB_CW-1:0] pass_bit_base =
      (HALF_POLY != 0)
          ? ((chunk_idx_i == '0) ? WIB_CW'(0) : WIB_CW'(HALF1_BITS))
          : WIB_CW'({{(32-$clog2(NUM_PWIT_CHUNKS)){1'b0}}, chunk_idx_i}
                     * CHUNK_MAX_I * MUX_INPUTS);

  // Counter widths
  localparam int ABSORB_CW   = $clog2(HLINES_WORDS + 1);
  localparam int SQUEEZE_CW  = $clog2(GAMMA_WORDS + 1);
  localparam int RMW_CW      = $clog2(2*CHUNK_WORDS + 1);
  localparam int GAMMAP_CW   = $clog2(CHUNK_WORDS + 1);
  localparam int I_CW        = $clog2(W + 1);

  // Layer-1 counter widths
  localparam int H_CW        = $clog2(NUM_OUT_L1 + 1);
  localparam int C_CW        = $clog2(MU1 + 1);
  localparam int XI_POS_CW   = $clog2(LAMBDA + 1);
  localparam int V_FETCH_CW  = $clog2(CW_R_L + 2);
  localparam int WRITE_CW    = $clog2(2 * CHUNK_WORDS + 1);

  // =========================================================================
  // State
  // =========================================================================
  typedef enum logic [5:0] {
    S_IDLE,
    S_SHAKE_INIT,
    S_ABSORB_HLINES,
    S_SQUEEZE_GAMMA,
    S_SQUEEZE_GAMMAP,

    // Layer-1 states
    S_L1_INIT,          // reset per-i counters; conditional xi/AES init on first i
    S_L1_WIT_RD,        // read CHUNK_WORDS witness words from key BRAM into acc0_reg
    S_L1_WIT_EXTRACT,   // extract i_bits from acc0_reg after WIT_RD completes
    S_L1_WIT_EXTRA,     // read one extra key word for i_bits spanning a boundary
    S_L1_PKSEED_LOAD,   // read pk_seed from key BRAM -> lj_v (skipped if cached)
    S_L1_GEN_BASE,      // c=0: base = h^[gamma], acc = 0
    S_L1_GEN_G_K,       // c>=1: g = h^[gamma], delta = g XOR base
    S_L1_AES_FIRE,      // fire dual AES-CTR pair for first limb (r=0)
    S_L1_AES_WAIT,      // wait for AES + pre-read gamma from BRAM
    S_L1_AES_STREAM,    // extract LAMBDA-bit limb into aes_limb
    S_L1_AES_MUL,       // issue gamma_r * limb_r; pre-fire AES for r+1
    S_L1_AES_MULW,      // wait for mul; pre-read gamma[r+1] from BRAM
    S_L1_FETCH_V,       // read CW_R_L words of V into v_reg
    S_L1_ISSUE_MUL,     // issue v*delta; XOR bit-AND into acc0
    S_L1_MUL_WAIT,      // latch mul_out into acc1
    S_L1_FINALIZE,      // acc0 ^= base (deg-shifted add)
    S_L1_WRITE,         // write 2*CHUNK_WORDS words of (acc0, acc1) to node region
    S_L1_NEXT_TUPLE,    // advance h or go to DONE

    // UC + Palpha update states
    S_UC_INIT,         // compute echelon bit-parts, latch challenge
    S_UC_ISSUE,        // issue next mul in UC sequence
    S_UC_WAIT,         // wait for mul result
    S_UC_PA_RMW,       // XOR UC result into Palpha via read-modify-write
    S_UC_ADV,          // advance unitary challenge (coeff *= x^32)
    S_UC_ADV_WAIT,     // wait for challenge mul result
    S_NODE_PA_RMW,     // XOR final node into Palpha via RMW

    // DFS scheduling states
    S_DFS_SETUP,       // set up deep-layer fold parameters for dfs_next_layer
    S_DFS_CHECK,       // after deep fold: route to next fold or back to L1

    // Gamma BRAM read (gamma stored in scratchpad, one limb at a time)
    S_GAMMA_RD,        // read CHUNK_WORDS words of gamma limb into v_reg

    // V limb on-demand read (shared by deep layers and UC)
    S_V_LIMB_RD,       // read one LAMBDA-wide V limb from Var BRAM into lj_v

    // Deep-layer states (inline fold, shared gf_mul_serial)
    S_LJ_A0_RD,        // read base poly a[0] coefficients from BRAM
    S_LJ_AK_RD,        // read a[k][c] from BRAM, compute diff, bit-AND fold
    S_LJ_ISSUE_MUL,    // issue v[k-1] * diff through shared gf_mul_serial
    S_LJ_MUL_WAIT,     // wait for mul result, XOR into res[c+1]
    S_LJ_WRITE,        // write result tuple to output BRAM region
    S_LJ_NEXT_D,       // layer fold complete -> S_DFS_CHECK

    // BRAM scratchpad states for lj_a0/lj_res
    S_LJ_A0_FETCH,     // read a0[c] from scratchpad -> base_reg
    S_LJ_RES_RMW,      // RMW res[c] ^= delta_reg in scratchpad
    S_LJ_RES_MUL_ACC,  // RMW res[c+1] ^= acc0_reg in scratchpad
    S_LJ_RES_PRELOAD,  // pre-load res[pa_coef] from scratchpad -> acc0_reg

    // UC coeff BRAM spill states
    S_UC_COEFF_RD,     // read uc_coeff from BRAM scratchpad -> delta_reg
    S_UC_COEFF_WR,     // write delta_reg -> uc_coeff BRAM scratchpad

    S_DONE
  } state_t;

  state_t state, next_state;

  // =========================================================================
  // Chunk-0 setup flip-flops (SHAKE, gamma, gamma')
  // =========================================================================
  logic [ABSORB_CW-1:0]   absorb_cnt,   next_absorb_cnt;
  logic [SQUEEZE_CW-1:0]  squeeze_cnt,  next_squeeze_cnt;
  // gamma lives in the BRAM scratchpad at GAMMA_BRAM_BASE (no register).
  // Gamma limbs are loaded into v_reg via S_GAMMA_RD (identity path) or
  // pre-read during S_L1_AES_WAIT / S_L1_AES_MULW (AES path).
  // uc_t2p_c1 also shares v_reg during UC states (non-overlapping window).
  logic [1:0]             gamma_idx,    next_gamma_idx;
  // Return destination after S_GAMMA_RD completes:
  localparam logic [2:0] GRET_GAMMAP   = 3'd0;  // -> S_SQUEEZE_GAMMAP (post-squeeze init)
  localparam logic [2:0] GRET_GEN_GK   = 3'd1;  // -> S_L1_GEN_G_K (xi advance, arity>1)
  localparam logic [2:0] GRET_FINAL    = 3'd2;  // -> S_L1_FINALIZE (xi advance, arity==1)
  localparam logic [2:0] GRET_FETCH_V  = 3'd3;  // -> S_L1_FETCH_V (xi advance in GEN_G_K)
  logic [2:0]             gamma_ret,    next_gamma_ret;
  logic [GAMMAP_CW-1:0]   gammap_cnt,   next_gammap_cnt;
  logic [I_CW-1:0]        i_cnt,        next_i_cnt;

  // =========================================================================
  // DFS group counters
  // =========================================================================
  localparam int DFS_GRP_CW = $clog2(MU1 + 1);

  logic [DFS_GRP_CW-1:0] dfs_l1_sub,     next_dfs_l1_sub;   // 0..mu2-1 within current d=0 group
  logic [DFS_GRP_CW-1:0] dfs_l2_cnt,     next_dfs_l2_cnt;   // 0..mu3-1 within current d=1 group
  logic [DFS_GRP_CW-1:0] dfs_l3_cnt,     next_dfs_l3_cnt;   // 0..mu4-1 within current d=2 group
  logic [1:0]            dfs_next_layer, next_dfs_next_layer;

  // =========================================================================
  // Layer-1 flip-flops
  // =========================================================================
  logic [H_CW-1:0]            h_reg,     next_h_reg;
  logic [C_CW-1:0]            c_reg,     next_c_reg;   // current k+1 in [1, MU1]
  logic [LAMBDA-1:0]          xi_run,    next_xi_run;
  logic [XI_POS_CW-1:0]       xi_pos,    next_xi_pos;  // 0..LAMBDA-1 within limb
  logic [1:0]                 xi_limb,   next_xi_limb; // 0..3
  logic [LAMBDA-1:0]          base_reg,  next_base_reg;
  logic [LAMBDA-1:0]          delta_reg, next_delta_reg;
  logic [LAMBDA-1:0]          acc0_reg,  next_acc0_reg;
  logic [LAMBDA-1:0]          acc1_reg,  next_acc1_reg;
  logic [CW_R_L*64-1:0]       v_reg,     next_v_reg;
  logic [V_FETCH_CW-1:0]      v_cnt,     next_v_cnt;
  logic [WRITE_CW-1:0]        write_cnt, next_write_cnt;
  logic [$clog2(LAMBDA)-1:0]  w_bit_pos, next_w_bit_pos;

  // Control bits for the current i-iteration (extracted in S_L1_WIT_EXTRACT)
  logic [MUX_INPUTS-1:0]     i_bits,    next_i_bits;
  // Key-BRAM word offset of the current witness batch
  logic [WBB_CW-1:0]         wit_batch_base, next_wit_batch_base;

  // Absolute column counter (used for identity/AES column selection)
  logic [COL_ABS_CW-1:0]     col_abs,   next_col_abs;
  // Per-i offsets into witness bits and V region
  localparam int WIB_CW = $clog2(W * MUX_INPUTS + 1);
  logic [WIB_CW-1:0]         wit_i_base, next_wit_i_base;
  logic [WIB_CW-1:0]         v_i_off,    next_v_i_off;

  // AES H' streaming registers (no sliding window - re-fire per limb)
  logic [AES_CTR_W-1:0]        aes_ctr,     next_aes_ctr;
  logic [AES_BIT_OFF_CW-1:0]   aes_bit_off, next_aes_bit_off;
  logic [AES_R_CW-1:0]         aes_r_idx,   next_aes_r_idx;
  logic                        aes_is_gk,   next_aes_is_gk;
  logic [LAMBDA-1:0]           aes_limb,    next_aes_limb;
  logic [63:0]                 aes_shift,   next_aes_shift;
  logic                        pkseed_loaded, next_pkseed_loaded;

  // =========================================================================
  // UC + Palpha update flip-flops
  // =========================================================================
  typedef enum logic [2:0] {
    UCP_T1, UCP_T2, UCP_SCHOOL, UCP_T2P, UCP_FIN
  } uc_phase_t;

  logic [1:0]           uc_d,       next_uc_d;
  uc_phase_t            uc_phase,   next_uc_phase;
  logic [3:0]           uc_sub,     next_uc_sub;
  // uc_t2p_c1 shares v_reg[LAMBDA-1:0] (v_reg is idle during UC).
  // uc_coeff spilled to BRAM at UC_COEFF_BRAM_BASE; loaded into delta_reg on demand
  // Palpha RMW: which coefficient (0..DEGREE) and step within coefficient
  logic [3:0]           pa_coef,    next_pa_coef;
  logic [RMW_CW-1:0]    pa_step,    next_pa_step;
  // Pre-computed x_pow for UCP_T2/UCP_T2P: avoids uc_d -> uc_arity -> multiply -> barrel
  // shift chain on the mul_b critical path.  Updated at phase transitions and when
  // uc_sub increments; consumed directly in S_UC_ISSUE.
  logic [LAMBDA-1:0]    uc_xpow,    next_uc_xpow;

  function automatic logic [LAMBDA-1:0] uc_v_limb(input int idx);
    return lj_v;
  endfunction

  // x^shift constant (no reduction needed for shifts < LAMBDA)
  function automatic logic [LAMBDA-1:0] x_pow(input int shift);
    return LAMBDA'(1) << shift;
  endfunction

  // Combinational echelon bit-part: sum bits[i] * x^(k*i) for i=0..N-1
  // Loop bound is the compile-time max (MU1-1) so Vivado can unroll it;
  // the runtime N gates which iterations actually contribute.
  function automatic logic [LAMBDA-1:0] bit_ech(input int N, input int k);
    logic [LAMBDA-1:0] acc;
    acc = '0;
    for (int i = 0; i < MU1 - 1; i++)
      if (i < N) acc ^= (lj_bits[i] ? x_pow(k * i) : LAMBDA'(0));
    return acc;
  endfunction

  // UC arity at layer uc_d (= MU_arr[uc_d] - 1 control entries)
  function automatic int uc_arity(input logic [1:0] d);
    case (d)
      2'd0: return MU1 - 1;  2'd1: return MU2 - 1;
      2'd2: return MU3 - 1;  default: return MU4 - 1;
    endcase
  endfunction


  // =========================================================================
  // Deep-layer flip-flops (inline fold, shared gf_mul_serial)
  // =========================================================================
  localparam int LJ_K_CW   = $clog2(MU1);
  localparam int LJ_C_CW   = $clog2(DEGREE + 1);
  localparam int LJ_H_CW   = $clog2(NUM_OUT_L1 + 1);
  localparam int LJ_WR_CW  = $clog2(2 * LJ_MAX_OUT_WORDS + 1);
  localparam int LJ_VRD_CW = $clog2((MU1 - 1) * CHUNK_WORDS + 1);
  localparam int LJ_ASM_CW = $clog2(DEGREE * CHUNK_WORDS + 1);
  localparam int LJ_CONS_CW = $clog2(M + 1);

  logic [1:0]                         d_reg,          next_d_reg;
  // Per-layer control data
  logic [MU1-2:0]                     lj_bits,        next_lj_bits;
  logic [LAMBDA-1:0]                  lj_v,           next_lj_v;
  // lj_a0 and lj_res live in BRAM scratchpad at LJ_A0_BRAM_BASE / LJ_RES_BRAM_BASE.
  // During UC states, lj_a0[0..3] are mapped to acc0/acc1/base/delta registers.

  // V limb read return destination (for S_V_LIMB_RD)
  localparam logic [1:0] VRET_LJ_ISSUE = 2'd0;
  localparam logic [1:0] VRET_UC_INIT  = 2'd1;
  localparam logic [1:0] VRET_UC_ISSUE = 2'd2;
  logic [1:0]                         v_limb_ret,     next_v_limb_ret;
  logic [1:0]                         lj_phase,       next_lj_phase;
  // Counters
  logic [LJ_K_CW-1:0]                lj_k,           next_lj_k;
  logic [LJ_C_CW-1:0]                lj_c,           next_lj_c;
  logic [LJ_H_CW-1:0]                lj_h,           next_lj_h;
  logic [LJ_CONS_CW-1:0]             lj_cons,        next_lj_cons;
  logic [LJ_ASM_CW-1:0]              lj_asm_cnt,     next_lj_asm_cnt;
  // V read counter
  logic [LJ_VRD_CW-1:0]              lj_vrd_cnt,     next_lj_vrd_cnt;
  // Write counter
  logic [LJ_WR_CW-1:0]               lj_wr_cnt,      next_lj_wr_cnt;
  // Arity for current tuple
  logic [LJ_K_CW:0]                  lj_arity_reg,   next_lj_arity_reg;
  // Num inputs for current layer
  logic [LJ_CONS_CW-1:0]             lj_num_in,      next_lj_num_in;
  // Linear BRAM read base for current layer (latched at S_DFS_SETUP)
  logic [VAR_ADDR_WIDTH_COMBINED-1:0] lj_rd_base,     next_lj_rd_base;
  logic [VAR_ADDR_WIDTH_COMBINED-1:0] lj_wr_base,     next_lj_wr_base;
  // Running offsets to replace runtime multiplies on the critical path.
  // lj_cons_offset = lj_cons * lj_in_stride (read side),
  // lj_h_offset    = lj_h   * lj_out_stride (write side).
  logic [VAR_ADDR_WIDTH_COMBINED-1:0] lj_in_stride,   next_lj_in_stride;
  logic [VAR_ADDR_WIDTH_COMBINED-1:0] lj_cons_offset, next_lj_cons_offset;
  logic [VAR_ADDR_WIDTH_COMBINED-1:0] lj_out_stride,  next_lj_out_stride;
  logic [VAR_ADDR_WIDTH_COMBINED-1:0] lj_h_offset,    next_lj_h_offset;

  // Deep-layer helpers: per-d_reg lookups
  function automatic int lj_get_arity(input logic [1:0] d);
    case (d)
      2'd0: return MU2;  2'd1: return MU3;  default: return MU4;
    endcase
  endfunction
  function automatic int lj_c_pos(input logic [1:0] d);
    case (d)
      2'd0: return C_POS_D1;  2'd1: return C_POS_D2;  default: return C_POS_D3;
    endcase
  endfunction
  function automatic int lj_in_coefs(input logic [1:0] d);
    case (d)
      2'd0: return 2;  2'd1: return 3;  default: return 4;
    endcase
  endfunction
  function automatic int lj_out_coefs(input logic [1:0] d);
    case (d)
      2'd0: return 3;  2'd1: return 4;  default: return 5;
    endcase
  endfunction
  // UC V-offset: starting V position for UC layer d (d=0 is layer-1, d>0 maps
  // to the same positions as deep layer d-1).
  function automatic int uc_v_offset(input logic [1:0] d);
    case (d)
      2'd0: return 0;  2'd1: return C_POS_D1;
      2'd2: return C_POS_D2;  default: return C_POS_D3;
    endcase
  endfunction
  // V accessor (single limb, pre-loaded via S_V_LIMB_RD)
  function automatic logic [LAMBDA-1:0] lj_v_limb(input logic [LJ_K_CW-1:0] k);
    return lj_v;
  endfunction
  // Remaining inputs for real_arity computation
  wire [LJ_CONS_CW:0] lj_remaining = {1'b0, lj_num_in} - {1'b0, lj_cons};

  assign dbg_gamma_o   = {{(3*LAMBDA){1'b0}}, v_reg[LAMBDA-1:0]};
  assign dbg_i_cnt_o   = i_cnt;

  // uc_coeff lives in BRAM, so there is no register to tap here
  assign dbg_gamma_p_o = '0;

  assign dbg_state_o         = state;
  assign dbg_delta_o         = delta_reg;
  assign dbg_acc1_o          = acc1_reg;
  assign dbg_v_lo_o          = v_reg[LAMBDA-1:0];
  assign dbg_base_o          = base_reg;
  assign dbg_mul_out_o       = mul_out;
  assign dbg_mul_out_valid_o = mul_out_valid;

  // =========================================================================
  // gf_mul_serial (shared across all fold operations)
  // =========================================================================
  logic              mul_in_valid;
  logic [LAMBDA-1:0] mul_a, mul_b;
  logic              mul_out_valid;
  logic [LAMBDA-1:0] mul_out;

  gf_mul_serial #(.LAMBDA(LAMBDA)) u_mul (
      .clk_i      (clk_i),
      .rst_i      (rst_i),
      .in_valid_i (mul_in_valid),
      .a_i        (mul_a),
      .b_i        (mul_b),
      .out_valid_o(mul_out_valid),
      .out_o      (mul_out)
  );

  // =========================================================================
  // Var BRAM 64-bit logical-view wrapper
  // =========================================================================
  logic [VAR_ADDR_WIDTH_COMBINED-1:0] var_laddr;
  logic [63:0]                        var_lwdata;
  logic                               var_lwr_en;
  logic                               var_bram_rd;

  wire  [63:0]                        var_lrdata =
      CAN_DUAL_COMBINED
          ? 64'(var_a_data_i)
          : {32'(var_b_data_i), 32'(var_a_data_i)};

  // Pipeline register stall: after issuing a BRAM read, hold all internal
  // state for 1 extra cycle so the registered address reaches the BRAM and
  // read data is valid when the FSM next evaluates.
  logic bram_rd_wait;

  // =========================================================================
  // Helpers
  // =========================================================================
  // gamma limbs are stored byte-swapped in the BRAM scratchpad (GF(2^lambda)
  // polynomial encoding, bit 0 = constant term) and pre-loaded into v_reg
  // via S_GAMMA_RD before use.

  // GF(2^lambda) x x with reduction via GF_POLY.
  function automatic logic [LAMBDA-1:0] mul_x(input logic [LAMBDA-1:0] v);
    return (v << 1) ^ (v[LAMBDA-1] ? LAMBDA'(GF_POLY) : '0);
  endfunction

  // Current tuple's arity. For layer-1 on outer-i, this is min(MU1, M - h*MU1).
  function automatic int current_arity_l1(input logic [H_CW-1:0] h);
    int rem;
    rem = M - {{(32-H_CW){1'b0}}, h} * MU1;
    return (rem >= MU1) ? MU1 : rem;
  endfunction

  // AES key formatting: pk_seed -> byte-reversed, padded for SEC3
  logic [LAMBDA-1:0]      pk_seed_be;
  logic [ENC_KEYSIZE-1:0] aes_key_padded;
  assign pk_seed_be = {<<8{lj_v}};
  generate
    if (SECURITY_LEVEL == 3) begin : g_aes_pad192
      assign aes_key_padded = {64'b0, pk_seed_be};
    end else begin : g_aes_nopad
      assign aes_key_padded = ENC_KEYSIZE'(pk_seed_be);
    end
  endgenerate

  // AES ciphertext byte-swap (bswap64 per lane, lane order reversed)
  logic [ENC_BLOCKSIZE-1:0] cipher_swapped_0, cipher_swapped_1;
  generate
    for (genvar g = 0; g < BLOCK_DIV_64; g = g + 1) begin : g_cipher_swap
      assign cipher_swapped_0[g*64 +: 64] =
          bswap64(aes0_ciphertext_i[(BLOCK_DIV_64 - 1 - g)*64 +: 64]);
      assign cipher_swapped_1[g*64 +: 64] =
          bswap64(aes1_ciphertext_i[(BLOCK_DIV_64 - 1 - g)*64 +: 64]);
    end
  endgenerate

  // Mask for the last (partial) limb of an H' row
  localparam int AES_LAST_LIMB_BITS = RSD_CODIM - (RSD_CODIM_LIMBS - 1) * LAMBDA;
  localparam [LAMBDA-1:0] AES_LAST_LIMB_MASK = (LAMBDA'(1) << AES_LAST_LIMB_BITS) - 1;

  // Identity vs AES column decision
  wire col_is_ident = (col_abs < COL_ABS_CW'(N_MINUS_K_RSD));

  // Lint-off for unused ports
  /* verilator lint_off UNUSEDSIGNAL */
  wire        _unused_aes0_ready = aes0_ready_i;
  wire        _unused_aes1_ready = aes1_ready_i;
  /* verilator lint_on UNUSEDSIGNAL */

  // Combinational AES signals (registered at output ports in sequential block)
  logic [ENC_KEYSIZE-1:0]   aes0_key_comb,   aes1_key_comb;
  logic [ENC_BLOCKSIZE-1:0] aes0_plaintext_comb, aes1_plaintext_comb;
  logic                     aes0_enable_comb, aes1_enable_comb;

  // =========================================================================
  // Next-state + output combinational logic
  // =========================================================================
  always_comb begin
    // State hold
    next_state        = state;
    next_absorb_cnt   = absorb_cnt;
    next_squeeze_cnt  = squeeze_cnt;
    next_gamma_idx    = gamma_idx;
    next_gamma_ret    = gamma_ret;
    next_dfs_l1_sub       = dfs_l1_sub;
    next_dfs_l2_cnt       = dfs_l2_cnt;
    next_dfs_l3_cnt       = dfs_l3_cnt;
    next_dfs_next_layer   = dfs_next_layer;
    next_gammap_cnt   = gammap_cnt;
    next_i_cnt        = i_cnt;

    next_h_reg        = h_reg;
    next_c_reg        = c_reg;
    next_xi_run       = xi_run;
    next_xi_pos       = xi_pos;
    next_xi_limb      = xi_limb;
    next_base_reg     = base_reg;
    next_delta_reg    = delta_reg;
    next_acc0_reg     = acc0_reg;
    next_acc1_reg     = acc1_reg;
    next_v_reg        = v_reg;
    next_v_cnt        = v_cnt;
    next_write_cnt    = write_cnt;
    next_w_bit_pos    = w_bit_pos;
    next_i_bits       = i_bits;
    next_wit_batch_base = wit_batch_base;
    next_col_abs      = col_abs;
    next_wit_i_base   = wit_i_base;
    next_v_i_off      = v_i_off;
    next_aes_ctr      = aes_ctr;
    next_aes_bit_off  = aes_bit_off;
    next_aes_r_idx    = aes_r_idx;
    next_aes_is_gk    = aes_is_gk;
    next_aes_limb     = aes_limb;
    next_aes_shift    = aes_shift;
    next_pkseed_loaded = pkseed_loaded;

    next_uc_d         = uc_d;
    next_uc_phase     = uc_phase;
    next_uc_sub       = uc_sub;
    next_uc_xpow      = uc_xpow;
    next_pa_coef      = pa_coef;
    next_pa_step      = pa_step;

    next_d_reg        = d_reg;
    next_lj_bits      = lj_bits;
    next_lj_v         = lj_v;
    next_v_limb_ret   = v_limb_ret;
    next_lj_phase     = lj_phase;
    next_lj_k         = lj_k;
    next_lj_c         = lj_c;
    next_lj_h         = lj_h;
    next_lj_cons      = lj_cons;
    next_lj_asm_cnt   = lj_asm_cnt;
    next_lj_vrd_cnt   = lj_vrd_cnt;
    next_lj_wr_cnt    = lj_wr_cnt;
    next_lj_arity_reg = lj_arity_reg;
    next_lj_num_in    = lj_num_in;
    next_lj_rd_base   = lj_rd_base;
    next_lj_wr_base   = lj_wr_base;
    next_lj_in_stride   = lj_in_stride;
    next_lj_cons_offset = lj_cons_offset;
    next_lj_out_stride  = lj_out_stride;
    next_lj_h_offset    = lj_h_offset;

    fsm_done_o        = 1'b0;

    // Output defaults
    shake_start_o         = 1'b0;
    shake_mode_o          = SHAKE_MODE_C;
    shake_din_o           = 64'b0;
    shake_din_valid_o     = 1'b0;
    shake_last_din_o      = 1'b0;
    shake_last_din_byte_o = 4'd0;
    shake_dout_ready_o    = 1'b0;

    key_addr_o    = '0;
    var_laddr     = '0;
    var_lwdata    = 64'b0;
    var_lwr_en    = 1'b0;
    var_bram_rd   = 1'b0;

    sig_data_o    = 64'b0;
    sig_addr_o    = '0;
    sig_wr_en_o   = 1'b0;

    aes0_key_comb       = '0;
    aes0_plaintext_comb = '0;
    aes0_enable_comb    = 1'b0;
    aes1_key_comb       = '0;
    aes1_plaintext_comb = '0;
    aes1_enable_comb    = 1'b0;

    mul_in_valid = 1'b0;
    mul_a        = '0;
    mul_b        = '0;

    case (state)
      // --------------------------------------------------------------------
      S_IDLE: begin
        if (fsm_start_i) begin
          if (chunk_idx_i == '0) begin
            next_absorb_cnt   = '0;
            next_squeeze_cnt  = '0;
            next_gammap_cnt     = '0;
            next_i_cnt          = '0;
            next_wit_batch_base = '0;
            next_state          = S_SHAKE_INIT;
          end else if (i_cnt < I_CW'(W)) begin
            next_gammap_cnt     = '0;
            next_wit_batch_base = WBB_CW'(
                {{(32-WIB_CW){1'b0}}, pass_bit_base} / 64);
            next_state          = S_SQUEEZE_GAMMAP;
          end else begin
            next_state = S_DONE;
          end
        end
      end

      // --------------------------------------------------------------------
      S_SHAKE_INIT: begin
        shake_start_o = 1'b1;
        next_state    = S_ABSORB_HLINES;
      end

      // --------------------------------------------------------------------
      S_ABSORB_HLINES: begin
        shake_din_o       = hlines_i[absorb_cnt*64 +: 64];
        shake_din_valid_o = 1'b1;
        if (absorb_cnt == ABSORB_CW'(HLINES_WORDS - 1)) begin
          shake_last_din_o      = 1'b1;
          shake_last_din_byte_o = 4'd8;
        end
        if (shake_din_ready_i) begin
          if (absorb_cnt == ABSORB_CW'(HLINES_WORDS - 1)) begin
            next_absorb_cnt = '0;
            next_state      = S_SQUEEZE_GAMMA;
          end else begin
            next_absorb_cnt = absorb_cnt + 1;
          end
        end
      end

      // --------------------------------------------------------------------
      S_SQUEEZE_GAMMA: begin
        shake_dout_ready_o = 1'b1;
        if (shake_dout_valid_i) begin
          // Write byte-swapped word to BRAM scratchpad (GF polynomial order).
          var_laddr  = VAR_ADDR_WIDTH_COMBINED'(
              GAMMA_BRAM_BASE + {{(VAR_ADDR_WIDTH_COMBINED-SQUEEZE_CW){1'b0}}, squeeze_cnt});
          var_lwdata = bswap64(shake_dout_i);
          var_lwr_en = 1'b1;
          if (squeeze_cnt == SQUEEZE_CW'(GAMMA_WORDS - 1)) begin
            next_squeeze_cnt = '0;
            // Pre-load gamma limb 0 into v_reg before entering PIOP loop.
            next_gamma_idx = 2'd0;
            next_gamma_ret = GRET_GAMMAP;
            next_v_cnt     = '0;
            next_state     = S_GAMMA_RD;
          end else begin
            next_squeeze_cnt = squeeze_cnt + 1;
          end
        end
      end

      // --------------------------------------------------------------------
      S_SQUEEZE_GAMMAP: begin
        shake_dout_ready_o = 1'b1;
        if (shake_dout_valid_i) begin
          var_laddr  = VAR_ADDR_WIDTH_COMBINED'(
              UC_COEFF_BRAM_BASE + {{(VAR_ADDR_WIDTH_COMBINED-GAMMAP_CW){1'b0}}, gammap_cnt});
          var_lwdata = bswap64(shake_dout_i);
          var_lwr_en = 1'b1;
          if (gammap_cnt == GAMMAP_CW'(CHUNK_WORDS - 1)) begin
            next_gammap_cnt = '0;
            next_i_cnt      = i_cnt + 1;
            if (dbg_i_limit_i == '0 || i_cnt >= dbg_i_limit_i
                || i_cnt >= I_CW'(W) || i_cnt >= pass_i_end())
              next_state = S_DONE;
            else
              next_state = S_L1_INIT;
          end else begin
            next_gammap_cnt = gammap_cnt + 1;
          end
        end
      end

      // ====================================================================
      // Gamma BRAM read: load CHUNK_WORDS words of limb gamma_idx into
      // v_reg[LAMBDA-1:0] (v_reg is idle at all call sites).
      // Uses v_cnt as sub-word counter.
      // ====================================================================
      S_GAMMA_RD: begin
        if (v_cnt < V_FETCH_CW'(CHUNK_WORDS)) begin
          var_laddr = VAR_ADDR_WIDTH_COMBINED'(
              GAMMA_BRAM_BASE + {{(VAR_ADDR_WIDTH_COMBINED-2){1'b0}}, gamma_idx} * CHUNK_WORDS
              + {{(VAR_ADDR_WIDTH_COMBINED-V_FETCH_CW){1'b0}}, v_cnt});
          var_bram_rd = 1'b1;
        end
        if (v_cnt >= V_FETCH_CW'(1))
          next_v_reg[(v_cnt - 1) * 64 +: 64] = var_lrdata;
        if (v_cnt == V_FETCH_CW'(CHUNK_WORDS)) begin
          next_v_cnt = '0;
          case (gamma_ret)
            GRET_GAMMAP: begin
              next_state = S_SQUEEZE_GAMMAP;
            end
            GRET_GEN_GK: begin
              next_xi_run = next_v_reg[LAMBDA-1:0];
              next_state  = S_L1_GEN_G_K;
            end
            GRET_FINAL: begin
              next_xi_run = next_v_reg[LAMBDA-1:0];
              next_state  = S_L1_FINALIZE;
            end
            GRET_FETCH_V: begin
              next_xi_run = next_v_reg[LAMBDA-1:0];
              next_v_reg  = '0;
              next_state  = S_L1_FETCH_V;
            end
            default: next_state = S_IDLE;
          endcase
        end else begin
          next_v_cnt = v_cnt + 1;
        end
      end

      // ====================================================================
      // Layer 1 datapath
      // ====================================================================

      // --------------------------------------------------------------------
      // Per-i init. Resets per-i counters, advances wit_batch_base if
      // needed, then always goes to WIT_RD to reload witness bits.
      S_L1_INIT: begin
        automatic logic [31:0] gbs;
        automatic logic [31:0] batch_end;
        gbs       = ({{(32-I_CW){1'b0}}, i_cnt} - 1) * MUX_INPUTS;
        batch_end = {{(32-WBB_CW){1'b0}}, wit_batch_base} * 64 + LAMBDA;

        next_h_reg      = '0;
        next_c_reg      = '0;
        next_base_reg   = '0;
        next_acc1_reg   = '0;
        next_w_bit_pos  = '0;
        next_col_abs    = COL_ABS_CW'(({{(32-I_CW){1'b0}}, i_cnt} - 1) * M);
        next_dfs_l1_sub = '0;
        next_dfs_l2_cnt = '0;
        next_dfs_l3_cnt = '0;
        next_pkseed_loaded = 1'b0;
        next_wit_i_base = WIB_CW'(gbs);
        next_v_i_off    = WIB_CW'(gbs - {{(32-WIB_CW){1'b0}}, pass_bit_base});

        if (chunk_idx_i == '0 && i_cnt == I_CW'(1)) begin
          next_xi_run       = v_reg[LAMBDA-1:0];
          next_xi_pos       = '0;
          next_xi_limb      = 2'd0;
          next_aes_ctr      = '0;
          next_aes_bit_off  = '0;
        end

        if (gbs >= batch_end)
          next_wit_batch_base = wit_batch_base + WBB_CW'(CHUNK_WORDS);

        next_v_cnt = '0;
        next_state = S_L1_WIT_RD;
      end

      // --------------------------------------------------------------------
      // Read CHUNK_WORDS witness words into acc0_reg (temporary).
      // Uses wit_batch_base as the key-BRAM word offset.
      S_L1_WIT_RD: begin
        key_addr_o = (BRAM_ADDR_SIZE+1)'(
            WIT_OFFSET + {{(BRAM_ADDR_SIZE+1-WBB_CW){1'b0}}, wit_batch_base}
            + {{(BRAM_ADDR_SIZE+1-V_FETCH_CW){1'b0}}, v_cnt});
        if (v_cnt > '0)
          next_acc0_reg[(v_cnt - 1) * 64 +: 64] = key_data_i;
        if (v_cnt == V_FETCH_CW'(CHUNK_WORDS)) begin
          next_v_cnt = '0;
          next_state = S_L1_WIT_EXTRACT;
        end else begin
          next_v_cnt = v_cnt + 1;
        end
      end

      // --------------------------------------------------------------------
      // Extract i_bits from acc0_reg (filled by WIT_RD), then clear acc0.
      S_L1_WIT_EXTRACT: begin
        automatic logic [$clog2(LAMBDA)-1:0] ls;
        ls = $clog2(LAMBDA)'(
            {{(32-WIB_CW){1'b0}}, wit_i_base}
            - {{(32-WBB_CW){1'b0}}, wit_batch_base} * 64);
        next_i_bits    = MUX_INPUTS'(acc0_reg >> ls);
        next_acc0_reg  = '0;
        if (ls > $clog2(LAMBDA)'(LAMBDA - MUX_INPUTS)) begin
          key_addr_o = (BRAM_ADDR_SIZE+1)'(
              WIT_OFFSET + {{(BRAM_ADDR_SIZE+1-WBB_CW){1'b0}}, wit_batch_base}
              + CHUNK_WORDS);
          next_state = S_L1_WIT_EXTRA;
        end else begin
          next_state = S_L1_GEN_BASE;
        end
      end

      // --------------------------------------------------------------------
      // Read one extra key-BRAM word for i_bits that span a LAMBDA-batch
      // boundary. The address was driven in S_L1_WIT_EXTRACT; key_data_i
      // now holds the word past the current batch.
      S_L1_WIT_EXTRA: begin
        automatic int lc = LAMBDA - int'(
            {{(32-WIB_CW){1'b0}}, wit_i_base}
            - {{(32-WBB_CW){1'b0}}, wit_batch_base} * 64);
        next_i_bits = i_bits | (MUX_INPUTS'(key_data_i) << lc);
        next_state = S_L1_GEN_BASE;
      end

      // --------------------------------------------------------------------
      // Read pk_seed from key BRAM into lj_v.  Skipped when pkseed_loaded
      // is set (lj_v still holds pk_seed from a prior AES column).
      // Cleared in S_L1_INIT and S_DFS_SETUP (deep folds overwrite lj_v).
      S_L1_PKSEED_LOAD: begin
        key_addr_o = (BRAM_ADDR_SIZE+1)'(PKSEED_KEY_OFFSET
                        + {{(BRAM_ADDR_SIZE+1-V_FETCH_CW){1'b0}}, v_cnt});
        if (v_cnt > '0)
          next_lj_v[(v_cnt - 1) * 64 +: 64] = key_data_i;
        if (v_cnt == V_FETCH_CW'(CHUNK_WORDS)) begin
          next_v_cnt = '0;
          next_pkseed_loaded = 1'b1;
          next_state = S_L1_AES_FIRE;
        end else begin
          next_v_cnt = v_cnt + 1;
        end
      end

      // --------------------------------------------------------------------
      // c = 0 of tuple h: generate h^[gamma] for the base column.
      // Identity path: base = xi_run (combinational, 1 cycle).
      // AES path: branch to AES generation states.
      S_L1_GEN_BASE: begin
        next_acc0_reg = '0;
        next_acc1_reg = '0;
        next_c_reg    = C_CW'(1);
        if (col_is_ident) begin
          next_base_reg = xi_run;
          next_col_abs  = col_abs + 1;
          // Advance xi
          if (xi_pos == XI_POS_CW'(LAMBDA - 1)) begin
            next_xi_limb = xi_limb + 2'd1;
            next_xi_pos  = '0;
            // Detour through GAMMA_RD to load the new limb.
            next_gamma_idx = xi_limb[1:0] + 2'd1;
            next_v_cnt     = '0;
            next_gamma_ret = (current_arity_l1(h_reg) == 1) ? GRET_FINAL : GRET_GEN_GK;
            next_state     = S_GAMMA_RD;
          end else begin
            next_xi_run  = mul_x(xi_run);
            next_xi_pos  = xi_pos + 1;
            if (current_arity_l1(h_reg) == 1)
              next_state = S_L1_FINALIZE;
            else
              next_state = S_L1_GEN_G_K;
          end
        end else begin
          next_aes_is_gk = 1'b0;
          next_delta_reg = '0;
          next_aes_r_idx = '0;
          next_v_cnt     = '0;
          next_state     = pkseed_loaded ? S_L1_AES_FIRE : S_L1_PKSEED_LOAD;
        end
      end

      // --------------------------------------------------------------------
      // c >= 1: generate h^[gamma] for the k-th column, compute delta = g XOR base.
      S_L1_GEN_G_K: begin
        if (col_is_ident) begin
          next_delta_reg = xi_run ^ base_reg;
          next_col_abs   = col_abs + 1;
          if (xi_pos == XI_POS_CW'(LAMBDA - 1)) begin
            next_xi_limb   = xi_limb + 2'd1;
            next_xi_pos    = '0;
            next_gamma_idx = xi_limb[1:0] + 2'd1;
            next_v_cnt     = '0;
            next_gamma_ret = GRET_FETCH_V;
            next_state     = S_GAMMA_RD;
          end else begin
            next_xi_run  = mul_x(xi_run);
            next_xi_pos  = xi_pos + 1;
            next_v_cnt = '0;
            next_v_reg = '0;
            next_state = S_L1_FETCH_V;
          end
        end else begin
          next_aes_is_gk = 1'b1;
          next_delta_reg = '0;
          next_aes_r_idx = '0;
          next_v_cnt     = '0;
          next_state     = pkseed_loaded ? S_L1_AES_FIRE : S_L1_PKSEED_LOAD;
        end
      end

      // ====================================================================
      // AES H' column generation (shared gf_mul_serial)
      // ====================================================================

      // AES streaming: fire a block pair for the first limb (r=0).
      // Subsequent limbs are pre-fired in AES_MUL to overlap AES
      // latency with the GF multiply.  aes_ctr/aes_bit_off track
      // position in the AES-CTR stream, persisting across columns.
      S_L1_AES_FIRE: begin
        // Limb start bit (unsigned): aes_bit_off + aes_r_idx * LAMBDA
        // pair_blk = aes_ctr + limb_start_bit / ENC_BLOCKSIZE
        automatic logic [AES_CTR_W+3:0] lbs_u;
        automatic logic [AES_CTR_W-1:0] pair_blk;
        lbs_u    = (AES_CTR_W+4)'(aes_bit_off)
                 + (AES_CTR_W+4)'(aes_r_idx) * (AES_CTR_W+4)'(LAMBDA);
        pair_blk = aes_ctr + AES_CTR_W'(lbs_u >> $clog2(ENC_BLOCKSIZE));
        aes0_key_comb       = aes_key_padded;
        aes0_plaintext_comb = {<<8{ENC_BLOCKSIZE'(pair_blk)}};
        aes0_enable_comb    = 1'b1;
        aes1_key_comb       = aes_key_padded;
        aes1_plaintext_comb = {<<8{ENC_BLOCKSIZE'(pair_blk + 1)}};
        aes1_enable_comb    = 1'b1;
        next_v_cnt       = '0;
        next_state       = S_L1_AES_WAIT;
      end

      S_L1_AES_WAIT: begin
        aes0_key_comb = aes_key_padded;
        aes1_key_comb = aes_key_padded;
        // Pre-read gamma[aes_r_idx] from BRAM while waiting for AES.
        // v_cnt counts 0..CHUNK_WORDS+1; values > CHUNK_WORDS mean done.
        if (v_cnt <= V_FETCH_CW'(CHUNK_WORDS)) begin
          if (v_cnt < V_FETCH_CW'(CHUNK_WORDS)) begin
            var_laddr = VAR_ADDR_WIDTH_COMBINED'(
                GAMMA_BRAM_BASE
                + {{(VAR_ADDR_WIDTH_COMBINED-2){1'b0}}, aes_r_idx[1:0]} * CHUNK_WORDS
                + {{(VAR_ADDR_WIDTH_COMBINED-V_FETCH_CW){1'b0}}, v_cnt});
            var_bram_rd = 1'b1;
          end
          if (v_cnt >= V_FETCH_CW'(1))
            next_v_reg[(v_cnt - 1) * 64 +: 64] = var_lrdata;
          next_v_cnt = v_cnt + 1;
        end
        if (aes0_valid_i && aes1_valid_i
            && v_cnt > V_FETCH_CW'(CHUNK_WORDS)) begin
          next_v_cnt = '0;
          next_state = S_L1_AES_STREAM;
        end
      end

      // Word-by-word extraction of one LAMBDA-bit limb from the AES
      // output ports into aes_limb.  aes_shift is the shift temp.
      S_L1_AES_STREAM: begin
        automatic logic [AES_BIT_OFF_CW+1:0] lbs_lo;
        automatic logic [AES_COMBINED_CW-1:0] wo;
        automatic logic [5:0] so;
        automatic logic [AES_COMBINED_CW-1:0] rd_idx;
        automatic logic [63:0] cur_word;
        automatic logic [2*ENC_BLOCKSIZE-1:0] combined;

        combined = {cipher_swapped_1, cipher_swapped_0};

        lbs_lo = (AES_BIT_OFF_CW+2)'(aes_bit_off)
               + (AES_BIT_OFF_CW+2)'(aes_r_idx) * (AES_BIT_OFF_CW+2)'(LAMBDA);
        wo     = AES_COMBINED_CW'((lbs_lo & (AES_BIT_OFF_CW+2)'(ENC_BLOCKSIZE - 1)) >> 6);
        so     = aes_bit_off[5:0];

        rd_idx   = wo + AES_COMBINED_CW'(v_cnt);
        cur_word = combined[{rd_idx, 6'b0} +: 64];

        if (so == 6'd0) begin
          next_aes_limb[v_cnt * 64 +: 64] = cur_word;
          if (v_cnt == V_FETCH_CW'(CHUNK_WORDS - 1)) begin
            next_v_cnt = '0;
            next_state = S_L1_AES_MUL;
          end else begin
            next_v_cnt = v_cnt + 1;
          end
        end else begin
          if (v_cnt == '0) begin
            next_aes_shift = cur_word;
            next_v_cnt = v_cnt + 1;
          end else begin
            next_aes_limb[(v_cnt - 1) * 64 +: 64] =
                (cur_word << (6'd0 - so)) | (aes_shift >> so);
            next_aes_shift = cur_word;
            if (v_cnt == V_FETCH_CW'(CHUNK_WORDS)) begin
              next_v_cnt = '0;
              next_state = S_L1_AES_MUL;
            end else begin
              next_v_cnt = v_cnt + 1;
            end
          end
        end
      end

      S_L1_AES_MUL: begin
        automatic logic [LAMBDA-1:0] row_limb;
        automatic logic [AES_CTR_W+3:0] nxt_lbs;
        automatic logic [AES_CTR_W-1:0] nxt_pair;
        row_limb = aes_limb;
        if (aes_r_idx == AES_R_CW'(RSD_CODIM_LIMBS - 1))
          row_limb = row_limb & AES_LAST_LIMB_MASK;
        mul_a        = v_reg[LAMBDA-1:0];
        mul_b        = row_limb;
        mul_in_valid = 1'b1;
        // Pre-fire AES for the next limb while the GF multiply runs.
        // By the time AES_MULW finishes (LAMBDA/16 cycles), the AES
        // result is ready or nearly ready, hiding most of the latency.
        nxt_lbs  = (AES_CTR_W+4)'(aes_bit_off)
                 + (AES_CTR_W+4)'(aes_r_idx + 1) * (AES_CTR_W+4)'(LAMBDA);
        nxt_pair = aes_ctr + AES_CTR_W'(nxt_lbs >> $clog2(ENC_BLOCKSIZE));
        if (aes_r_idx != AES_R_CW'(RSD_CODIM_LIMBS - 1)) begin
          aes0_key_comb       = aes_key_padded;
          aes0_plaintext_comb = {<<8{ENC_BLOCKSIZE'(nxt_pair)}};
          aes0_enable_comb    = 1'b1;
          aes1_key_comb       = aes_key_padded;
          aes1_plaintext_comb = {<<8{ENC_BLOCKSIZE'(nxt_pair + 1)}};
          aes1_enable_comb    = 1'b1;
        end
        next_state   = S_L1_AES_MULW;
      end

      S_L1_AES_MULW: begin
        // Hold AES key while pre-fired cores are encrypting
        aes0_key_comb = aes_key_padded;
        aes1_key_comb = aes_key_padded;
        // Pre-read gamma[r+1] from BRAM while GF multiply runs.
        // LAMBDA/16 >= CHUNK_WORDS+1 always, so this completes in time.
        // v_cnt increments past CHUNK_WORDS as a "done" sentinel.
        if (aes_r_idx != AES_R_CW'(RSD_CODIM_LIMBS - 1)
            && v_cnt <= V_FETCH_CW'(CHUNK_WORDS)) begin
          if (v_cnt < V_FETCH_CW'(CHUNK_WORDS)) begin
            var_laddr = VAR_ADDR_WIDTH_COMBINED'(
                GAMMA_BRAM_BASE
                + {{(VAR_ADDR_WIDTH_COMBINED-2){1'b0}}, aes_r_idx[1:0] + 2'd1} * CHUNK_WORDS
                + {{(VAR_ADDR_WIDTH_COMBINED-V_FETCH_CW){1'b0}}, v_cnt});
            var_bram_rd = 1'b1;
          end
          if (v_cnt >= V_FETCH_CW'(1))
            next_v_reg[(v_cnt - 1) * 64 +: 64] = var_lrdata;
          next_v_cnt = v_cnt + 1;
        end
        if (mul_out_valid) begin
          next_delta_reg = delta_reg ^ mul_out;
          if (aes_r_idx == AES_R_CW'(RSD_CODIM_LIMBS - 1)) begin
            // All limbs done - advance persistent stream position
            automatic logic [AES_CTR_W+3:0] consumed;
            consumed = (AES_CTR_W+4)'(aes_bit_off) + (AES_CTR_W+4)'(RSD_CODIM);
            next_aes_ctr     = aes_ctr + AES_CTR_W'(consumed >> $clog2(ENC_BLOCKSIZE));
            next_aes_bit_off = AES_BIT_OFF_CW'(consumed);
            next_col_abs = col_abs + 1;
            if (!aes_is_gk) begin
              next_base_reg = delta_reg ^ mul_out;
              if (current_arity_l1(h_reg) == 1)
                next_state = S_L1_FINALIZE;
              else
                next_state = S_L1_GEN_G_K;
            end else begin
              next_delta_reg = (delta_reg ^ mul_out) ^ base_reg;
              next_v_cnt = '0;
              next_v_reg = '0;
              next_state = S_L1_FETCH_V;
            end
          end else begin
            // More limbs - AES pre-fired, gamma pre-read; go wait for AES
            next_aes_r_idx = aes_r_idx + 1;
            next_state     = S_L1_AES_WAIT;
          end
        end
      end

      // --------------------------------------------------------------------
      // Read CW_R_L words of V from Var BRAM. V address includes the per-i
      // offset (v_i_off) so the correct V entries are fetched for each i.
      S_L1_FETCH_V: begin
        // Drive address while v_cnt < CW_R_L
        if (v_cnt < V_FETCH_CW'(CW_R_L)) begin
          var_laddr = VAR_ADDR_WIDTH_COMBINED'(
              L1_V_BASE
              + ({{(32-WIB_CW){v_i_off[WIB_CW-1]}}, v_i_off}
                 + {{(32-C_CW){1'b0}}, c_reg} - 1) * CW_R_L
              + {{(32-V_FETCH_CW){1'b0}}, v_cnt});
          var_bram_rd = 1'b1;
        end
        // Latch previous cycle's read for v_cnt - 1
        if (v_cnt >= V_FETCH_CW'(1)) begin
          next_v_reg = v_reg;
          next_v_reg[(v_cnt - 1) * 64 +: 64] = var_lrdata;
        end
        if (v_cnt == V_FETCH_CW'(CW_R_L)) begin
          next_v_cnt = '0;
          next_state = S_L1_ISSUE_MUL;
        end else begin
          next_v_cnt = v_cnt + 1;
        end
      end

      // --------------------------------------------------------------------
      // Issue v * delta through gf_mul_serial. In parallel: acc0 ^= {lambda{w}} AND delta
      // (free bit-AND) using i_bits[w_bit_pos].
      S_L1_ISSUE_MUL: begin
        mul_a        = v_reg[LAMBDA-1:0];
        mul_b        = delta_reg;
        mul_in_valid = 1'b1;
        if (i_bits[w_bit_pos])
          next_acc0_reg = acc0_reg ^ delta_reg;
        next_state   = S_L1_MUL_WAIT;
      end

      // --------------------------------------------------------------------
      // Wait for mul_out, XOR into acc1. Advance c/k or finalize.
      S_L1_MUL_WAIT: begin
        if (mul_out_valid) begin
          next_acc1_reg = acc1_reg ^ mul_out;
          next_w_bit_pos = w_bit_pos + 6'd1;
          // Are we done with this tuple?
          if (c_reg == C_CW'(current_arity_l1(h_reg) - 1)) begin
            next_state = S_L1_FINALIZE;
          end else begin
            next_c_reg = c_reg + 1;
            next_state = S_L1_GEN_G_K;
          end
        end
      end

      // --------------------------------------------------------------------
      // acc0 ^= base (deg-shifted add; at layer 1 in_deg=0, so just c=0).
      S_L1_FINALIZE: begin
        next_acc0_reg = acc0_reg ^ base_reg;
        next_write_cnt = '0;
        next_state = S_L1_WRITE;
      end

      // --------------------------------------------------------------------
      // Write (acc0 [CHUNK_WORDS words]; acc1 [CHUNK_WORDS words]) to Var
      // BRAM at DFS_L1_BASE + dfs_l1_sub * 2*CHUNK_WORDS (DFS L1_TEMP slot).
      S_L1_WRITE: begin
        var_laddr  = VAR_ADDR_WIDTH_COMBINED'(
                          DFS_L1_BASE
                          + {{(32-DFS_GRP_CW){1'b0}}, dfs_l1_sub} * NODE_L1_WORDS_PER_TUPLE
                          + {{(32-WRITE_CW){1'b0}}, write_cnt});
        var_lwr_en = 1'b1;
        if (write_cnt < WRITE_CW'(CHUNK_WORDS))
          var_lwdata = acc0_reg[write_cnt * 64 +: 64];
        else
          var_lwdata = acc1_reg[(write_cnt - CHUNK_WORDS) * 64 +: 64];

        if (write_cnt == WRITE_CW'(NODE_L1_WORDS_PER_TUPLE - 1)) begin
          next_write_cnt = '0;
          next_state     = S_L1_NEXT_TUPLE;
        end else begin
          next_write_cnt = write_cnt + 1;
        end
      end

      // --------------------------------------------------------------------
      // DFS: advance within d=0 group or trigger fold when group is full.
      S_L1_NEXT_TUPLE: begin
        automatic logic group_end =
            (dfs_l1_sub >= DFS_GRP_CW'(lj_get_arity(2'd0) - 1))
            || (h_reg >= H_CW'(NUM_OUT_L1 - 1));
        if (group_end) begin
          next_dfs_next_layer = 2'd0;
          next_state          = S_DFS_SETUP;
        end else begin
          next_dfs_l1_sub = dfs_l1_sub + DFS_GRP_CW'(1);
          next_h_reg      = h_reg + 1;
          next_c_reg      = '0;
          next_w_bit_pos  = '0;
          next_state      = S_L1_GEN_BASE;
        end
      end

      // ====================================================================
      // DFS scheduling - set up and route between deep-layer folds
      // ====================================================================

      // Set up deep-layer fold parameters for dfs_next_layer.
      S_DFS_SETUP: begin
        next_d_reg      = dfs_next_layer;
        next_lj_h       = '0;
        next_lj_cons    = '0;
        next_lj_c       = '0;
        next_lj_asm_cnt = '0;
        next_lj_vrd_cnt = '0;
        next_lj_v       = '0;
        next_pkseed_loaded = 1'b0;
        next_v_reg      = '0;
        next_lj_phase   = '0;
        next_lj_cons_offset = '0;
        next_lj_h_offset    = '0;

        case (dfs_next_layer)
          2'd0: begin
            next_lj_rd_base    = VAR_ADDR_WIDTH_COMBINED'(DFS_L1_BASE);
            next_lj_wr_base    = VAR_ADDR_WIDTH_COMBINED'(DFS_L2_BASE
                + {{(32-DFS_GRP_CW){1'b0}}, dfs_l2_cnt} * lj_out_coefs(2'd0) * CHUNK_WORDS);
            next_lj_num_in     = LJ_CONS_CW'({{(LJ_CONS_CW-DFS_GRP_CW){1'b0}}, dfs_l1_sub} + 1);
            next_lj_bits       = (MU1-1)'(i_bits >> C_POS_D1);
            next_lj_in_stride  = VAR_ADDR_WIDTH_COMBINED'(2 * CHUNK_WORDS);
            next_lj_out_stride = VAR_ADDR_WIDTH_COMBINED'(3 * CHUNK_WORDS);
          end
          2'd1: begin
            next_lj_rd_base    = VAR_ADDR_WIDTH_COMBINED'(DFS_L2_BASE);
            next_lj_wr_base    = VAR_ADDR_WIDTH_COMBINED'(DFS_L3_BASE
                + {{(32-DFS_GRP_CW){1'b0}}, dfs_l3_cnt} * lj_out_coefs(2'd1) * CHUNK_WORDS);
            next_lj_num_in     = LJ_CONS_CW'(dfs_l2_cnt);
            next_lj_bits       = (MU1-1)'(i_bits >> C_POS_D2);
            next_lj_in_stride  = VAR_ADDR_WIDTH_COMBINED'(3 * CHUNK_WORDS);
            next_lj_out_stride = VAR_ADDR_WIDTH_COMBINED'(4 * CHUNK_WORDS);
          end
          default: begin
            next_lj_rd_base    = VAR_ADDR_WIDTH_COMBINED'(DFS_L3_BASE);
            next_lj_wr_base    = VAR_ADDR_WIDTH_COMBINED'(DFS_L1_BASE);
            next_lj_num_in     = LJ_CONS_CW'(dfs_l3_cnt);
            next_lj_bits       = (MU1-1)'(i_bits >> C_POS_D3);
            next_lj_in_stride  = VAR_ADDR_WIDTH_COMBINED'(4 * CHUNK_WORDS);
            next_lj_out_stride = VAR_ADDR_WIDTH_COMBINED'(5 * CHUNK_WORDS);
          end
        endcase

        next_state = S_LJ_A0_RD;
      end

      // After a deep-layer fold completes, decide where to go next.
      S_DFS_CHECK: begin
        automatic logic all_l1_done = (h_reg >= H_CW'(NUM_OUT_L1 - 1));

        case (d_reg)
          2'd0: begin
            next_dfs_l2_cnt = dfs_l2_cnt + DFS_GRP_CW'(1);
            if (((dfs_l2_cnt + DFS_GRP_CW'(1)) >= DFS_GRP_CW'(MU3)) || all_l1_done) begin
              next_dfs_next_layer = 2'd1;
              next_state          = S_DFS_SETUP;
            end else begin
              next_dfs_l1_sub = '0;
              next_h_reg      = h_reg + 1;
              next_c_reg      = '0;
              next_w_bit_pos  = '0;
              next_state      = S_L1_GEN_BASE;
            end
          end
          2'd1: begin
            next_dfs_l3_cnt = dfs_l3_cnt + DFS_GRP_CW'(1);
            if (((dfs_l3_cnt + DFS_GRP_CW'(1)) >= DFS_GRP_CW'(MU4)) || all_l1_done) begin
              next_dfs_next_layer = 2'd2;
              next_state          = S_DFS_SETUP;
            end else begin
              next_dfs_l1_sub = '0;
              next_dfs_l2_cnt = '0;
              next_h_reg      = h_reg + 1;
              next_c_reg      = '0;
              next_w_bit_pos  = '0;
              next_state      = S_L1_GEN_BASE;
            end
          end
          default: begin
            // d=2 complete -> DFS fold done. Start UC chain.
            next_uc_d       = 2'd0;
            next_lj_bits    = i_bits[MU1-2:0];
            next_lj_vrd_cnt = '0;
            next_lj_v       = '0;
            next_v_limb_ret = VRET_UC_INIT;
            next_state      = S_V_LIMB_RD;
          end
        endcase
      end

      // ====================================================================
      // Deep layers - inline fold with shared gf_mul_serial
      // ====================================================================

      // --------------------------------------------------------------------
      // Read one LAMBDA-wide V limb from Var BRAM into lj_v.
      // Address depends on v_limb_ret (deep layer vs UC context).
      S_V_LIMB_RD: begin
        automatic int entry_idx;
        case (v_limb_ret)
          VRET_LJ_ISSUE: entry_idx =
              {{(32-WIB_CW){v_i_off[WIB_CW-1]}}, v_i_off}
              + lj_c_pos(d_reg) + {{(32-LJ_K_CW){1'b0}}, lj_k} - 1;
          VRET_UC_INIT: entry_idx =
              {{(32-WIB_CW){v_i_off[WIB_CW-1]}}, v_i_off}
              + uc_v_offset(uc_d);
          default: entry_idx =
              {{(32-WIB_CW){v_i_off[WIB_CW-1]}}, v_i_off}
              + uc_v_offset(uc_d) + {{(32-4){1'b0}}, uc_sub};
        endcase

        if (lj_vrd_cnt < LJ_VRD_CW'(CHUNK_WORDS)) begin
          var_laddr = VAR_ADDR_WIDTH_COMBINED'(
              L1_V_BASE + entry_idx * CW_R_L
              + {{(32-LJ_VRD_CW){1'b0}}, lj_vrd_cnt});
          var_bram_rd = 1'b1;
        end

        if (lj_vrd_cnt >= LJ_VRD_CW'(1))
          next_lj_v[(lj_vrd_cnt - 1) * 64 +: 64] = var_lrdata;

        if (lj_vrd_cnt == LJ_VRD_CW'(CHUNK_WORDS)) begin
          next_lj_vrd_cnt = '0;
          case (v_limb_ret)
            VRET_LJ_ISSUE: next_state = S_LJ_ISSUE_MUL;
            VRET_UC_INIT:  next_state = S_UC_INIT;
            default:       next_state = S_UC_ISSUE;
          endcase
        end else begin
          next_lj_vrd_cnt = lj_vrd_cnt + 1;
        end
      end

      // --------------------------------------------------------------------
      // Read base polynomial a[0] from input BRAM and write to a0/res
      // scratchpads via 3-phase pipeline (read -> write a0 -> write res).
      // Then zero-fill the extra res coefficient. On completion: set arity.
      S_LJ_A0_RD: begin
        logic [31:0] total_a0_words;
        total_a0_words = lj_in_coefs(d_reg) * CHUNK_WORDS;

        if (lj_asm_cnt < LJ_ASM_CW'(total_a0_words)) begin
          case (lj_phase)
            2'd0: begin
              var_laddr = lj_rd_base + lj_cons_offset
                  + VAR_ADDR_WIDTH_COMBINED'(
                      {{(32-LJ_ASM_CW){1'b0}}, lj_asm_cnt});
              var_bram_rd = 1'b1;
              next_lj_phase = 2'd1;
            end
            2'd1: begin
              var_laddr  = VAR_ADDR_WIDTH_COMBINED'(
                  LJ_A0_BRAM_BASE + {{(32-LJ_ASM_CW){1'b0}}, lj_asm_cnt});
              var_lwdata = var_lrdata;
              var_lwr_en = 1'b1;
              next_lj_phase = 2'd2;
            end
            default: begin
              var_laddr  = VAR_ADDR_WIDTH_COMBINED'(
                  LJ_RES_BRAM_BASE + {{(32-LJ_ASM_CW){1'b0}}, lj_asm_cnt});
              var_lwdata = var_lrdata;
              var_lwr_en = 1'b1;
              next_lj_phase   = 2'd0;
              next_lj_asm_cnt = lj_asm_cnt + 1;
            end
          endcase
        end else if (lj_asm_cnt < LJ_ASM_CW'(total_a0_words + CHUNK_WORDS)) begin
          var_laddr  = VAR_ADDR_WIDTH_COMBINED'(
              LJ_RES_BRAM_BASE + {{(32-LJ_ASM_CW){1'b0}}, lj_asm_cnt});
          var_lwdata = 64'b0;
          var_lwr_en = 1'b1;
          next_lj_asm_cnt = lj_asm_cnt + 1;
        end else begin
          next_lj_cons = lj_cons + 1;
          next_lj_cons_offset = lj_cons_offset + lj_in_stride;
          if (lj_remaining >= {{(LJ_CONS_CW+1-LJ_K_CW-1){1'b0}}, (LJ_K_CW+1)'(lj_get_arity(d_reg))})
            next_lj_arity_reg = (LJ_K_CW+1)'(lj_get_arity(d_reg));
          else
            next_lj_arity_reg = (LJ_K_CW+1)'(lj_remaining);
          next_lj_k       = LJ_K_CW'(1);
          next_lj_c       = '0;
          next_lj_asm_cnt = '0;
          next_v_reg       = '0;
          if (lj_remaining <= {{(LJ_CONS_CW){1'b0}}, 1'b1}) begin
            next_lj_wr_cnt = '0;
            next_state = S_LJ_WRITE;
          end else begin
            next_state = S_LJ_AK_RD;
          end
        end
      end

      // --------------------------------------------------------------------
      // Read one coefficient a[k][c] from BRAM into v_reg, then fetch
      // a0[c] from scratchpad for diff/fold computation.
      S_LJ_AK_RD: begin
        if (lj_asm_cnt < LJ_ASM_CW'(CHUNK_WORDS)) begin
          var_laddr = lj_rd_base + lj_cons_offset
              + VAR_ADDR_WIDTH_COMBINED'(
                  {{(32-LJ_C_CW){1'b0}}, lj_c} * CHUNK_WORDS
                  + {{(32-LJ_ASM_CW){1'b0}}, lj_asm_cnt});
          var_bram_rd = 1'b1;
        end
        if (lj_asm_cnt > '0) begin
          next_v_reg[(lj_asm_cnt - 1) * 64 +: 64] = var_lrdata;
        end
        if (lj_asm_cnt == LJ_ASM_CW'(CHUNK_WORDS)) begin
          if (lj_c == LJ_C_CW'(lj_in_coefs(d_reg) - 1)) begin
            next_lj_cons = lj_cons + 1;
            next_lj_cons_offset = lj_cons_offset + lj_in_stride;
          end
          next_lj_asm_cnt = '0;
          next_state       = S_LJ_A0_FETCH;
        end else begin
          next_lj_asm_cnt = lj_asm_cnt + 1;
        end
      end

      // --------------------------------------------------------------------
      // Read a0[c] from scratchpad into base_reg, compute diff, route to
      // RES_RMW (if bit set) or directly to ISSUE_MUL.
      S_LJ_A0_FETCH: begin
        if (lj_asm_cnt < LJ_ASM_CW'(CHUNK_WORDS)) begin
          var_laddr = VAR_ADDR_WIDTH_COMBINED'(
              LJ_A0_BRAM_BASE
              + {{(32-LJ_C_CW){1'b0}}, lj_c} * CHUNK_WORDS
              + {{(32-LJ_ASM_CW){1'b0}}, lj_asm_cnt});
          var_bram_rd = 1'b1;
        end
        if (lj_asm_cnt > '0)
          next_base_reg[(lj_asm_cnt - 1) * 64 +: 64] = var_lrdata;
        if (lj_asm_cnt == LJ_ASM_CW'(CHUNK_WORDS)) begin
          next_delta_reg = v_reg[LAMBDA-1:0] ^ next_base_reg;
          if (lj_bits[lj_k - LJ_K_CW'(1)]) begin
            next_lj_asm_cnt = '0;
            next_state = S_LJ_RES_RMW;
          end else begin
            next_lj_vrd_cnt = '0;
            next_v_limb_ret = VRET_LJ_ISSUE;
            next_state      = S_V_LIMB_RD;
          end
        end else begin
          next_lj_asm_cnt = lj_asm_cnt + 1;
        end
      end

      // --------------------------------------------------------------------
      // RMW: res[c] ^= delta_reg in scratchpad. Alternating read/write
      // cycles, 2 cycles per 64-bit word.
      S_LJ_RES_RMW: begin
        logic [LJ_ASM_CW-1:0] rw;
        rw = lj_asm_cnt >> 1;
        var_laddr = VAR_ADDR_WIDTH_COMBINED'(
            LJ_RES_BRAM_BASE
            + {{(32-LJ_C_CW){1'b0}}, lj_c} * CHUNK_WORDS
            + {{(32-LJ_ASM_CW){1'b0}}, rw});
        var_bram_rd = ~lj_asm_cnt[0];
        if (lj_asm_cnt[0]) begin
          var_lwdata = var_lrdata ^ delta_reg[rw * 64 +: 64];
          var_lwr_en = 1'b1;
        end
        if (lj_asm_cnt == LJ_ASM_CW'(2 * CHUNK_WORDS - 1)) begin
          next_lj_vrd_cnt = '0;
          next_v_limb_ret = VRET_LJ_ISSUE;
          next_state      = S_V_LIMB_RD;
        end else begin
          next_lj_asm_cnt = lj_asm_cnt + 1;
        end
      end

      // --------------------------------------------------------------------
      // Issue v[k-1] * diff through the shared gf_mul_serial.
      S_LJ_ISSUE_MUL: begin
        mul_a        = lj_v_limb(lj_k - LJ_K_CW'(1));
        mul_b        = delta_reg;
        mul_in_valid = 1'b1;
        next_state   = S_LJ_MUL_WAIT;
      end

      // --------------------------------------------------------------------
      // Wait for mul result, latch into acc0_reg, then RMW res[c+1].
      S_LJ_MUL_WAIT: begin
        if (mul_out_valid) begin
          next_acc0_reg   = mul_out;
          next_lj_asm_cnt = '0;
          next_state      = S_LJ_RES_MUL_ACC;
        end
      end

      // --------------------------------------------------------------------
      // RMW: res[c+1] ^= acc0_reg in scratchpad. Then advance (c, k).
      S_LJ_RES_MUL_ACC: begin
        logic [LJ_ASM_CW-1:0] rw;
        rw = lj_asm_cnt >> 1;
        var_laddr = VAR_ADDR_WIDTH_COMBINED'(
            LJ_RES_BRAM_BASE
            + ({{(32-LJ_C_CW){1'b0}}, lj_c} + 1) * CHUNK_WORDS
            + {{(32-LJ_ASM_CW){1'b0}}, rw});
        var_bram_rd = ~lj_asm_cnt[0];
        if (lj_asm_cnt[0]) begin
          var_lwdata = var_lrdata ^ acc0_reg[rw * 64 +: 64];
          var_lwr_en = 1'b1;
        end
        if (lj_asm_cnt == LJ_ASM_CW'(2 * CHUNK_WORDS - 1)) begin
          if (lj_c == LJ_C_CW'(lj_in_coefs(d_reg) - 1)) begin
            next_lj_c = '0;
            if ({{1'b0, lj_k} == lj_arity_reg - (LJ_K_CW+1)'(1)}) begin
              next_lj_wr_cnt = '0;
              next_state = S_LJ_WRITE;
            end else begin
              next_lj_k       = lj_k + LJ_K_CW'(1);
              next_lj_asm_cnt = '0;
              next_v_reg       = '0;
              next_state       = S_LJ_AK_RD;
            end
          end else begin
            next_lj_c       = lj_c + 1;
            next_lj_asm_cnt = '0;
            next_v_reg       = '0;
            next_state       = S_LJ_AK_RD;
          end
        end else begin
          next_lj_asm_cnt = lj_asm_cnt + 1;
        end
      end

      // --------------------------------------------------------------------
      // Write result polynomial from res scratchpad to output BRAM.
      // Alternating: even cycles read from res BRAM, odd cycles write to output.
      S_LJ_WRITE: begin
        logic [LJ_WR_CW-1:0] half_cnt;
        half_cnt = lj_wr_cnt >> 1;
        if (lj_wr_cnt[0] == 1'b0) begin
          var_laddr = VAR_ADDR_WIDTH_COMBINED'(
              LJ_RES_BRAM_BASE + {{(32-LJ_WR_CW){1'b0}}, half_cnt});
          var_bram_rd = 1'b1;
        end else begin
          var_laddr  = lj_wr_base + lj_h_offset
              + VAR_ADDR_WIDTH_COMBINED'(
                  {{(32-LJ_WR_CW){1'b0}}, half_cnt});
          var_lwdata = var_lrdata;
          var_lwr_en = 1'b1;
        end
        if (lj_wr_cnt == LJ_WR_CW'(2 * lj_out_coefs(d_reg) * CHUNK_WORDS - 1)) begin
          if (lj_cons == lj_num_in) begin
            next_state = S_LJ_NEXT_D;
          end else begin
            next_lj_h       = lj_h + 1;
            next_lj_h_offset = lj_h_offset + lj_out_stride;
            next_lj_c       = '0;
            next_lj_asm_cnt = '0;
            next_v_reg       = '0;
            next_lj_phase    = '0;
            next_state       = S_LJ_A0_RD;
          end
        end else begin
          next_lj_wr_cnt = lj_wr_cnt + 1;
        end
      end

      // --------------------------------------------------------------------
      // Advance to next deep layer or finish.
      // After each deep-layer fold: enter UC for that layer.
      // lj_bits already holds the correct values from S_DFS_SETUP.
      S_LJ_NEXT_D: begin
        next_state = S_DFS_CHECK;
      end

      // ====================================================================
      // UC computation + Palpha update
      // ====================================================================

      // Init UC computation: compute bit echelons (combinational), set up
      // V accumulators. lj_v holds V[0] pre-loaded by S_V_LIMB_RD.
      S_UC_INIT: begin
        logic [31:0] a;
        a = uc_arity(uc_d);
        next_acc0_reg  = bit_ech(a, 1);
        next_acc1_reg  = lj_v;
        next_base_reg  = bit_ech(a - 1, a);
        next_delta_reg = lj_v;
        next_v_reg[LAMBDA-1:0] = lj_v;
        next_uc_sub    = 4'd1;
        if (a >= 2) begin
          next_uc_phase   = UCP_T1;
          next_lj_vrd_cnt = '0;
          next_v_limb_ret = VRET_UC_ISSUE;
          next_state      = S_V_LIMB_RD;
        end else begin
          next_uc_phase = UCP_FIN;
          next_state    = S_UC_PA_RMW;
        end
      end

      // Generic UC mul issue/wait: selects operands based on (uc_phase, uc_sub).
      S_UC_ISSUE: begin
        case (uc_phase)
          UCP_T1: begin
            mul_a = uc_v_limb(uc_sub);
            mul_b = x_pow(int'(uc_sub));
          end
          UCP_T2: begin
            mul_a = uc_v_limb(uc_sub);
            mul_b = uc_xpow;
          end
          UCP_SCHOOL: begin
            case (uc_sub)
              4'd1: begin
                mul_a = acc0_reg;
                mul_b = delta_reg;
              end
              4'd2: begin
                mul_a = acc1_reg;
                mul_b = base_reg;
              end
              default: begin
                mul_a = acc1_reg;
                mul_b = delta_reg;
              end
            endcase
          end
          UCP_T2P: begin
            mul_a = uc_v_limb(uc_sub);
            mul_b = uc_xpow;
          end
          UCP_FIN: begin
            case (uc_sub)
              4'd1: begin
                mul_a = acc0_reg ^ v_reg[LAMBDA-1:0];
                mul_b = delta_reg;
              end
              default: begin
                mul_a = acc1_reg;
                mul_b = delta_reg;
              end
            endcase
          end
          default: ;
        endcase
        mul_in_valid = 1'b1;
        next_state   = S_UC_WAIT;
      end

      S_UC_WAIT: begin
        if (mul_out_valid) begin
          logic [31:0] a;
          a = uc_arity(uc_d);
          case (uc_phase)
            UCP_T1: begin
              next_acc1_reg = acc1_reg ^ mul_out;
              if (uc_sub == 4'(a - 1)) begin
                if (a >= 3) begin
                  next_uc_sub = 4'd1;
                  next_uc_phase = UCP_T2;
                  next_uc_xpow = x_pow(a);
                  next_lj_vrd_cnt = '0;
                  next_v_limb_ret = VRET_UC_ISSUE;
                  next_state = S_V_LIMB_RD;
                end else begin
                  next_uc_sub = 4'd1;
                  next_uc_phase = UCP_SCHOOL;
                  next_state = S_UC_ISSUE;
                end
              end else begin
                next_uc_sub = uc_sub + 4'd1;
                next_lj_vrd_cnt = '0;
                next_v_limb_ret = VRET_UC_ISSUE;
                next_state = S_V_LIMB_RD;
              end
            end
            UCP_T2: begin
              next_delta_reg = delta_reg ^ mul_out;
              if (uc_sub == 4'(a - 2)) begin
                next_uc_sub = 4'd1;
                next_uc_phase = UCP_SCHOOL;
                next_state = S_UC_ISSUE;
              end else begin
                next_uc_sub = uc_sub + 4'd1;
                next_uc_xpow = LAMBDA'(uc_xpow << a);
                next_lj_vrd_cnt = '0;
                next_v_limb_ret = VRET_UC_ISSUE;
                next_state = S_V_LIMB_RD;
              end
            end
            UCP_SCHOOL: begin
              case (uc_sub)
                4'd1: next_acc0_reg = mul_out;
                4'd2: next_acc0_reg = acc0_reg ^ mul_out;
                default: next_acc1_reg = mul_out;
              endcase
              if (uc_sub == 4'd3) begin
                if (a >= 3) begin
                  next_uc_sub = 4'd1;
                  next_uc_phase = UCP_T2P;
                  next_uc_xpow = x_pow(a + 1);
                  next_lj_vrd_cnt = '0;
                  next_v_limb_ret = VRET_UC_ISSUE;
                  next_state = S_V_LIMB_RD;
                end else begin
                  next_uc_sub = 4'd1;
                  next_uc_phase = UCP_FIN;
                  next_lj_asm_cnt = '0;
                  next_lj_phase = 2'd0;
                  next_state = S_UC_COEFF_RD;
                end
              end else begin
                next_uc_sub = uc_sub + 4'd1;
                next_state = S_UC_ISSUE;
              end
            end
            UCP_T2P: begin
              next_v_reg[LAMBDA-1:0] = v_reg[LAMBDA-1:0] ^ mul_out;
              if (uc_sub == 4'(a - 2)) begin
                next_uc_sub = 4'd1;
                next_uc_phase = UCP_FIN;
                next_lj_asm_cnt = '0;
                next_lj_phase = 2'd0;
                next_state = S_UC_COEFF_RD;
              end else begin
                next_uc_sub = uc_sub + 4'd1;
                next_uc_xpow = LAMBDA'(uc_xpow << (a + 1));
                next_lj_vrd_cnt = '0;
                next_v_limb_ret = VRET_UC_ISSUE;
                next_state = S_V_LIMB_RD;
              end
            end
            UCP_FIN: begin
              case (uc_sub)
                4'd1: next_acc0_reg = mul_out;
                default: next_acc1_reg = mul_out;
              endcase
              if (uc_sub == 4'd2) begin
                next_pa_coef = 4'd1;
                next_pa_step = '0;
                next_state = S_UC_PA_RMW;
              end else begin
                next_uc_sub = uc_sub + 4'd1;
                next_state = S_UC_ISSUE;
              end
            end
            default: next_state = S_UC_PA_RMW;
          endcase
        end
      end

      S_UC_PA_RMW: begin
        automatic logic [LAMBDA-1:0] uc_word =
            (pa_coef == 4'd1) ? acc0_reg : acc1_reg;
        automatic logic [RMW_CW-1:0] w = pa_step >> 1;
        sig_addr_o = SIG_ADDR_WIDTH'(PALPHA_SIG_OFFSET
                        + {{(SIG_ADDR_WIDTH-4){1'b0}}, (pa_coef - 4'd1)} * CHUNK_WORDS + w);
        if (pa_step[0] == 1'b0) begin
          // Read phase
        end else begin
          sig_data_o  = sig_data_i ^ uc_word[w*64 +: 64];
          sig_wr_en_o = 1'b1;
        end
        if (pa_step == RMW_CW'(2*CHUNK_WORDS - 1)) begin
          if (pa_coef == 4'd2) begin
            if (uc_arity(uc_d) >= 2) begin
              next_state = S_UC_ADV;
            end else begin
              next_lj_asm_cnt = '0;
              next_lj_phase   = 2'd1;
              next_state      = S_UC_COEFF_RD;
            end
          end else begin
            next_pa_coef = pa_coef + 1;
            next_pa_step = '0;
          end
        end else begin
          next_pa_step = pa_step + 1;
        end
      end

      // Advance unitary challenge: coeff *= x^32
      S_UC_ADV: begin
        mul_a        = delta_reg;
        mul_b        = LAMBDA'(1) << 32;
        mul_in_valid = 1'b1;
        next_state   = S_UC_ADV_WAIT;
      end

      S_UC_ADV_WAIT: begin
        if (mul_out_valid) begin
          next_delta_reg  = mul_out;
          next_lj_asm_cnt = '0;
          next_state      = S_UC_COEFF_WR;
        end
      end

      // Read uc_coeff from BRAM scratchpad into delta_reg.
      // lj_phase: 0 = return to S_UC_ISSUE (FIN), 1 = return to S_UC_ADV.
      S_UC_COEFF_RD: begin
        if (lj_asm_cnt < LJ_ASM_CW'(CHUNK_WORDS)) begin
          var_laddr = VAR_ADDR_WIDTH_COMBINED'(
              UC_COEFF_BRAM_BASE + {{(VAR_ADDR_WIDTH_COMBINED-LJ_ASM_CW){1'b0}}, lj_asm_cnt});
          var_bram_rd = 1'b1;
        end
        if (lj_asm_cnt > '0)
          next_delta_reg[(lj_asm_cnt - 1) * 64 +: 64] = var_lrdata;
        if (lj_asm_cnt == LJ_ASM_CW'(CHUNK_WORDS)) begin
          next_lj_asm_cnt = '0;
          next_state = (lj_phase == 2'd0) ? S_UC_ISSUE : S_UC_ADV;
        end else begin
          next_lj_asm_cnt = lj_asm_cnt + 1;
        end
      end

      // Write delta_reg (new uc_coeff) to BRAM scratchpad after UC_ADV.
      S_UC_COEFF_WR: begin
        var_laddr  = VAR_ADDR_WIDTH_COMBINED'(
            UC_COEFF_BRAM_BASE + {{(VAR_ADDR_WIDTH_COMBINED-LJ_ASM_CW){1'b0}}, lj_asm_cnt});
        var_lwdata = delta_reg[lj_asm_cnt * 64 +: 64];
        var_lwr_en = 1'b1;
        if (lj_asm_cnt == LJ_ASM_CW'(CHUNK_WORDS - 1)) begin
          if (uc_d == 2'd3) begin
            next_pa_coef    = 4'd1;
            next_lj_asm_cnt = '0;
            next_state      = S_LJ_RES_PRELOAD;
          end else begin
            next_uc_d       = uc_d + 2'd1;
            next_lj_vrd_cnt = '0;
            next_lj_bits    = (MU1-1)'(i_bits >> lj_c_pos(uc_d[1:0]));
            next_v_limb_ret = VRET_UC_INIT;
            next_state      = S_V_LIMB_RD;
          end
        end else begin
          next_lj_asm_cnt = lj_asm_cnt + 1;
        end
      end

      // Pre-load res[pa_coef] from BRAM scratchpad into acc0_reg.
      S_LJ_RES_PRELOAD: begin
        if (lj_asm_cnt < LJ_ASM_CW'(CHUNK_WORDS)) begin
          var_laddr = VAR_ADDR_WIDTH_COMBINED'(
              LJ_RES_BRAM_BASE
              + {{(32-4){1'b0}}, pa_coef} * CHUNK_WORDS
              + {{(32-LJ_ASM_CW){1'b0}}, lj_asm_cnt});
          var_bram_rd = 1'b1;
        end
        if (lj_asm_cnt > '0)
          next_acc0_reg[(lj_asm_cnt - 1) * 64 +: 64] = var_lrdata;
        if (lj_asm_cnt == LJ_ASM_CW'(CHUNK_WORDS)) begin
          next_pa_step = '0;
          next_state   = S_NODE_PA_RMW;
        end else begin
          next_lj_asm_cnt = lj_asm_cnt + 1;
        end
      end

      // XOR final node polynomial (DEGREE+1 coefficients) into Palpha.
      // acc0_reg holds res[pa_coef] pre-loaded by S_LJ_RES_PRELOAD.
      S_NODE_PA_RMW: begin
        automatic logic [RMW_CW-1:0] w = pa_step >> 1;
        sig_addr_o = SIG_ADDR_WIDTH'(PALPHA_SIG_OFFSET
                        + {{(SIG_ADDR_WIDTH-4){1'b0}}, (pa_coef - 4'd1)} * CHUNK_WORDS + w);
        if (pa_step[0] == 1'b0) begin
          // Read phase
        end else begin
          sig_data_o  = sig_data_i ^ acc0_reg[w*64 +: 64];
          sig_wr_en_o = 1'b1;
        end
        if (pa_step == RMW_CW'(2*CHUNK_WORDS - 1)) begin
          if (pa_coef == 4'(DEGREE)) begin
            automatic logic [I_CW-1:0] i_limit = pass_i_end();
            if (dbg_i_limit_i != '0 && dbg_i_limit_i < i_limit)
              i_limit = dbg_i_limit_i;
            if (i_cnt >= I_CW'(W)) begin
              next_state      = S_DONE;
            end else if (i_cnt >= i_limit)
              next_state = S_DONE;
            else begin
              next_gammap_cnt  = '0;
              next_state       = S_SQUEEZE_GAMMAP;
            end
          end else begin
            next_pa_coef    = pa_coef + 1;
            next_lj_asm_cnt = '0;
            next_state      = S_LJ_RES_PRELOAD;
          end
        end else
          next_pa_step = pa_step + 1;
      end

      // --------------------------------------------------------------------
      S_DONE: begin
        fsm_done_o = 1'b1;
        next_state = S_IDLE;
      end

      default: next_state = S_IDLE;
    endcase
  end

  // =========================================================================
  // Sequential - with output pipeline registers and BRAM read stall
  //
  // BRAM and AES output ports are registered to break the critical
  // combinational path (process_pwit state mux -> piop mux -> sign mux -> BRAM).
  // =========================================================================
  always_ff @(posedge clk_i or posedge rst_i) begin
    if (rst_i) begin
      state          <= S_IDLE;
      absorb_cnt     <= '0;
      squeeze_cnt    <= '0;
      gamma_idx      <= '0;
      gamma_ret      <= '0;
      dfs_l1_sub     <= '0;
      dfs_l2_cnt     <= '0;
      dfs_l3_cnt     <= '0;
      dfs_next_layer <= '0;
      gammap_cnt     <= '0;
      i_cnt          <= '0;
      h_reg          <= '0;
      c_reg          <= '0;
      xi_run         <= '0;
      xi_pos         <= '0;
      xi_limb        <= '0;
      base_reg       <= '0;
      delta_reg      <= '0;
      acc0_reg       <= '0;
      acc1_reg       <= '0;
      v_reg          <= '0;
      v_cnt          <= '0;
      write_cnt      <= '0;
      w_bit_pos      <= '0;
      i_bits         <= '0;
      wit_batch_base <= '0;
      col_abs        <= '0;
      wit_i_base     <= '0;
      v_i_off        <= '0;
      aes_ctr        <= '0;
      aes_bit_off    <= '0;
      aes_r_idx      <= '0;
      aes_is_gk      <= 1'b0;
      aes_limb       <= '0;
      aes_shift      <= '0;
      pkseed_loaded  <= 1'b0;
      uc_d           <= '0;
      uc_phase       <= UCP_T1;
      uc_sub         <= '0;
      pa_coef        <= '0;
      pa_step        <= '0;
      d_reg          <= '0;
      lj_bits        <= '0;
      lj_v           <= '0;
      v_limb_ret     <= '0;
      lj_phase       <= '0;
      lj_k           <= '0;
      lj_c           <= '0;
      lj_h           <= '0;
      lj_cons        <= '0;
      lj_asm_cnt     <= '0;
      lj_vrd_cnt     <= '0;
      lj_wr_cnt      <= '0;
      lj_arity_reg   <= '0;
      lj_num_in      <= '0;
      lj_rd_base     <= '0;
      lj_wr_base     <= '0;
      bram_rd_wait   <= 1'b0;
      // Registered outputs
      var_a_addr_o   <= '0;
      var_a_data_o   <= '0;
      var_a_wr_en_o  <= 1'b0;
      var_b_addr_o   <= '0;
      var_b_data_o   <= '0;
      var_b_wr_en_o  <= 1'b0;
      aes0_key_o       <= '0;
      aes0_plaintext_o <= '0;
      aes0_enable_o    <= 1'b0;
      aes1_key_o       <= '0;
      aes1_plaintext_o <= '0;
      aes1_enable_o    <= 1'b0;
    end else if (bram_rd_wait) begin
      // see bram_rd_wait
      bram_rd_wait <= 1'b0;
    end else begin
      state          <= next_state;
      absorb_cnt     <= next_absorb_cnt;
      squeeze_cnt    <= next_squeeze_cnt;
      gamma_idx      <= next_gamma_idx;
      gamma_ret      <= next_gamma_ret;
      dfs_l1_sub     <= next_dfs_l1_sub;
      dfs_l2_cnt     <= next_dfs_l2_cnt;
      dfs_l3_cnt     <= next_dfs_l3_cnt;
      dfs_next_layer <= next_dfs_next_layer;
      gammap_cnt     <= next_gammap_cnt;
      i_cnt          <= next_i_cnt;
      h_reg          <= next_h_reg;
      c_reg          <= next_c_reg;
      xi_run         <= next_xi_run;
      xi_pos         <= next_xi_pos;
      xi_limb        <= next_xi_limb;
      base_reg       <= next_base_reg;
      delta_reg      <= next_delta_reg;
      acc0_reg       <= next_acc0_reg;
      acc1_reg       <= next_acc1_reg;
      v_reg          <= next_v_reg;
      v_cnt          <= next_v_cnt;
      write_cnt      <= next_write_cnt;
      w_bit_pos      <= next_w_bit_pos;
      i_bits         <= next_i_bits;
      wit_batch_base <= next_wit_batch_base;
      col_abs        <= next_col_abs;
      wit_i_base     <= next_wit_i_base;
      v_i_off        <= next_v_i_off;
      aes_ctr        <= next_aes_ctr;
      aes_bit_off    <= next_aes_bit_off;
      aes_r_idx      <= next_aes_r_idx;
      aes_is_gk      <= next_aes_is_gk;
      aes_limb       <= next_aes_limb;
      aes_shift      <= next_aes_shift;
      pkseed_loaded  <= next_pkseed_loaded;
      uc_d           <= next_uc_d;
      uc_phase       <= next_uc_phase;
      uc_sub         <= next_uc_sub;
      uc_xpow        <= next_uc_xpow;
      pa_coef        <= next_pa_coef;
      pa_step        <= next_pa_step;
      d_reg          <= next_d_reg;
      lj_bits        <= next_lj_bits;
      lj_v           <= next_lj_v;
      v_limb_ret     <= next_v_limb_ret;
      lj_phase       <= next_lj_phase;
      lj_k           <= next_lj_k;
      lj_c           <= next_lj_c;
      lj_h           <= next_lj_h;
      lj_cons        <= next_lj_cons;
      lj_asm_cnt     <= next_lj_asm_cnt;
      lj_vrd_cnt     <= next_lj_vrd_cnt;
      lj_wr_cnt      <= next_lj_wr_cnt;
      lj_arity_reg   <= next_lj_arity_reg;
      lj_num_in      <= next_lj_num_in;
      lj_rd_base     <= next_lj_rd_base;
      lj_wr_base     <= next_lj_wr_base;
      lj_in_stride   <= next_lj_in_stride;
      lj_cons_offset <= next_lj_cons_offset;
      lj_out_stride  <= next_lj_out_stride;
      lj_h_offset    <= next_lj_h_offset;
      bram_rd_wait   <= var_bram_rd & ~bram_rd_wait;
      // Registered BRAM outputs
      var_a_addr_o   <= phys_a(var_laddr);
      var_a_data_o   <= split_a(var_lwdata);
      var_a_wr_en_o  <= var_lwr_en;
      var_b_addr_o   <= phys_b(var_laddr);
      var_b_data_o   <= split_b(var_lwdata);
      var_b_wr_en_o  <= var_lwr_en;
      // Registered AES outputs
      aes0_key_o       <= aes0_key_comb;
      aes0_plaintext_o <= aes0_plaintext_comb;
      aes0_enable_o    <= aes0_enable_comb;
      aes1_key_o       <= aes1_key_comb;
      aes1_plaintext_o <= aes1_plaintext_comb;
      aes1_enable_o    <= aes1_enable_comb;
    end
  end

endmodule
