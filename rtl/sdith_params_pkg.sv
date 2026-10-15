// SPDX-FileCopyrightText: 2026 Stef Halmans, Niklas Höher
// SPDX-License-Identifier: LicenseRef-RUB-SecEng

// =============================================================================
//  sdith_params_pkg - SDitH hardware parameter package
//
//  Single source of truth for all configuration-dependent constants used by
//  the SDitH RTL. Config knobs:
//
//      SECURITY_LEVEL   NIST category  { 1, 3, 5 }
//      PARAMETER_SET    speed/size     { PARAMS_SHORT (0), PARAMS_FAST (1) }
//      HCOM_IN_PHASE12  alt hcom path  { 0 = DFS-based (KAT-faithful, default),
//                                        1 = in-phase12 (spec-order, no KAT) }
//      HALF_POLY        PIOP mode      { 0 = 5-chunk, 1 = half-poly 2-pass (default) }
//      CACHE_DEPTH      GGM tree cache { default 8 (SEC1) / 7 (SEC3/5), up to
//                                        GGM_TREE_DEPTH for full leaf caching }
//
//  Override at compile time (Verilator / Vivado -D flags):
//      -DSEC_LEVEL=3 -DPARAM_SET=1 -DHCOM_IN_PHASE12=0 -DHALF_POLY=1 -DCACHE_DEPTH=10
//
//  Shared combinational helpers (bswap64, phys_a/b, split_a/b, ctz_func) live
//  in sdith_helpers_pkg - import that separately where needed.
//// =============================================================================

package sdith_params_pkg;

    // =========================================================================
    // 1. Type definitions + top-level configuration
    // =========================================================================

    typedef enum logic [0:0] {
        PARAMS_SHORT = 1'b0,  // smaller signature, more computation
        PARAMS_FAST  = 1'b1   // faster signing, larger signature
    } params_e;

    typedef enum logic [0:0] {
        HASH_SHAKE128 = 1'b0,
        HASH_SHAKE256 = 1'b1
    } hash_e;

    typedef enum logic [0:0] {
        ENC_AES128      = 1'b0,
        ENC_RIJNDAEL256 = 1'b1
    } enc_e;

    // Compile-time overrides
`ifndef SEC_LEVEL
`define SEC_LEVEL 3
`endif
`ifndef PARAM_SET
`define PARAM_SET 1
`endif
`ifndef HCOM_IN_PHASE12
`define HCOM_IN_PHASE12 0
`endif
`ifndef HALF_POLY
`define HALF_POLY 1
`endif
    parameter int      SECURITY_LEVEL  = `SEC_LEVEL;             // 1 / 3 / 5
    parameter params_e PARAMETER_SET   = params_e'(`PARAM_SET);  // SHORT / FAST
    parameter int      HCOM_IN_PHASE12 = `HCOM_IN_PHASE12;       // 0 = default (KAT), 1 = alt spec-order
    parameter int      HALF_POLY       = `HALF_POLY;             // 0 = 5-chunk, 1 = half-poly 2-pass

    // =========================================================================
    // 2. Security-level basics
    // =========================================================================
    parameter int LAMBDA =
        (SECURITY_LEVEL == 1) ? 128 :
        (SECURITY_LEVEL == 3) ? 192 : 256;
    parameter int LAMBDA_DIV_64 = LAMBDA / 64;

    // =========================================================================
    // 3. Symmetric primitives (AES / SHAKE)
    //    - SEC1 uses AES-128 + SHAKE128 (128-bit block / 128-bit hash rate)
    //    - SEC3/5 use Rijndael-256 + SHAKE256 (256-bit block / 256-bit hash rate)
    // =========================================================================
    parameter hash_e HASH_XOF =
        (SECURITY_LEVEL == 1) ? HASH_SHAKE128 : HASH_SHAKE256;

    parameter enc_e ENC =
        (SECURITY_LEVEL == 1) ? ENC_AES128 : ENC_RIJNDAEL256;

    parameter int ENC_BLOCKSIZE =
        (SECURITY_LEVEL == 1) ? 128 : 256;
    parameter int ENC_KEYSIZE   = ENC_BLOCKSIZE;
    parameter int BLOCK_DIV_64  = ENC_BLOCKSIZE / 64;

    // =========================================================================
    // 4. SDitH scheme parameters
    //    Per security-level + param-set from NIST submission tables.
    //    Spec notation: tau, kappa, w_pow, T_open, n, k, w, mu1..mu_d
    // =========================================================================

    // tau - number of parallel repetitions (one GGM tree per repetition)
    parameter int TAU =
        (SECURITY_LEVEL == 1 && PARAMETER_SET == PARAMS_SHORT) ?  11 :
        (SECURITY_LEVEL == 1 && PARAMETER_SET == PARAMS_FAST ) ?  16 :
        (SECURITY_LEVEL == 3 && PARAMETER_SET == PARAMS_SHORT) ?  16 :
        (SECURITY_LEVEL == 3 && PARAMETER_SET == PARAMS_FAST ) ?  24 :
        (SECURITY_LEVEL == 5 && PARAMETER_SET == PARAMS_SHORT) ?  21 :
        (SECURITY_LEVEL == 5 && PARAMETER_SET == PARAMS_FAST ) ?  32 : 0;

    // kappa - GGM tree depth; N_CAP = 2^kappa leaves per tree
    parameter int KAPPA =
        (SECURITY_LEVEL == 1 && PARAMETER_SET == PARAMS_SHORT) ?  11 :
        (SECURITY_LEVEL == 1 && PARAMETER_SET == PARAMS_FAST ) ?   8 :
        (SECURITY_LEVEL == 3 && PARAMETER_SET == PARAMS_SHORT) ?  12 :
        (SECURITY_LEVEL == 3 && PARAMETER_SET == PARAMS_FAST ) ?   8 :
        (SECURITY_LEVEL == 5 && PARAMETER_SET == PARAMS_SHORT) ?  12 :
        (SECURITY_LEVEL == 5 && PARAMETER_SET == PARAMS_FAST ) ?   8 : 0;

    // w_pow - proof-of-work threshold exponent
    parameter int W_POW =
        (SECURITY_LEVEL == 1 && PARAMETER_SET == PARAMS_SHORT) ?   9 :
        (SECURITY_LEVEL == 1 && PARAMETER_SET == PARAMS_FAST ) ?   2 :
        (SECURITY_LEVEL == 3 && PARAMETER_SET == PARAMS_SHORT) ?   2 :
        (SECURITY_LEVEL == 3 && PARAMETER_SET == PARAMS_FAST ) ?   2 :
        (SECURITY_LEVEL == 5 && PARAMETER_SET == PARAMS_SHORT) ?   6 :
        (SECURITY_LEVEL == 5 && PARAMETER_SET == PARAMS_FAST ) ?   2 : 0;

    // T_open - number of revealed sibling paths in the signature
    parameter int T_OPEN =
        (SECURITY_LEVEL == 1 && PARAMETER_SET == PARAMS_SHORT) ? 107 :
        (SECURITY_LEVEL == 1 && PARAMETER_SET == PARAMS_FAST ) ? 101 :
        (SECURITY_LEVEL == 3 && PARAMETER_SET == PARAMS_SHORT) ? 157 :
        (SECURITY_LEVEL == 3 && PARAMETER_SET == PARAMS_FAST ) ? 153 :
        (SECURITY_LEVEL == 5 && PARAMETER_SET == PARAMS_SHORT) ? 216 :
        (SECURITY_LEVEL == 5 && PARAMETER_SET == PARAMS_FAST ) ? 207 : 0;

    // Restricted syndrome decoding (RSD) code dimensions: n, k, n-k, w
    parameter int N =
        (SECURITY_LEVEL == 1) ? 10360 :
        (SECURITY_LEVEL == 3) ? 18396 : 19864;
    parameter int K_RSD =
        (SECURITY_LEVEL == 1) ?  9928 :
        (SECURITY_LEVEL == 3) ? 17804 : 19064;
    parameter int N_MINUS_K_RSD =
        (SECURITY_LEVEL == 1) ? 432 :
        (SECURITY_LEVEL == 3) ? 592 : 800;
    parameter int W =
        (SECURITY_LEVEL == 1) ?  56 :
        (SECURITY_LEVEL == 3) ?  73 : 104;
    parameter int M = N / W;    // m = n/w - number of mux circuit evaluations

    // mu1..mu_d - mux tree arities; |wit| = sum(mu_i-1) * w
    parameter int MU1 = 4;
    parameter int MU2 = 4;
    parameter int MU3 = 4;
    parameter int MU4 = (SECURITY_LEVEL == 3) ? 4 : 3;

    // =========================================================================
    // 5. Scheme constants
    // =========================================================================
    parameter int Q      = 2;    // field characteristic (GF(2))
    parameter int B      = 16;   // bias parameter - extra bits in r_cchk region
    parameter int DEGREE = 4;    // d - mux circuit polynomial degree; P_alpha(X) has degree d

    // =========================================================================
    // 6. Derived sizes
    //    |wit|, L (VOLE length), N_CAP, VOLE pair layout, alpha column size
    // =========================================================================
    parameter int WIT_SIZE = (MU1-1 + MU2-1 + MU3-1 + MU4-1) * W;   // |wit| in bits

    // L - total VOLE length per leaf = |r_cchk| + |r_cz| + |r_wit|
    parameter int R_ACC_SIZE       = WIT_SIZE + 3*LAMBDA + LAMBDA + B;
    parameter int R_ACC_SIZE_BYTES = (R_ACC_SIZE + 7) / 8;     // L in bytes (C par.Lbyte)
    parameter int R_ACC_SIZE_ROUND = R_ACC_SIZE_BYTES * 8;     // L rounded up (C par.L)
    parameter int R_ACC_PARTS      = (R_ACC_SIZE + 63) / 64;   // L in 64-bit words
    parameter int R_ACC_LAST       = R_ACC_PARTS * 64 - R_ACC_SIZE;  // padding bits

    // N_CAP = 2^kappa - leaves per GGM tree
    parameter int N_CAP = 1 << KAPPA;

    // VOLE pair layout (C ordering: [r_cchk | r_cz | r_wit])
    parameter int NUM_CCHK_PAIRS = ((KAPPA * TAU + B + 7) / 8) * 8;  // |r_cchk| - consistency check pairs
    parameter int NUM_CZ_PAIRS   = (DEGREE - 1) * LAMBDA;             // |r_cz| = (d-1)*lambda - check-zero pairs for P_alpha
    parameter int R_WIT_OFFSET   = NUM_CCHK_PAIRS + NUM_CZ_PAIRS;     // offset to r_wit in u/V vectors

    // alpha column size - rows of the consistency check matrix M
    parameter int ALPHA_COL_BITS  = LAMBDA + B;
    parameter int ALPHA_COL_WORDS = (ALPHA_COL_BITS + 63) / 64;

    // =========================================================================
    // 7. GF(2^lambda) reduction polynomial (excludes the leading x^lambda term)
    //    GF(2^128): x^128 + x^7 + x^2 + x + 1    -> 0x87  (degree 7)
    //    GF(2^192): x^192 + x^7 + x^2 + x + 1    -> 0x87  (degree 7)
    //    GF(2^256): x^256 + x^10 + x^5 + x^2 + 1 -> 0x425 (degree 10)
    // =========================================================================
    parameter int GF_POLY        = (SECURITY_LEVEL == 5) ? 1061 : 135;
    parameter int GF_POLY_DEGREE = (SECURITY_LEVEL == 5) ? 10   : 7;

    // =========================================================================
    // 8. GGM tree + cache tree geometry
    //    The GGM tree has TAU * N_CAP leaves total, arranged in TAU groups.
    //    For non-power-of-2 TAU*N_CAP, the tree is depth-mixed (some leaves
    //    at depth D-1, others at depth D) - GGM_TREE_DEPTH is the deeper one.
    //    The cache tree stores nodes at CACHE_TREE_DEPTH as precomputed roots
    //    for fast leaf fetching during commit phases.
    // =========================================================================
    parameter int GGM_TREE_DEPTH = $clog2(TAU * N_CAP) + ((TAU == 16 || TAU == 32) ? 1 : 0);
    parameter int GGM_TREE_SIZE  = TAU * N_CAP;

    parameter int CACHE_TREE_DEPTH =
`ifdef CACHE_DEPTH
        `CACHE_DEPTH;
`else
        (SECURITY_LEVEL >= 3) ? 7 : 8;
`endif
    parameter int CACHE_ENTRIES = 1 << CACHE_TREE_DEPTH;

    // =========================================================================
    // 9. Physical BRAM primitive sizing (Xilinx RAMB36E1)
    //    TDP width 36 (32 data + 4 parity): 1024-deep - used for dual-port var mem
    //    SDP width 72 (64 data + 8 parity): 512-deep  - used for 64-bit single-port
    // =========================================================================
    parameter int BRAM_TDP_DEPTH_32     = 1024;
    parameter int BRAM_SDP_DEPTH_64     = 512;
    parameter int BRAM_WIDTH_64_BLOCKS  = BRAM_SDP_DEPTH_64;
    parameter int CACHE_BRAM_DEPTH      = (1 << CACHE_TREE_DEPTH) * (LAMBDA / 64);
    parameter int CACHE_ADDR_WIDTH      = $clog2(CACHE_BRAM_DEPTH);
    parameter int BRAM_ADDR_SIZE        = $clog2(BRAM_WIDTH_64_BLOCKS) - 1;

    // External message BRAM (read-only from sign) - length-prefixed layout:
    //   word 0     = message length in bytes (64-bit LE)
    //   words 1..N = message data (64-bit LE, zero-padded to 8B boundary)
    parameter int MSG_MEM_WORDS  = BRAM_SDP_DEPTH_64;               // 512 (1 RAMB36E1)
    parameter int MSG_ADDR_WIDTH = $clog2(MSG_MEM_WORDS);
    parameter int MSG_MAX_BYTES  = (MSG_MEM_WORDS - 1) * 8;         // 4088B max

    // Key BRAM layout (external) - byte layout mirrors the reference SK
    // serialization (skey_mapping_t in sw_reference_implementation/*/sdith_signature.c):
    //   [SKSEED_KEY_OFFSET  .. +SKSEED_KEY_WORDS-1] skey_seed  (lambda bits, unused by HW sign)
    //   [PKSEED_KEY_OFFSET  .. +PKSEED_KEY_WORDS-1] pkey_seed  (lambda bits, used by hash_piop + H' expansion)
    //   [WIT_OFFSET         .. +WIT_WORDS-1]        skey_encoded_solution (|wit| bits, 64-bit LE)
    //   [Y_KEY_OFFSET       .. +Y_KEY_WORDS-1]      pkey_y     ((n-k) bits, 64-bit LE)
    // Host just memcpy's the reference SK byte stream into the key BRAM at offset 0.
    parameter int SKSEED_KEY_OFFSET  = 0;
    parameter int SKSEED_KEY_WORDS   = LAMBDA_DIV_64;
    parameter int PKSEED_KEY_OFFSET  = SKSEED_KEY_OFFSET + SKSEED_KEY_WORDS;    // = LAMBDA_DIV_64
    parameter int PKSEED_KEY_WORDS   = LAMBDA_DIV_64;
    parameter int WIT_OFFSET         = PKSEED_KEY_OFFSET + PKSEED_KEY_WORDS;    // = 2*LAMBDA_DIV_64
    parameter int WIT_WORDS          = (WIT_SIZE + 63) / 64;
    parameter int Y_KEY_OFFSET       = WIT_OFFSET + WIT_WORDS;
    parameter int Y_KEY_WORDS        = (N_MINUS_K_RSD + 63) / 64;

    // =========================================================================
    // 10. Variable memory sizing
    //     var_bram uses 32-bit mem_dual primitives, combined into 64-bit logical
    //     words for SEC3/5. SEC1 keeps 32-bit ports and reads/writes two halves
    //     simultaneously (CAN_DUAL=0 path).
    //       SEC1:       1 BRAM  (1 mem_dual @ 32-bit, 1024 x 32 -> 512 x 64)
    //       SEC3:       2 BRAMs (1 dual pair, 1024 x 64)
    //       SEC5 SHORT: 4 BRAMs (2 dual pairs, 2048 x 64)
    //       SEC5 FAST:  3 BRAMs (1 dual pair + 1 single, 1536 x 64)
    // =========================================================================
    parameter int VAR_DATA_WIDTH_COMBINED =
        (HALF_POLY == 0 && SECURITY_LEVEL == 1) ? 32 : 64;
    parameter int VAR_NUM_BRAMS_COMBINED  =
        (HALF_POLY == 0) ?
            ((SECURITY_LEVEL == 1)                                  ? 1 :
             (SECURITY_LEVEL == 3)                                  ? 2 :
             (SECURITY_LEVEL == 5 && PARAMETER_SET == PARAMS_FAST)  ? 3 : 4)
        :
            ((SECURITY_LEVEL == 1)                                  ? 2 :
             (SECURITY_LEVEL == 3)                                  ? 3 :
             (SECURITY_LEVEL == 5 && PARAMETER_SET == PARAMS_FAST)  ? 5 : 5);
    // For CAN_DUAL=0 (32-bit, SEC1): compute max logical 64-bit address
    // to detect whether alpha+haux overflow the physical BRAM capacity.
    parameter int VAR_MAX_LOGICAL_ADDR =
        R_ACC_PARTS + KAPPA * (R_ACC_PARTS + 1)
        + ALPHA_COL_BITS * ((TAU * KAPPA + 63) / 64) + 2 * LAMBDA_DIV_64;
    parameter int VAR_HAS_OVERFLOW        = (VAR_DATA_WIDTH_COMBINED == 32 &&
                                             VAR_MAX_LOGICAL_ADDR > BRAM_TDP_DEPTH_32 / 2) ? 1 : 0;
    // VAR_MEM_DEPTH stays at the BRAM physical capacity. The overflow
    // region lives ABOVE this in a separate RAMB18; only VAR_ADDR_WIDTH
    // is widened (by 1 bit) so phys_a/phys_b don't truncate overflow addresses.
    parameter int VAR_MEM_DEPTH_COMBINED  =
        (VAR_DATA_WIDTH_COMBINED == 32) ? BRAM_TDP_DEPTH_32 :
        (VAR_NUM_BRAMS_COMBINED % 2 == 1) ?
            (VAR_NUM_BRAMS_COMBINED / 2) * BRAM_TDP_DEPTH_32 + BRAM_TDP_DEPTH_32 / 2 :
            (VAR_NUM_BRAMS_COMBINED / 2) * BRAM_TDP_DEPTH_32;
    parameter int VAR_ADDR_WIDTH_COMBINED =
        VAR_HAS_OVERFLOW ? ($clog2(VAR_MEM_DEPTH_COMBINED) + 1) : $clog2(VAR_MEM_DEPTH_COMBINED);
    parameter int CAN_DUAL_COMBINED       = (VAR_DATA_WIDTH_COMBINED >= 64) ? 1 : 0;

    // =========================================================================
    // 11. Signature memory layout (all offsets in 64-bit words)
    //     Matches C map_signature() ordering:
    //       salt | sibling_path | leaf_cmt | u (aux) |
    //       alpha_plain (cchk_u) | dwit | P_alpha | h_piop | pow_ctr
    //     Fields are word-aligned (may exceed byte-packed SIG_SIZE/64).
    // =========================================================================
    // 1. global_salt
    parameter int SALT_SIG_OFFSET   = 0;
    parameter int SALT_SIG_WORDS    = LAMBDA_DIV_64;
    // 2. ggm_sibling_path (written by blc_open_rand_eval)
    parameter int SIG_SIB_OFFSET    = SALT_SIG_OFFSET + SALT_SIG_WORDS;
    parameter int SIG_SIB_WORDS     = (T_OPEN * LAMBDA / 8 + 7) / 8;
    // 3. ggm_hidden_leaf_cmt (written by blc_open_rand_eval)
    parameter int SIG_CMT_OFFSET    = SIG_SIB_OFFSET + SIG_SIB_WORDS;
    parameter int SIG_CMT_WORDS     = TAU * 2 * LAMBDA_DIV_64;
    // 4. u[1..tau-1] - correlation values (aux) for repetitions e=1..tau-1
    parameter int AUX_OFFSET        = SIG_CMT_OFFSET + SIG_CMT_WORDS;
    parameter int AUX_SIZE          = (TAU - 1) * R_ACC_PARTS;
    // 5. alpha_plain - consistency check plain bits (cchk_u, written by blc_commit_hlines)
    parameter int SIG_CCHK_U_OFFSET = AUX_OFFSET + AUX_SIZE;
    parameter int SIG_CCHK_U_WORDS  = (NUM_CCHK_PAIRS / 8 + 7) / 8;
    // 6. dwit - delta witness = wit XOR u_wit (circuit_in_pub)
    parameter int DWIT_SIG_OFFSET   = SIG_CCHK_U_OFFSET + SIG_CCHK_U_WORDS;
    parameter int DWIT_SIG_WORDS    = ((WIT_SIZE + 7) / 8 + 7) / 8;
    // 7. P_alpha - proof polynomial coefficients, d elements of GF(2^lambda)
    parameter int PALPHA_SIG_OFFSET     = DWIT_SIG_OFFSET + DWIT_SIG_WORDS;
    parameter int PALPHA_SIG_WORDS      = DEGREE * LAMBDA_DIV_64;
    // 8. h_piop - PIOP Fiat-Shamir challenge hash
    parameter int H_PIOP_SIG_OFFSET = PALPHA_SIG_OFFSET + PALPHA_SIG_WORDS;
    parameter int H_PIOP_SIG_SIZE   = 2 * LAMBDA_DIV_64;
    // 9. proofow_ctr_reveal (written by blc_open_rand_eval)
    parameter int SIG_POW_OFFSET    = H_PIOP_SIG_OFFSET + H_PIOP_SIG_SIZE;
    parameter int SIG_POW_WORDS     = 1;

    parameter int SIG_MEM_WORDS     = SIG_POW_OFFSET + SIG_POW_WORDS;
    parameter int SIG_ADDR_WIDTH    = $clog2(SIG_MEM_WORDS);

    // Byte-packed signature size (NIST reference - for documentation)
    parameter int SIG_SIZE = 8 * (
        (SECURITY_LEVEL == 1 && PARAMETER_SET == PARAMS_SHORT) ?  3705 :
        (SECURITY_LEVEL == 1 && PARAMETER_SET == PARAMS_FAST ) ?  4484 :
        (SECURITY_LEVEL == 3 && PARAMETER_SET == PARAMS_SHORT) ?  7964 :
        (SECURITY_LEVEL == 3 && PARAMETER_SET == PARAMS_FAST ) ?  9916 :
        (SECURITY_LEVEL == 5 && PARAMETER_SET == PARAMS_SHORT) ? 14121 :
        (SECURITY_LEVEL == 5 && PARAMETER_SET == PARAMS_FAST ) ? 17540 : 0);

    // =========================================================================
    // 12. Variable memory layout (sign pipeline)
    //     Word offsets into the dual-port var BRAM. Regions overlap in time:
    //     hcom writes are later overwritten by alpha_base, etc.
    //
    //     Commit stages:
    //     [0 .. R_ACC_PARTS-1]         r_acc (u for e=0, accumulated r for e>=1)
    //     [RBASE_OFFSET  .. ]          r_base columns (kappa or kappa-1 in var)
    //     [HCOM_VAR_OFFSET .. ]        hcom, later overwritten by alpha_base
    //     [HAUX_VAR_OFFSET .. ]        haux (only when USE_CACHE_OVERFLOW == 0)
    //     P_alpha is stored directly in sig memory at PALPHA_SIG_OFFSET.
    //
    //     PIOP stage (reuses commit region - runs later):
    //     [0              .. CW-1]     r_acc accumulator (CW = CHUNK_WORDS)
    //     [PWIT_V_OFFSET  .. ]         V matrix [e][col][word]
    // =========================================================================

    // Commit stage layout - r_base, hcom/alpha_base, haux
    //   haux is always placed after alpha_base. When VAR_HAS_OVERFLOW (SEC1 SHORT
    //   HP=0), haux and the last alpha rows spill into the RAMB18 overflow bank;
    //   the var_stall mechanism handles the serialized access transparently.
    parameter int HAUX_SIZE            = 2 * LAMBDA_DIV_64;
    parameter int RBASE_OFFSET    = R_ACC_PARTS;
    parameter int RBASE_SIZE      = KAPPA * R_ACC_PARTS;
    parameter int HCOM_VAR_OFFSET = RBASE_OFFSET + KAPPA * (R_ACC_PARTS + 1);
    parameter int HAUX_VAR_OFFSET = HCOM_VAR_OFFSET
                                  + ALPHA_COL_BITS * ((TAU * KAPPA + 63) / 64);

    // Precomputed rbase shadow copies (HALF_POLY=1 only): phase12 stores rbase
    //   for e=1..NUM_PRECOMP_E in spare var BRAM above haux; hlines skips
    //   gen_rbase for those e. process_rbase reads shadows single-column only
    //   (both ports could land in the upper single-BRAM region on odd configs).
    parameter int SHADOW_RBASE_BASE    = HAUX_VAR_OFFSET + HAUX_SIZE;
    parameter int RBASE_SHADOW_STRIDE  = KAPPA * (R_ACC_PARTS + 1);
    parameter int SHADOW_RBASE_SPARE   =
        (VAR_MEM_DEPTH_COMBINED > SHADOW_RBASE_BASE) ?
        (VAR_MEM_DEPTH_COMBINED - SHADOW_RBASE_BASE) : 0;
    parameter int NUM_PRECOMP_E        =
        (HALF_POLY == 0 || SHADOW_RBASE_SPARE <= 0) ? 0 :
        ((SHADOW_RBASE_SPARE / RBASE_SHADOW_STRIDE) < (TAU - 1)) ?
         (SHADOW_RBASE_SPARE / RBASE_SHADOW_STRIDE) : (TAU - 1);

    // Mux circuit parameters
    parameter int MUX_INPUTS       = (MU1-1) + (MU2-1) + (MU3-1) + (MU4-1);

    // PIOP stage layout - V matrix and r_acc per chunk
    parameter int CHUNK_WORDS       = LAMBDA_DIV_64;                      // lambda/64 words per chunk
    parameter int CHUNK_MAX_I       = LAMBDA / MUX_INPUTS;
    parameter int CHUNK_BIT_SIZE    = CHUNK_MAX_I * MUX_INPUTS;           // <= LAMBDA
    parameter int NUM_PWIT_CHUNKS   = (HALF_POLY != 0)
        ? (WIT_SIZE + LAMBDA - 1) / LAMBDA
        : (W + CHUNK_MAX_I - 1) / CHUNK_MAX_I;
    parameter int LAST_CHUNK_SIZE   = WIT_SIZE - (NUM_PWIT_CHUNKS - 1)
        * ((HALF_POLY != 0) ? LAMBDA : CHUNK_BIT_SIZE);
    parameter int PWIT_RACC_OFFSET  = 0;
    parameter int PWIT_V_OFFSET     = CHUNK_WORDS;                        // past racc
    parameter int PWIT_V_WORDS      = TAU * KAPPA * CHUNK_WORDS;         // tau*kappa*(lambda/64)

    // Half-polynomial 2-pass parameters (used when HALF_POLY=1)
    parameter int HALF1_ITERS      = W / 2;
    parameter int HALF2_ITERS      = W - HALF1_ITERS;
    parameter int HALF1_BITS       = HALF1_ITERS * MUX_INPUTS;
    parameter int HALF2_BITS       = WIT_SIZE - HALF1_BITS;
    parameter int HALF_CW          = ((HALF1_BITS > HALF2_BITS ? HALF1_BITS : HALF2_BITS) + 63) / 64;
    parameter int PWIT_V_WORDS_HALF = TAU * KAPPA * HALF_CW;  // col-wise size (analysis only)

    // Row-wise V_in layout (scatter output, consumed by process_pwit)
    parameter int CW_R_HALF        = (TAU * KAPPA + 63) / 64;
    parameter int ROFF_HALF        = HALF_CW + KAPPA * HALF_CW;  // racc + rbase
    parameter int VIN_WORDS_HALF   = HALF_CW * 64 * CW_R_HALF;  // padded row-wise size

    // AES-CTR random-access parameters per pass (compile-time constants)
    parameter int PWIT_START_BIT_P0   = R_WIT_OFFSET;
    parameter int PWIT_START_BIT_P1   = R_WIT_OFFSET + HALF1_BITS;
    parameter int PWIT_FIRST_BLOCK_P0 = PWIT_START_BIT_P0 / ENC_BLOCKSIZE;
    parameter int PWIT_FIRST_BLOCK_P1 = PWIT_START_BIT_P1 / ENC_BLOCKSIZE;
    parameter int PWIT_BIT_OFFSET_P0  = PWIT_START_BIT_P0 % ENC_BLOCKSIZE;
    parameter int PWIT_BIT_OFFSET_P1  = PWIT_START_BIT_P1 % ENC_BLOCKSIZE;
    parameter int PWIT_NUM_BLOCKS_P0  = (PWIT_BIT_OFFSET_P0 + HALF1_BITS + ENC_BLOCKSIZE - 1) / ENC_BLOCKSIZE;
    parameter int PWIT_NUM_BLOCKS_P1  = (PWIT_BIT_OFFSET_P1 + HALF2_BITS + ENC_BLOCKSIZE - 1) / ENC_BLOCKSIZE;

    // Tightened PIOP scratchpad sizing - minimum var BRAM depth needed by
    // the PIOP stage when scratchpad is packed directly after the V matrix.
    // HALF_POLY=0: LJ scratch + DFS nodes overwrite the transpose scratch region;
    //   only gamma must stay beyond TRANSPOSE_END to survive GenV rewrites.
    // HALF_POLY=1: DFS_L2+ after V_in scatter output.
    parameter int PIOP_DFS_L1_WORDS   = MU2 * 2 * CHUNK_WORDS;
    parameter int PIOP_DFS_L2_WORDS   = MU3 * 3 * CHUNK_WORDS;
    parameter int PIOP_DFS_L3_WORDS   = MU4 * 4 * CHUNK_WORDS;
    parameter int PIOP_GAMMA_WORDS    = 4 * LAMBDA_DIV_64;
    parameter int PIOP_LJ_SCRATCH     = (2 * DEGREE + 2) * CHUNK_WORDS;
    parameter int PIOP_CW_R           = (TAU * KAPPA + 63) / 64;
    parameter int PIOP_ROWWISE_WORDS  = LAMBDA * PIOP_CW_R;
    parameter int PIOP_TRANSPOSE_OFF  = CHUNK_WORDS
        + ((PWIT_V_WORDS > PIOP_ROWWISE_WORDS) ? PWIT_V_WORDS : PIOP_ROWWISE_WORDS);
    parameter int PIOP_TRANSPOSE_END  = PIOP_TRANSPOSE_OFF + 64;
    parameter int PIOP_GAMMA_RAW_HP0  = PIOP_TRANSPOSE_OFF
        + PIOP_LJ_SCRATCH + PIOP_DFS_L1_WORDS + PIOP_DFS_L2_WORDS
        + PIOP_DFS_L3_WORDS;
    parameter int PIOP_GAMMA_BASE_HP0 = (PIOP_GAMMA_RAW_HP0 < PIOP_TRANSPOSE_END)
        ? PIOP_TRANSPOSE_END : PIOP_GAMMA_RAW_HP0;
    parameter int PIOP_TIGHTENED_DEPTH_HP0 = PIOP_GAMMA_BASE_HP0 + PIOP_GAMMA_WORDS;
    parameter int PIOP_TIGHTENED_DEPTH_HP1 =
        ROFF_HALF + VIN_WORDS_HALF
        + PIOP_DFS_L2_WORDS + PIOP_DFS_L3_WORDS + PIOP_GAMMA_WORDS;
    parameter int VAR_MEM_DEPTH_TIGHTENED =
        (HALF_POLY == 0) ? PIOP_TIGHTENED_DEPTH_HP0 : PIOP_TIGHTENED_DEPTH_HP1;

    // =========================================================================
    // 13. Cache BRAM layout
    //     The single-port cache BRAM stores precomputed GGM cache tree nodes:
    //       [0 .. CACHE_TREE_WORDS-1]           cache tree nodes at CACHE_TREE_DEPTH
    //     DFS siblings are stored in var_bram (scratch at address 0, overwritten
    //     by phase12).
    //     For SEC1 SHORT the cache has spare capacity. USE_CACHE_OVERFLOW=1
    //     relocates rbase[KAPPA-1] and haux into that spare region,
    //     freeing var BRAM for the PIOP V matrix.
    // =========================================================================
    parameter int USE_CACHE_OVERFLOW = 0;
    parameter int RBASE_VAR_COLS     = USE_CACHE_OVERFLOW ? (KAPPA - 1) : KAPPA;

    parameter int CACHE_TREE_WORDS   = (1 << CACHE_TREE_DEPTH) * (LAMBDA / 64);
    parameter int CACHE_RBASE_OFFSET = CACHE_TREE_WORDS;
    parameter int CACHE_HAUX_OFFSET  = CACHE_RBASE_OFFSET
                                     + (USE_CACHE_OVERFLOW ? (R_ACC_PARTS + 1) : 0);

    // DFS sibling scratch in var_bram (depths 0..GGM_TREE_DEPTH inclusive)
    parameter int VAR_SIB_WORDS      = (GGM_TREE_DEPTH + 1) * LAMBDA_DIV_64;

    // =========================================================================
    // 13b. Open-rand-eval var_bram layout (reuses var_bram after PIOP completes)
    //      Sort data at address 0, backup copy at address TAU.
    //      Maximum usage: 2*TAU words (max 64 for SEC5_FAST).
    // =========================================================================
    parameter int ORE_SORT_BASE   = 0;
    parameter int ORE_BACKUP_BASE = TAU;

    // =========================================================================
    // 14. SHAKE hash prefixes (domain separation bytes from the C reference)
    // =========================================================================
    parameter logic [7:0] HASH_BAVC_PREFIX  = 8'h01;  // hcom - leaf commitment hash
    parameter logic [7:0] HASH_AUX_PREFIX   = 8'h02;  // haux = H(0x02 || hcom || u[1..tau-1])
    parameter logic [7:0] HASH_LINES_PREFIX = 8'h03;  // h_lines - consistency check hash
    parameter logic [7:0] HASH_PIOP_PREFIX  = 8'h04;  // h_piop - PIOP Fiat-Shamir hash

    // =========================================================================
    // 15. Key memory widths (KeyGen output -> Sign input)
    // =========================================================================
    parameter int PK_BYTES =
        (SECURITY_LEVEL == 1) ?  70 :
        (SECURITY_LEVEL == 3) ?  98 : 132;
    parameter int SK_BYTES =
        (SECURITY_LEVEL == 1) ? 163 :
        (SECURITY_LEVEL == 3) ? 232 : 307;

    parameter int SK_MEM_DATA_WIDTH = 64;
    parameter int PK_MEM_DATA_WIDTH = 64;
    parameter int SK_MEM_ADDR_WIDTH = $clog2((SK_BYTES * 8) / SK_MEM_DATA_WIDTH);
    parameter int PK_MEM_ADDR_WIDTH = $clog2((PK_BYTES * 8) / PK_MEM_DATA_WIDTH);

endpackage
