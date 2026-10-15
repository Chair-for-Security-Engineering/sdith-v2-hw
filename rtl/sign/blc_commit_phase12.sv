// SPDX-FileCopyrightText: 2026 Stef Halmans, Niklas Höher
// SPDX-License-Identifier: LicenseRef-RUB-SecEng

import sdith_params_pkg::*;
import sdith_helpers_pkg::*;

// blc_commit_phase12
//
// BLC.Commit.Haux ("BLC phase 1-2"): the first pass of the two-pass BLC
// commit split. For each repetition e it drives the external gen_rbase
// (shared with the Hlines stage, connected via the gr_* ports):
//   e = 0:                full r_base build; r_acc[0] doubles as u.
//   e = 1..NUM_PRECOMP_E: shadow r_base build into spare scratchpad, so
//                         Hlines can skip those leaf traversals.
//   remaining e:          racc only, into the temp slot.
// After each e > 0, aux[e] = u XOR r_acc_temp is written to the signature.
// Finally h_aux = SHAKE(0x02 || h_com || aux[1..tau-1]) is computed and
// stored for the Hlines stage.
//
// Memory layout:
//   var[0 .. R_ACC_PARTS-1]             : r_acc[0] / u vector (slot 0)
//   var[RBASE_OFFSET .. ]               : r_base columns (built by gen_rbase during e=0)
//   var[HCOM_VAR_OFFSET .. ]            : hcom (DFS wrote here), racc temp for e>0
//   sig[AUX_OFFSET + (e-1)*R_ACC_PARTS ..] : aux[e] for e=1..TAU-1
//   cache[CACHE_HAUX_OFFSET ..]         : haux (when USE_CACHE_OVERFLOW)
//   cache[CACHE_RBASE_OFFSET ..]        : rbase[KAPPA-1] (when USE_CACHE_OVERFLOW)

module blc_commit_phase12 (
    input logic clk_i,
    input logic rst_i,
    input logic var_stall_i,
    input logic fsm_enable_i,

    output logic fsm_done_o,

    // Gen_rbase control (to external gen_rbase via sign.sv mux)
    output logic                                  gr_start_o,
    output logic [$clog2(TAU+1)-1:0]              gr_e_o,
    output logic [VAR_ADDR_WIDTH_COMBINED-1:0]    gr_rbase_base_o,
    output logic [BRAM_ADDR_SIZE:0]               gr_slot_offset_o,
    output logic                                  gr_build_rbase_o,
    input  logic                                  gr_done_i,

    // SHAKE (active during haux computation)
    output logic        shake_start_o,
    output logic        shake_mode_o,
    output logic        shake_seed_from_output_o,
    output logic [63:0] shake_din_o,
    output logic        shake_din_valid_o,
    output logic        shake_last_din_o,
    output logic [ 3:0] shake_last_din_byte_o,
    output logic        shake_dout_ready_o,
    input  logic        shake_din_ready_i,
    input  logic [63:0] shake_dout_i,
    input  logic        shake_dout_valid_i,

    // Signature memory (single-port, 64-bit)
    input  logic [63:0]              sig_data_i,
    output logic [63:0]              sig_data_o,
    output logic [SIG_ADDR_WIDTH-1:0] sig_addr_o,
    output logic                     sig_wr_en_o,

    // Dual-port variable memory
    input  logic [VAR_DATA_WIDTH_COMBINED-1:0] var_a_data_i,
    output logic [VAR_DATA_WIDTH_COMBINED-1:0] var_a_data_o,
    output logic [VAR_ADDR_WIDTH_COMBINED-1:0] var_a_addr_o,
    output logic                               var_a_wr_en_o,

    input  logic [VAR_DATA_WIDTH_COMBINED-1:0] var_b_data_i,
    output logic [VAR_DATA_WIDTH_COMBINED-1:0] var_b_data_o,
    output logic [VAR_ADDR_WIDTH_COMBINED-1:0] var_b_addr_o,
    output logic                               var_b_wr_en_o,

    // Cache BRAM (for rbase[KAPPA-1] and haux when USE_CACHE_OVERFLOW)
    input  logic [63:0]             cache_data_i,
    output logic [63:0]             cache_data_o,
    output logic [CACHE_ADDR_WIDTH-1:0] cache_addr_o,
    output logic                    cache_wr_en_o,
    // Cache active: haux squeeze only (gen_rbase cache writes handled externally)
    output logic                    cache_active_o
);
  // Local parameters

  localparam CAN_DUAL = CAN_DUAL_COMBINED;

  localparam HCOM_WORDS = 2 * LAMBDA_DIV_64;
  localparam HAUX_SQUEEZE_WORDS = 2 * LAMBDA_DIV_64;
  // Combine dual-port var read data into a 64-bit logical word
  // (bswap64, phys_a, phys_b, split_a, split_b come from sdith_helpers_pkg)
  function automatic [63:0] combine_ab;
    if (CAN_DUAL) return 64'(var_a_data_i);
    else          return {var_b_data_i, var_a_data_i};
  endfunction

  // Whether to write rbase[KAPPA-1] and haux to cache BRAM
  localparam USE_CACHE = USE_CACHE_OVERFLOW;

  // Precomp count
  localparam PRECOMP = NUM_PRECOMP_E;

  // Slot offset for racc temp
  localparam RACC_TEMP_OFFSET = HCOM_VAR_OFFSET + HCOM_WORDS;

  // State definition

  typedef enum logic [3:0] {
    S_IDLE,
    S_WAIT_GR,       // wait for external gen_rbase to complete
    S_AUX_RD,
    S_AUX_RD2,       // CAN_DUAL=0 only: read slot 1
    S_AUX_WR,
    S_NEXT_E,
    // haux computation states
    S_HAUX_START,
    S_HAUX_HCOM,
    S_HAUX_HCOM_PRIME,
    S_HAUX_AUX_PRIME,
    S_HAUX_AUX_FEED,
    S_HAUX_DRAIN,     // emit remaining pack_buf bytes as last SHAKE word
    S_HAUX_SQUEEZE,
    S_DONE
  } fsm_state_t;

  fsm_state_t state, next_state;
  // Loop counters

  localparam E_WIDTH = $clog2(TAU + 1);
  logic [E_WIDTH-1:0] e, next_e;
  logic [$clog2(R_ACC_PARTS):0] aux_w, next_aux_w;

  // Running accumulators to avoid multiplies (eliminates DSP inference)
  // sig_aux_base = AUX_OFFSET + (e-1)*R_ACC_PARTS (incremented by R_ACC_PARTS per e)
  logic [SIG_ADDR_WIDTH-1:0] sig_aux_base, next_sig_aux_base;
  // Aux latch (CAN_DUAL=0: need to store r_acc[0] word)

  logic [63:0] aux_r0, next_aux_r0;
  // haux registers

  // hash_w: word counter, sized for max(HCOM_WORDS, R_ACC_PARTS)
  localparam HASH_W_MAX = (HCOM_WORDS > R_ACC_PARTS) ? HCOM_WORDS : R_ACC_PARTS;
  logic [$clog2(HASH_W_MAX+1)-1:0] hash_w, next_hash_w;
  logic [$clog2(HAUX_SQUEEZE_WORDS+1)-1:0] squeeze_w, next_squeeze_w;

  // Packing buffer for haux SHAKE feeding.
  // Accumulates bytes MSB-first; emits 8-byte SHAKE words from the top.
  // Max pending: 7 bytes (56 bits).
  logic [55:0] pack_buf, next_pack_buf;
  logic [3:0]  pack_cnt, next_pack_cnt;  // 0..7
  // Var memory: always output int_var_* (gen_rbase owns memory externally)

  logic [63:0]             int_var_a_data, int_var_b_data;
  logic [VAR_ADDR_WIDTH_COMBINED-1:0] int_var_a_addr, int_var_b_addr;
  logic                    int_var_a_wr, int_var_b_wr;

  assign var_a_data_o  = split_a(int_var_a_data);
  assign var_a_addr_o  = phys_a(int_var_a_addr);
  assign var_a_wr_en_o = int_var_a_wr;
  assign var_b_data_o  = split_b(int_var_b_data);
  assign var_b_addr_o  = phys_b(int_var_b_addr);
  assign var_b_wr_en_o = int_var_b_wr;
  // FSM

  always_comb begin
    next_state     = state;
    next_e         = e;
    next_aux_w     = aux_w;
    next_sig_aux_base = sig_aux_base;
    next_aux_r0    = aux_r0;
    next_hash_w    = hash_w;
    next_squeeze_w = squeeze_w;
    next_pack_buf       = pack_buf;
    next_pack_cnt       = pack_cnt;

    fsm_done_o      = 1'b0;

    // Gen_rbase defaults
    gr_start_o       = 1'b0;
    gr_e_o           = '0;
    gr_rbase_base_o  = '0;
    gr_slot_offset_o = '0;
    gr_build_rbase_o = 1'b0;

    // SHAKE defaults
    shake_start_o            = 1'b0;
    shake_mode_o             = 1'b0;   // hash mode
    shake_seed_from_output_o = 1'b0;
    shake_din_o              = 64'b0;
    shake_din_valid_o        = 1'b0;
    shake_last_din_o         = 1'b0;
    shake_last_din_byte_o    = 4'd0;
    shake_dout_ready_o       = 1'b0;

    // Sig memory defaults
    sig_data_o  = 64'b0;
    sig_addr_o  = '0;
    sig_wr_en_o = 1'b0;

    // Var memory defaults
    int_var_a_data = 64'b0;
    int_var_a_addr = '0;
    int_var_a_wr   = 1'b0;
    int_var_b_data = 64'b0;
    int_var_b_addr = '0;
    int_var_b_wr   = 1'b0;

    // Cache BRAM defaults
    cache_data_o  = 64'b0;
    cache_addr_o  = '0;
    cache_wr_en_o = 1'b0;
    cache_active_o = (state == S_HAUX_SQUEEZE);

    case (state)

      // ========================================================
      S_IDLE: begin
        if (fsm_enable_i) begin
          next_e = '0;
          next_sig_aux_base = (SIG_ADDR_WIDTH)'(AUX_OFFSET);
          // Fire gen_rbase for e=0: full rbase build
          gr_start_o       = 1'b1;
          gr_e_o           = '0;
          gr_rbase_base_o  = VAR_ADDR_WIDTH_COMBINED'(RBASE_OFFSET);
          gr_slot_offset_o = '0;
          gr_build_rbase_o = 1'b1;
          next_state = S_WAIT_GR;
        end
      end

      // ========================================================
      // Wait for external gen_rbase to complete
      // ========================================================
      S_WAIT_GR: begin
        if (gr_done_i) begin
          if (e == 0)
            next_state = S_NEXT_E;
          else begin
            // e>0: extract aux = slot0 XOR racc_temp
            next_aux_w = '0;
            next_state = S_AUX_RD;
          end
        end
      end

      // ========================================================
      // Aux extraction: read r_acc[0] and r_acc[e] (at RACC_TEMP_OFFSET)
      // ========================================================
      S_AUX_RD: begin
        if (CAN_DUAL) begin
          int_var_a_addr = VAR_ADDR_WIDTH_COMBINED'(aux_w);
          int_var_b_addr = VAR_ADDR_WIDTH_COMBINED'(RACC_TEMP_OFFSET + aux_w);
          next_state = S_AUX_WR;
        end else begin
          int_var_a_addr = VAR_ADDR_WIDTH_COMBINED'(aux_w);
          int_var_b_addr = VAR_ADDR_WIDTH_COMBINED'(aux_w);
          next_state = S_AUX_RD2;
        end
      end

      // CAN_DUAL=0 only: latch r_acc[0], read racc_temp at RACC_TEMP_OFFSET
      S_AUX_RD2: begin
        next_aux_r0    = combine_ab();
        int_var_a_addr = VAR_ADDR_WIDTH_COMBINED'(RACC_TEMP_OFFSET + aux_w);
        int_var_b_addr = VAR_ADDR_WIDTH_COMBINED'(RACC_TEMP_OFFSET + aux_w);
        next_state     = S_AUX_WR;
      end

      // Write aux[e] word to sig memory
      S_AUX_WR: begin
        if (CAN_DUAL) begin
          sig_data_o = 64'(var_a_data_i) ^ 64'(var_b_data_i);
        end else begin
          sig_data_o = aux_r0 ^ combine_ab();
        end

        sig_addr_o  = sig_aux_base + (SIG_ADDR_WIDTH)'(aux_w);
        sig_wr_en_o = 1'b1;

        if (aux_w == ($clog2(R_ACC_PARTS)+1)'(R_ACC_PARTS - 1)) begin
          next_sig_aux_base = sig_aux_base + (SIG_ADDR_WIDTH)'(R_ACC_PARTS);
          next_state = S_NEXT_E;
        end else begin
          next_aux_w = aux_w + 1;
          next_state = S_AUX_RD;
        end
      end

      // ========================================================
      // Advance to next e
      // ========================================================
      S_NEXT_E: begin
        if (e == E_WIDTH'(TAU - 1)) begin
          next_state = S_HAUX_START;
        end else begin
          next_e = e + 1;
          // e=0: base stays at AUX_OFFSET
          // Fire gen_rbase for next e
          gr_start_o = 1'b1;
          gr_e_o     = e + 1;
          if (PRECOMP > 0 && (e + 1) <= E_WIDTH'(PRECOMP)) begin
            // Precomputed: build shadow rbase
            gr_rbase_base_o  = VAR_ADDR_WIDTH_COMBINED'(
                SHADOW_RBASE_BASE + e * RBASE_SHADOW_STRIDE);
            gr_slot_offset_o = (BRAM_ADDR_SIZE+1)'(RACC_TEMP_OFFSET);
            gr_build_rbase_o = 1'b1;
          end else begin
            // Non-precomputed: racc only
            gr_rbase_base_o  = '0;
            gr_slot_offset_o = (BRAM_ADDR_SIZE+1)'(RACC_TEMP_OFFSET);
            gr_build_rbase_o = 1'b0;
          end
          next_state = S_WAIT_GR;
        end
      end

      // ========================================================
      // HAUX: Start SHAKE, load prefix byte into packing buffer
      // C reference: SHAKE(0x02 || hash_com || corr_u)
      // ========================================================
      S_HAUX_START: begin
        shake_start_o        = 1'b1;
        next_hash_w          = '0;
        next_e               = E_WIDTH'(1);
        next_sig_aux_base    = (SIG_ADDR_WIDTH)'(AUX_OFFSET);  // e=1 -> (1-1)*R_ACC_PARTS = 0
        next_pack_cnt        = 4'd1;
        next_pack_buf        = {HASH_AUX_PREFIX, 48'd0};  // prefix byte at MSB
        // Prime var BRAM read for first hcom word
        int_var_a_addr = VAR_ADDR_WIDTH_COMBINED'(HCOM_VAR_OFFSET);
        int_var_b_addr = VAR_ADDR_WIDTH_COMBINED'(HCOM_VAR_OFFSET);
        next_state           = S_HAUX_HCOM;
      end

      // ========================================================
      // HAUX: Load hcom word from var BRAM into packing buffer
      // One hcom word per visit; after all HCOM_WORDS -> AUX_PRIME
      // ========================================================
      S_HAUX_HCOM: begin
        // Keep var BRAM address stable for stall tolerance
        int_var_a_addr = VAR_ADDR_WIDTH_COMBINED'(HCOM_VAR_OFFSET + hash_w);
        int_var_b_addr = VAR_ADDR_WIDTH_COMBINED'(HCOM_VAR_OFFSET + hash_w);
        begin
          logic [63:0]  hcom_word;
          logic [119:0] combined;
          logic [3:0]   total;

          hcom_word = combine_ab();

          // Pack: {existing pending bytes, new 8 hcom bytes, zero pad}
          case (pack_cnt)
            0: combined = {hcom_word, 56'd0};
            1: combined = {pack_buf[55:48], hcom_word, 48'd0};
            2: combined = {pack_buf[55:40], hcom_word, 40'd0};
            3: combined = {pack_buf[55:32], hcom_word, 32'd0};
            4: combined = {pack_buf[55:24], hcom_word, 24'd0};
            5: combined = {pack_buf[55:16], hcom_word, 16'd0};
            6: combined = {pack_buf[55:8],  hcom_word,  8'd0};
            7: combined = {pack_buf[55:0],  hcom_word       };
            default: combined = {hcom_word, 56'd0};
          endcase
          total = pack_cnt + 4'd8;

          shake_din_o       = combined[119:56];
          shake_din_valid_o = 1'b1;

          if (shake_din_ready_i) begin
            next_pack_buf = combined[55:0];
            next_pack_cnt = total - 4'd8;

            if (hash_w == ($clog2(HCOM_WORDS+1))'(HCOM_WORDS - 1)) begin
              next_hash_w = '0;
              next_state  = S_HAUX_AUX_PRIME;
            end else begin
              next_hash_w = hash_w + 1;
              next_state  = S_HAUX_HCOM_PRIME;
            end
          end
        end
      end

      // ========================================================
      // HAUX: Prime var BRAM for next hcom word (1-cycle latency)
      // ========================================================
      S_HAUX_HCOM_PRIME: begin
        int_var_a_addr = VAR_ADDR_WIDTH_COMBINED'(HCOM_VAR_OFFSET + hash_w);
        int_var_b_addr = VAR_ADDR_WIDTH_COMBINED'(HCOM_VAR_OFFSET + hash_w);
        next_state = S_HAUX_HCOM;
      end

      // ========================================================
      // HAUX: Prime sig memory read (1-cycle BRAM latency).
      // Used before every aux word; no prefetching.
      // ========================================================
      S_HAUX_AUX_PRIME: begin
        sig_addr_o = sig_aux_base + (SIG_ADDR_WIDTH)'(hash_w);
        next_state = S_HAUX_AUX_FEED;
      end

      // ========================================================
      // HAUX: Load bswapped sig word into packing buffer, emit if full
      // After load, go back to AUX_PRIME for next word.
      // Last word of each entry: only load valid bytes (skip padding).
      // ========================================================
      S_HAUX_AUX_FEED: begin
        begin
          logic [63:0]  new_data;
          logic [3:0]   new_bytes;
          logic         is_last_word;
          logic [119:0] combined;
          logic [3:0]   total;

          new_data     = bswap64(sig_data_i);
          is_last_word = (hash_w == ($clog2(R_ACC_PARTS)+1)'(R_ACC_PARTS - 1));
          new_bytes    = is_last_word ?
                         ((R_ACC_SIZE_BYTES % 8 == 0) ? 4'd8 : 4'(R_ACC_SIZE_BYTES % 8))
                         : 4'd8;

          // Pack new data after existing pending bytes
          case (pack_cnt)
            0: combined = {new_data, 56'd0};
            1: combined = {pack_buf[55:48], new_data, 48'd0};
            2: combined = {pack_buf[55:40], new_data, 40'd0};
            3: combined = {pack_buf[55:32], new_data, 32'd0};
            4: combined = {pack_buf[55:24], new_data, 24'd0};
            5: combined = {pack_buf[55:16], new_data, 16'd0};
            6: combined = {pack_buf[55:8],  new_data,  8'd0};
            7: combined = {pack_buf[55:0],  new_data       };
            default: combined = {new_data, 56'd0};
          endcase
          total = pack_cnt + new_bytes;

          if (total >= 4'd8) begin
            // Emit top 8 bytes to SHAKE
            shake_din_o       = combined[119:56];
            shake_din_valid_o = 1'b1;

            // Final word of final entry and no leftover?
            if (is_last_word && e == TAU - 1 && total == 4'd8) begin
              shake_last_din_o      = 1'b1;
              shake_last_din_byte_o = 4'd8;
            end

            if (shake_din_ready_i) begin
              next_pack_buf = combined[55:0];
              next_pack_cnt = total - 4'd8;

              // Advance to next word or next entry
              if (is_last_word) begin
                next_hash_w = '0;
                if (e == TAU - 1) begin
                  if ((total - 4'd8) > 4'd0)
                    next_state = S_HAUX_DRAIN;
                  else begin
                    next_squeeze_w = '0;
                    next_state     = S_HAUX_SQUEEZE;
                  end
                end else begin
                  next_e     = e + 1;
                  next_sig_aux_base = sig_aux_base + (SIG_ADDR_WIDTH)'(R_ACC_PARTS);
                  next_state = S_HAUX_AUX_PRIME;
                end
              end else begin
                next_hash_w = hash_w + 1;
                next_state  = S_HAUX_AUX_PRIME;  // prime next word
              end
            end
            // SHAKE not ready: stall in AUX_FEED (sig_data_i is stable,
            // not prefetching, so data won't change)
          end else begin
            // total < 8: accumulate without emitting, advance to next word
            next_pack_buf = combined[119:64];
            next_pack_cnt = total;

            if (is_last_word) begin
              next_hash_w = '0;
              if (e == TAU - 1) begin
                next_state = S_HAUX_DRAIN;
              end else begin
                next_e     = e + 1;
                next_sig_aux_base = sig_aux_base + (SIG_ADDR_WIDTH)'(R_ACC_PARTS);
                next_state = S_HAUX_AUX_PRIME;
              end
            end else begin
              next_hash_w = hash_w + 1;
              next_state  = S_HAUX_AUX_PRIME;
            end
          end
        end
      end

      // ========================================================
      // HAUX: Drain remaining bytes as last SHAKE word
      // ========================================================
      S_HAUX_DRAIN: begin
        if (pack_cnt > 4'd0) begin
          shake_din_o           = {pack_buf, 8'd0};
          shake_din_valid_o     = 1'b1;
          shake_last_din_o      = 1'b1;
          shake_last_din_byte_o = pack_cnt;
          if (shake_din_ready_i) begin
            next_pack_cnt  = '0;
            next_squeeze_w = '0;
            next_state     = S_HAUX_SQUEEZE;
          end
        end else begin
          next_squeeze_w = '0;
          next_state     = S_HAUX_SQUEEZE;
        end
      end

      // ========================================================
      // HAUX: Squeeze haux from SHAKE -> write to cache or var BRAM
      // ========================================================
      S_HAUX_SQUEEZE: begin
        shake_dout_ready_o = 1'b1;

        if (shake_dout_valid_i) begin
          if (USE_CACHE) begin
            // Write haux word to cache BRAM at CACHE_HAUX_OFFSET
            cache_addr_o  = (CACHE_ADDR_WIDTH)'(CACHE_HAUX_OFFSET + squeeze_w);
            cache_data_o  = shake_dout_i;
            cache_wr_en_o = 1'b1;
          end else begin
            // Write haux word to var BRAM at HAUX_VAR_OFFSET
            int_var_a_data = shake_dout_i;
            int_var_a_addr = VAR_ADDR_WIDTH_COMBINED'(HAUX_VAR_OFFSET + squeeze_w);
            int_var_a_wr   = 1'b1;
            int_var_b_data = shake_dout_i;
            int_var_b_addr = VAR_ADDR_WIDTH_COMBINED'(HAUX_VAR_OFFSET + squeeze_w);
            int_var_b_wr   = CAN_DUAL ? 1'b0 : 1'b1;
          end

          if (squeeze_w == ($clog2(HAUX_SQUEEZE_WORDS+1))'(HAUX_SQUEEZE_WORDS - 1)) begin
            next_state = S_DONE;
          end else begin
            next_squeeze_w = squeeze_w + 1;
          end
        end
      end

      // ========================================================
      S_DONE: begin
        fsm_done_o = 1'b1;
      end

    endcase
  end
  // Sequential

  always_ff @(posedge clk_i or posedge rst_i) begin
    if (rst_i) begin
      state          <= S_IDLE;
      e              <= '0;
      aux_w          <= '0;
      aux_r0         <= '0;
      hash_w         <= '0;
      squeeze_w      <= '0;
      pack_buf       <= '0;
      pack_cnt       <= '0;
      sig_aux_base   <= '0;
    end else if (!var_stall_i) begin
      state          <= next_state;
      e              <= next_e;
      aux_w          <= next_aux_w;
      sig_aux_base   <= next_sig_aux_base;
      aux_r0         <= next_aux_r0;
      hash_w         <= next_hash_w;
      squeeze_w      <= next_squeeze_w;
      pack_buf        <= next_pack_buf;
      pack_cnt        <= next_pack_cnt;
    end
  end

endmodule
