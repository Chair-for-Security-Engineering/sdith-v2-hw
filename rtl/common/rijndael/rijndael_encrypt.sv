// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Niklas Höher

`timescale 1ns / 1ps

module rijndael_encrypt #(
    parameter int NB = 4,
    parameter int NK = 4,
    localparam int STATESIZE = 32 * NB,
    localparam int KEYSIZE = 32 * NK
) (
    input  logic                 clk_i,
    input  logic                 rst_ni,

    // Control signals
    input  logic                 enable_i,
    output logic                 ready_o,
    output logic                 valid_o,

    // Data signals
    input  logic [STATESIZE-1:0] plaintext_i,
    input  logic [KEYSIZE-1:0]   key_i,
    output logic [STATESIZE-1:0] ciphertext_o
);

    // ------------------------------------------------------------
    // Parameter / type definitions
    // ------------------------------------------------------------

    // Compute the required number of rounds
    localparam logic [31:0] NR = (NK > NB) ? NK + 6 : NB + 6;
    // Compute the bitwidth needed for the round counter
    localparam int ROUNDCOUNTERWIDTH = $clog2(NR);
    // Determine the last value of the round counter for comparison later on
    localparam logic[ROUNDCOUNTERWIDTH-1:0] LASTCOUNTERVALUE = NR[ROUNDCOUNTERWIDTH-1:0] - 1;

    // FSM states
    typedef enum logic [1:0] {
        STATE_IDLE,
        STATE_INIT_ADDROUNDKEY,
        STATE_ENCRYPT
    } fsm_state_e;

    // ------------------------------------------------------------
    // Encryption logic
    // ------------------------------------------------------------

    // FSM state, round counter, and signal indicating if we are in the last round
    fsm_state_e fsm_state, fsm_next_state;
    logic [ROUNDCOUNTERWIDTH-1:0] round_counter;
    logic is_last_round;

    // Internal Rijndael state
    logic [STATESIZE-1:0] rijndael_state, rijndael_next_state;

    // key schedule IO
    logic keyschedule_enable, keyschedule_rst_ni;
    logic [STATESIZE-1:0] roundkey;

    // Instantiate key schedule
    rijndael_keyschedule #(.NB (NB), .NK (NK)) keyschedule (
        .clk_i      (clk_i),
        .rst_ni     (keyschedule_rst_ni),
        .enable_i   (keyschedule_enable),
        .key_i      (key_i),
        .roundkey_o (roundkey)
    );

    // Instantiate AES round
    rijndael_round #(.NB (NB)) round (
        .is_last_i  (is_last_round),
        .state_i    (rijndael_state),
        .roundkey_i (roundkey),
        .state_o    (rijndael_next_state)
    );

    assign is_last_round = round_counter == LASTCOUNTERVALUE;
    assign ciphertext_o = rijndael_state;
    assign keyschedule_enable = (fsm_state == STATE_ENCRYPT || fsm_state == STATE_INIT_ADDROUNDKEY);
    assign keyschedule_rst_ni = (fsm_state != STATE_IDLE);

    // ------------------------------------------------------------
    // State machine
    // ------------------------------------------------------------

    // Next state logic
    always_comb begin
        case (fsm_state)
            STATE_IDLE:
                fsm_next_state = fsm_state_e'((enable_i) ? STATE_INIT_ADDROUNDKEY : STATE_IDLE);
            STATE_INIT_ADDROUNDKEY:
                fsm_next_state = fsm_state_e'(STATE_ENCRYPT);
            STATE_ENCRYPT:
                fsm_next_state = fsm_state_e'((is_last_round) ? STATE_IDLE : STATE_ENCRYPT);
            default:
                fsm_next_state = fsm_state;
        endcase
    end

    // Output logic
    always_comb begin
        case (fsm_state)
            STATE_IDLE : begin
                ready_o = 1'h1;
                valid_o = 1'h1;
            end

            default : begin
                ready_o = 1'h0;
                valid_o = 1'h0;
            end
        endcase
    end

    // Update internal FSM + Rijndael state
    always_ff @(posedge clk_i) begin
        if (!rst_ni) begin
            fsm_state <= STATE_IDLE;
            rijndael_state <= '0;
            round_counter <= '0;
        end else begin
            fsm_state <= fsm_next_state;
            if (fsm_state == STATE_IDLE && enable_i) begin
                rijndael_state <= plaintext_i;
                round_counter <= '0;
            end else if (fsm_state == STATE_INIT_ADDROUNDKEY) begin
                rijndael_state <= rijndael_state ^ roundkey;
            end else if (fsm_state == STATE_ENCRYPT) begin
                rijndael_state <= rijndael_next_state;
                round_counter <= round_counter + 1;
            end
        end
    end

endmodule
