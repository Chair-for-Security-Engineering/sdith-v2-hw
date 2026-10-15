// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Niklas Höher

`timescale 1ns / 1ps

module rijndael_keyschedule #(
    parameter int NB = 4,
    parameter int NK = 4,
    localparam int STATESIZE = 32 * NB,
    localparam int KEYSIZE = 32 * NK
) (
    input  logic                 clk_i,
    input  logic                 rst_ni,
    input  logic                 enable_i,
    input  logic [KEYSIZE-1:0]   key_i,
    output logic [STATESIZE-1:0] roundkey_o
);

    // ------------------------------------------------------------
    // Parameter definitions
    // ------------------------------------------------------------

    /**
     * Compute the number of key schedule steps that need to be performed during
     * each update to ensure that enough new words are expanded so that a new
     * round key can be supplied in each iteration.
     */
    localparam int NUMSTEPS = (NB + NK - 1) / NK;

    // Compute the size of the internal key state
    localparam int KEYSTATESIZE = NUMSTEPS * KEYSIZE;

    /**
     * This parameter contains the number of different cases that must be handled
     * when extracting the round key from the current (and next) key state for
     * every different combination of NB and NK.
     */
    localparam int NUMKEYVARIATIONS =
        (NB == NK || NB == 2 * NK) ? 1 :
        (NB == 4 && NK == 6) ? 3 :
        (NB == 6 && NK == 8) ? 4 :
        (NB == 6 && NK == 4) ? 4 :
        (NB == 8 && NK == 6) ? 3 :
        (NK == 2 * NB) ? 2 : 0;

    // Bitwidth of the register used to store the current state
    localparam int FSMSTATEWIDTH = $clog2(NUMKEYVARIATIONS);

    // ------------------------------------------------------------
    // Key schedule logic
    // ------------------------------------------------------------

    // Signals for storing the current and next internal keystate
    logic [KEYSTATESIZE-1:0] initial_keystate, keystate, next_keystate;

    // Signals for storing current and next round constants for each step instance
    logic [7:0] initial_rc [NUMSTEPS];
    logic [7:0] rc [NUMSTEPS];
    logic [7:0] next_rc [NUMSTEPS];

    // Signal that determines whether a key schedule step needs to be performed
    logic update_state;

    // Logic to compute the next round constant
    // => Declared as automatic because Synopsys DC does not like static
    function automatic [7:0] mul2(input logic [7:0] x);
        return {x[6:0], 1'b0} ^ (x[7] * 8'h1b);
    endfunction

    // Instantiate step instances
    rijndael_keyschedulestep #(.NK (NK)) keyschedulestep0 (
        .keystate_i      (keystate[KEYSIZE-1:0]),
        .rc_i            (rc[0]),
        .next_keystate_o (next_keystate[KEYSTATESIZE-1 -: KEYSIZE])
    );

    generate
        if (NUMSTEPS == 2) begin : gen_two_keyschedulesteps
            logic [KEYSIZE-1:0] keyschedulestep1_state_i;
            logic [7:0] keyschedulestep1_rc_i;

            assign keyschedulestep1_state_i = (!rst_ni) ? key_i : next_keystate[KEYSTATESIZE-1 -: KEYSIZE];
            assign keyschedulestep1_rc_i = (!rst_ni) ? 'h01 : rc[1];

            rijndael_keyschedulestep #(.NK (NK)) keyschedulestep1 (
                .keystate_i      (keyschedulestep1_state_i),
                .rc_i            (keyschedulestep1_rc_i),
                .next_keystate_o (next_keystate[KEYSIZE-1:0])
            );

            // If the internal key schedule state consists of 2 * 32 * NK bits, we also need
            // to perform one key schedule step as part of the initialization procedure.
            assign initial_keystate = {key_i, next_keystate[KEYSIZE-1:0]};
            assign initial_rc[0] = 8'h2;
            assign initial_rc[1] = 8'h4;
            // Since we perform two steps per update, we have to increment the RCs twice
            assign next_rc[0] = mul2(mul2(rc[0]));
            assign next_rc[1] = mul2(mul2(rc[1]));
        end else begin : gen_one_keyschedulestep
            assign initial_keystate = key_i;
            assign initial_rc[0] = 8'h1;
            assign next_rc[0] = mul2(rc[0]);
        end
    endgenerate

    // Logic to select the next round key
    generate
        if (NUMKEYVARIATIONS > 1) begin : gen_different_key_variations
            // Shorthand naming of these parameters to increase readability
            localparam int X = STATESIZE;
            localparam int Y = KEYSTATESIZE;

            // Signal for storing the current FSM state
            logic [FSMSTATEWIDTH-1:0] key_variation_state;

            // Define when the internal key state needs to be updated
            assign update_state = (key_variation_state != 0);

            // Update key variation state every time a new round key is generated
            always_ff @(posedge clk_i) begin
                if (!rst_ni) begin
                    key_variation_state <= 0;
                end else if (enable_i) begin
                    key_variation_state <=
                        (key_variation_state == NUMKEYVARIATIONS-1) ? 0 : (key_variation_state+1);
                end
            end

            // Determine roundkey_o and update_state depending on the current key variation state
            if (NUMKEYVARIATIONS == 2) begin : gen_2_key_variations
                always_comb begin
                    case (key_variation_state)
                        1'b0   : roundkey_o = keystate[Y-1:X];
                        1'b1   : roundkey_o = keystate[X-1:0];
                        default: roundkey_o = 'h0;
                    endcase
                end
            end else if (NUMKEYVARIATIONS == 3) begin : gen_3_key_variations
                always_comb begin
                    case (key_variation_state)
                        2'b00  : roundkey_o = keystate[Y-1:Y-X];
                        2'b01  : roundkey_o = {keystate[Y-X-1:0], next_keystate[Y-1:X]};
                        2'b10  : roundkey_o = keystate[X-1:0];
                        default: roundkey_o = 'h0;
                    endcase
                end
            end else if (NUMKEYVARIATIONS == 4) begin : gen_4_key_variations
                always_comb begin
                    case (key_variation_state)
                        2'b00  : roundkey_o = keystate[Y-1:Y-X];
                        2'b01  : roundkey_o = {keystate[Y-X-1:0], next_keystate[Y-1:2*Y-2*X]};
                        2'b10  : roundkey_o = {keystate[2*Y-2*X-1:0], next_keystate[Y-1:3*Y-3*X]};
                        2'b11  : roundkey_o = keystate[3*Y-3*X-1:0];
                        default: roundkey_o = 'h0;
                    endcase
                end
            end
        end else begin : gen_one_key_variation
            // The round key is always the full state and we need to perform an update every time
            assign roundkey_o = keystate;
            assign update_state = 1'h1;
        end
    endgenerate

    // Update the internal state
    always_ff @(posedge clk_i) begin
        if (!rst_ni) begin
            // Reset round constants
            for (int i = 0; i < NUMSTEPS; i++) begin
                rc[i] <= initial_rc[i];
            end
            // Reset internal key state to the main Rijndael key
            keystate <= initial_keystate;
        end else if (enable_i && update_state) begin
            // Update round constants
            for (int i = 0; i < NUMSTEPS; i++) begin
               rc[i] <= next_rc[i];
            end
            // Update internal key state
            keystate <= next_keystate;
        end
    end

endmodule
