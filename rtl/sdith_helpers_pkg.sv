// SPDX-FileCopyrightText: 2026 Stef Halmans, Niklas Höher
// SPDX-License-Identifier: LicenseRef-RUB-SecEng

/*
 * Shared combinational helpers for the SDitH RTL, split out of sdith_params_pkg.
 */

package sdith_helpers_pkg;

    import sdith_params_pkg::*;

    // Byte-reverse a 64-bit word (LE memory <-> MSB-first SHAKE).
    function automatic logic [63:0] bswap64(input logic [63:0] d);
        bswap64 = {d[7:0],   d[15:8],  d[23:16], d[31:24],
                   d[39:32], d[47:40], d[55:48], d[63:56]};
    endfunction

    // Scratchpad (var_bram) port translation: logical 64-bit address -> physical port address.
    // CAN_DUAL=1 (SEC3/5, 64-bit ports): port A carries full word.
    // CAN_DUAL=0 (SEC1, 32-bit ports): port A = lo 32b, port B = hi 32b.
    function automatic logic [VAR_ADDR_WIDTH_COMBINED-1:0]
    phys_a(input logic [VAR_ADDR_WIDTH_COMBINED-1:0] logical_addr);
        if (CAN_DUAL_COMBINED) return logical_addr;
        else                   return VAR_ADDR_WIDTH_COMBINED'({logical_addr, 1'b0});
    endfunction

    function automatic logic [VAR_ADDR_WIDTH_COMBINED-1:0]
    phys_b(input logic [VAR_ADDR_WIDTH_COMBINED-1:0] logical_addr);
        if (CAN_DUAL_COMBINED) return logical_addr;
        else                   return VAR_ADDR_WIDTH_COMBINED'({logical_addr, 1'b1});
    endfunction

    // Split a 64-bit write word into the appropriate port half.
    function automatic logic [VAR_DATA_WIDTH_COMBINED-1:0]
    split_a(input logic [63:0] data);
        if (CAN_DUAL_COMBINED) return VAR_DATA_WIDTH_COMBINED'(data);
        else                   return data[31:0];
    endfunction

    function automatic logic [VAR_DATA_WIDTH_COMBINED-1:0]
    split_b(input logic [63:0] data);
        if (CAN_DUAL_COMBINED) return VAR_DATA_WIDTH_COMBINED'(data);
        else                   return data[63:32];
    endfunction

    // Count trailing zeros of a value in range [1, N_CAP]. Used for
    // Gray-code column selection: column j first written at i = 2^j.
    function automatic logic [$clog2(KAPPA)-1:0]
    ctz_func(input logic [$clog2(N_CAP):0] val);
        ctz_func = '0;
        for (int b = 0; b < KAPPA; b++) begin
            if (val[b]) begin
                ctz_func = ($clog2(KAPPA))'(b);
                break;
            end
        end
    endfunction

endpackage
