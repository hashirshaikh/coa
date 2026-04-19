module access_control (
    input [1:0] privilege,
    input rw, // 0 = read, 1 = write
    input [1:0] req_privilege,
    input readonly,
    output is_valid
);
    // Check if input privilege is greater or equal to required
    wire priv_ok = (privilege >= req_privilege);
    
    // Check if write is attempted on read-only region
    wire rw_ok = ~(rw & readonly);
    
    // Valid access requires both privilege clearance and correct R/W operation
    assign is_valid = priv_ok & rw_ok;
endmodule
