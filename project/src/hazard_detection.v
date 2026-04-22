module hazard_detection (
    input valid_s1,
    input valid_s2,
    input [31:0] addr_s1,
    input [31:0] addr_s2,
    output stall
);

    // Hazard detection according to specifications
    assign stall = valid_s1 && valid_s2 && (addr_s1 == addr_s2);

endmodule
