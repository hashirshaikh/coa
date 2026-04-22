module forwarding_unit (
    input [1:0] threat_level_s3,
    input [15:0] locked_regions_s3,
    output [1:0] fwd_threat_level_s2,
    output [15:0] fwd_locked_regions_s2
);
    // Forward the current outputs of S3 to earlier stages if needed
    assign fwd_threat_level_s2 = threat_level_s3;
    assign fwd_locked_regions_s2 = locked_regions_s3;

endmodule
