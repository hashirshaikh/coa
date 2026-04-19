module intrusion_detection (
    input is_valid,
    input is_locked,
    input [1:0] privilege,
    output intrusion_detected
);
    // An intrusion is either an invalid access attempt 
    // OR accessing a locked region while having LOW privilege (USER or SYSTEM).
    // KERNEL (2'b10) and SECURE (2'b11) are allowed to bypass region locks.
    assign intrusion_detected = (~is_valid) | (is_locked && (privilege < 2'b10));
endmodule
