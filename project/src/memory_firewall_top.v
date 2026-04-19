module memory_firewall_top (
    input clk,
    input reset,
    input [31:0] address,
    input rw,
    input [1:0] privilege,
    output access_granted,
    output access_denied,
    output alert,
    output [1:0] threat_level,
    output [7:0] total_violations // Exposed for TB viewing convenience
);

    wire [3:0] region;
    wire [1:0] req_privilege;
    wire readonly;
    wire is_valid;
    wire intrusion_detected;
    wire log_en;
    wire [15:0] locked_regions;
    wire is_locked;

    // Structural Instantiations
    region_decoder u_region_decoder (
        .address(address),
        .region(region)
    );

    policy_engine u_policy_engine (
        .region(region),
        .req_privilege(req_privilege),
        .readonly(readonly)
    );

    access_control u_access_control (
        .privilege(privilege),
        .rw(rw),
        .req_privilege(req_privilege),
        .readonly(readonly),
        .is_valid(is_valid)
    );

    assign is_locked = locked_regions[region];

    intrusion_detection u_intrusion_detection (
        .is_valid(is_valid),
        .is_locked(is_locked),
        .privilege(privilege),
        .intrusion_detected(intrusion_detected)
    );

    violation_counter u_violation_counter (
        .clk(clk),
        .reset(reset),
        .log_en(log_en),
        .total_violations(total_violations)
    );

    logger u_logger (
        .clk(clk),
        .reset(reset),
        .log_en(log_en),
        .address(address),
        .region(region),
        .rw(rw),
        .privilege(privilege)
    );

    threat_analysis u_threat_analysis (
        .clk(clk),
        .reset(reset),
        .log_en(log_en),
        .address(address),
        .total_violations(total_violations),
        .threat_level(threat_level)
    );

    region_lock u_region_lock (
        .clk(clk),
        .reset(reset),
        .region(region),
        .log_en(log_en),
        .threat_level(threat_level),
        .locked_regions(locked_regions)
    );

    fsm_controller u_fsm_controller (
        .clk(clk),
        .reset(reset),
        .address(address),
        .rw(rw),
        .privilege(privilege),
        .intrusion_detected(intrusion_detected),
        .log_en(log_en),
        .access_granted(access_granted),
        .access_denied(access_denied),
        .alert(alert)
    );

endmodule
