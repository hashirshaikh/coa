module memory_firewall_top (
    input clk,
    input reset,
    input input_valid,
    input [31:0] address,
    input rw,
    input [1:0] privilege,
    output access_granted,
    output access_denied,
    output alert,
    output [1:0] threat_level,
    output [7:0] total_violations,
    
    // Exposed for Testbench viewing
    output [31:0] dbg_addr_s1,
    output [31:0] dbg_addr_s2,
    output [31:0] dbg_addr_s3,
    output dbg_valid_s1,
    output dbg_valid_s2,
    output dbg_valid_s3,
    output dbg_stall,
    output dbg_cache_hit
);

    // ============================================
    // PIPELINE REGISTERS
    // ============================================
    
    // Stage 1
    reg valid_s1;
    reg [31:0] addr_s1;
    reg rw_s1;
    reg [1:0] priv_s1;
    
    // Stage 2
    reg valid_s2;
    reg [31:0] addr_s2;
    reg rw_s2;
    reg [1:0] priv_s2;
    reg [3:0] region_s2;
    
    // Stage 3
    reg valid_s3;
    reg [31:0] addr_s3;
    reg rw_s3;
    reg [1:0] priv_s3;
    reg [3:0] region_s3;
    reg is_valid_s3;

    // Output assignments for TB
    assign dbg_addr_s1 = addr_s1;
    assign dbg_addr_s2 = addr_s2;
    assign dbg_addr_s3 = addr_s3;
    assign dbg_valid_s1 = valid_s1;
    assign dbg_valid_s2 = valid_s2;
    assign dbg_valid_s3 = valid_s3;

    // ============================================
    // STAGE 1: Input Capture & Region Decode
    // ============================================
    wire [3:0] region_s1_comb;
    
    region_decoder u_region_decoder (
        .address(addr_s1),
        .region(region_s1_comb)
    );
    
    // ============================================
    // HAZARD DETECTION (Evaluate using S1 and S2)
    // ============================================
    wire stall;
    assign dbg_stall = stall;
    
    hazard_detection u_hazard_detect (
        .valid_s1(valid_s1),
        .valid_s2(valid_s2),
        .addr_s1(addr_s1),
        .addr_s2(addr_s2),
        .stall(stall)
    );

    // ============================================
    // STAGE 2: Cache, Policy Check, Access Control
    // ============================================
    wire cache_hit;
    wire cache_miss;
    assign dbg_cache_hit = cache_hit;
    
    cache u_cache (
        .clk(clk),
        .reset(reset),
        .address(addr_s2),
        .rw(rw_s2),
        .cache_hit(cache_hit),
        .cache_miss(cache_miss)
    );

    wire [1:0] req_privilege_s2;
    wire readonly_s2;
    policy_engine u_policy_engine (
        .region(region_s2),
        .req_privilege(req_privilege_s2),
        .readonly(readonly_s2)
    );

    wire is_valid_s2_comb;
    access_control u_access_control (
        .privilege(priv_s2),
        .rw(rw_s2),
        .req_privilege(req_privilege_s2),
        .readonly(readonly_s2),
        .is_valid(is_valid_s2_comb)
    );

    // ============================================
    // STAGE 3: Intrusion Detection, Logging, FSM
    // ============================================
    wire intrusion_detected;
    wire [15:0] locked_regions;
    wire is_locked_s3 = locked_regions[region_s3];

    // Forwarding logic
    wire [1:0] fwd_threat_level_s2;
    wire [15:0] fwd_locked_regions_s2;

    forwarding_unit u_forwarding (
        .threat_level_s3(threat_level),
        .locked_regions_s3(locked_regions),
        .fwd_threat_level_s2(fwd_threat_level_s2),
        .fwd_locked_regions_s2(fwd_locked_regions_s2)
    );

    // Apply forwarding to access control decision
    wire is_locked_s2 = fwd_locked_regions_s2[region_s2];
    wire is_valid_s2_final = is_valid_s2_comb && !is_locked_s2;

    intrusion_detection u_intrusion_detection (
        .is_valid(is_valid_s3),
        .is_locked(is_locked_s3),
        .privilege(priv_s3),
        .intrusion_detected(intrusion_detected)
    );

    wire log_en;
    // Log enable logic tied to valid_s3 to avoid dummy transaction logging
    wire fsm_log_en;
    assign log_en = valid_s3 && intrusion_detected && fsm_log_en;
    
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
        .address(addr_s3),
        .region(region_s3),
        .rw(rw_s3),
        .privilege(priv_s3)
    );

    threat_analysis u_threat_analysis (
        .clk(clk),
        .reset(reset),
        .log_en(log_en),
        .address(addr_s3),
        .total_violations(total_violations),
        .threat_level(threat_level)
    );

    region_lock u_region_lock (
        .clk(clk),
        .reset(reset),
        .region(region_s3),
        .log_en(log_en),
        .threat_level(threat_level),
        .locked_regions(locked_regions)
    );

    // Filter properties going into FSM based on Valid ID
    wire fsm_valid = valid_s3;
    wire intrusion_detected_to_fsm = fsm_valid ? intrusion_detected : 1'b0;
    
    fsm_controller u_fsm_controller (
        .clk(clk),
        .reset(reset),
        .address(addr_s3),
        .rw(rw_s3),
        .privilege(priv_s3),
        .intrusion_detected(intrusion_detected_to_fsm),
        .log_en(fsm_log_en),
        .access_granted(access_granted),
        .access_denied(access_denied),
        .alert(alert)
    );

    // ============================================
    // PIPELINE REGISTER LOGIC
    // ============================================
    always @(posedge clk or posedge reset) begin
        if (reset) begin
            valid_s1 <= 0;
            addr_s1 <= 0;
            rw_s1 <= 0;
            priv_s1 <= 0;
            
            valid_s2 <= 0;
            addr_s2 <= 0;
            rw_s2 <= 0;
            priv_s2 <= 0;
            region_s2 <= 0;
            
            valid_s3 <= 0;
            addr_s3 <= 0;
            rw_s3 <= 0;
            priv_s3 <= 0;
            region_s3 <= 0;
            is_valid_s3 <= 0;
        end else begin
            if (!stall) begin
                // S1 updates
                valid_s1 <= input_valid;
                addr_s1 <= address;
                rw_s1 <= rw;
                priv_s1 <= privilege;
            end
            
            // S2 updates from S1
            // If stalled, S2 gets a bubble (flush) so the instruction in S2 can leave and resolve the hazard.
            valid_s2 <= stall ? 1'b0 : valid_s1;
            if (!stall) begin
                addr_s2 <= addr_s1;
                rw_s2 <= rw_s1;
                priv_s2 <= priv_s1;
                region_s2 <= region_s1_comb;
            end
            
            // S3 Always updates (normal pipeline progression)
            // It inherently pulls a bubble if S2 was flushed.
            valid_s3 <= valid_s2;
            addr_s3  <= addr_s2;
            rw_s3    <= rw_s2;
            priv_s3  <= priv_s2;
            region_s3 <= region_s2;
            is_valid_s3 <= valid_s2 ? is_valid_s2_final : 1'b0;
        end
    end

endmodule
