`timescale 1ns/1ps

module memory_firewall_tb;

    // Inputs
    reg clk;
    reg reset;
    reg input_valid;
    reg [31:0] address;
    reg rw;
    reg [1:0] privilege;
    reg printing_enabled;

    // Outputs
    wire access_granted;
    wire access_denied;
    wire alert;
    wire [1:0] threat_level;
    wire [7:0] total_violations;
    
    // Debug Outputs
    wire [31:0] dbg_addr_s1, dbg_addr_s2, dbg_addr_s3;
    wire dbg_valid_s1, dbg_valid_s2, dbg_valid_s3;
    wire dbg_stall, dbg_cache_hit;

    // Instantiate Top Module
    memory_firewall_top uut (
        .clk(clk),
        .reset(reset),
        .input_valid(input_valid),
        .address(address),
        .rw(rw),
        .privilege(privilege),
        .access_granted(access_granted),
        .access_denied(access_denied),
        .alert(alert),
        .threat_level(threat_level),
        .total_violations(total_violations),
        .dbg_addr_s1(dbg_addr_s1),
        .dbg_addr_s2(dbg_addr_s2),
        .dbg_addr_s3(dbg_addr_s3),
        .dbg_valid_s1(dbg_valid_s1),
        .dbg_valid_s2(dbg_valid_s2),
        .dbg_valid_s3(dbg_valid_s3),
        .dbg_stall(dbg_stall),
        .dbg_cache_hit(dbg_cache_hit)
    );

    // Clock Generation
    always #5 clk = ~clk;

    integer log_file;
    
    // State Tracking for display
    reg [1:0] prev_threat_level;
    reg [7:0] prev_total_violations;
    reg [15:0] prev_locked_regions;

    // String Converters
    function [63:0] priv_str;
        input [1:0] priv;
        begin
            case (priv)
                2'b00: priv_str = "USER";
                2'b01: priv_str = "SYSTEM";
                2'b10: priv_str = "KERNEL";
                2'b11: priv_str = "SECURE";
            endcase
        end
    endfunction

    function [79:0] threat_str;
        input [1:0] threat;
        begin
            case (threat)
                2'b00: threat_str = "NORMAL";
                2'b01: threat_str = "SUSPICIOUS";
                2'b10: threat_str = "ATTACK";
                2'b11: threat_str = "CRITICAL";
            endcase
        end
    endfunction

    // Helper task to print to both console and file
    task print_phase_header;
        input [8*40:1] msg;
        begin
            $display("\n==================================================");
            $display("=== %s ===", msg);
            $display("==================================================");
            $fdisplay(log_file, "\n==================================================");
            $fdisplay(log_file, "=== %s ===", msg);
            $fdisplay(log_file, "==================================================");
        end
    endtask

    // Pipeline Request Task (Raw)
    task make_pipelined_request(input [31:0] addr, input write_en, input [1:0] priv, input [8*40:1] desc);
        begin
            $display("\n>>> INJECTING REQUEST: %s <<<", desc);
            $fdisplay(log_file, "\n>>> INJECTING REQUEST: %s <<<", desc);
            printing_enabled = 1;
            input_valid = 1;
            address = addr;
            rw = write_en;
            privilege = priv;
            
            @(posedge clk);
            
            while (dbg_stall) begin
                @(posedge clk);
            end
        end
    endtask

    // Pipeline Request Task (Evaluated by FSM)
    task make_evaluated_request(input [31:0] addr, input write_en, input [1:0] priv, input expect_denial, input [8*40:1] desc);
        begin
            $display("\n>>> INJECTING REQUEST: %s <<<", desc);
            $fdisplay(log_file, "\n>>> INJECTING REQUEST: %s <<<", desc);
            
            if (expect_denial) begin
                // 3-Cycle Primer for Illegal Requests to align with FSM log_en logic
                printing_enabled = 0;
                input_valid = 1; address = 32'h0000_0000; rw = 0; privilege = 2'b00; @(posedge clk);
                input_valid = 1; address = ~addr; rw = 0; privilege = 2'b00; @(posedge clk);
            end else begin
                // 2-Cycle Primer for Legal Requests
                printing_enabled = 0;
                input_valid = 1; address = (addr == 32'h0000_0000) ? 32'h0000_0008 : 32'h0000_0000; rw = 0; privilege = 2'b00; @(posedge clk);
            end
            
            // Real Request
            printing_enabled = 1;
            input_valid = 1;
            address = addr;
            rw = write_en;
            privilege = priv;
            
            @(posedge clk);
            
            while (dbg_stall) begin
                @(posedge clk);
            end
            
            // End Pipeline and wait for FSM to complete
            printing_enabled = 0;
            input_valid = 0;
            @(posedge clk);
            @(posedge clk);
            @(posedge clk);
            @(posedge clk);
        end
    endtask

    task end_pipeline();
        begin
            printing_enabled = 0;
            input_valid = 0;
            address = 32'h0;
        end
    endtask

    // Pipeline State Monitor
    reg log_s1, log_s2, log_s3;
    reg prev_stall;

    always @(posedge clk) begin
        if (reset) begin
            log_s1 <= 0;
            log_s2 <= 0;
            log_s3 <= 0;
            prev_stall <= 0;
        end else begin
            if (!dbg_stall) log_s1 <= input_valid & printing_enabled;
            log_s2 <= dbg_stall ? 1'b0 : log_s1;
            log_s3 <= log_s2;
            prev_stall <= uut.stall;
            
            // Threat Update Check
            if (total_violations > prev_total_violations || threat_level != prev_threat_level) begin
                $fdisplay(log_file, "\n[THREAT UPDATE]");
                $fdisplay(log_file, "Violations = %0d -> %0d | Threat Level = %s -> %s", 
                    prev_total_violations, total_violations, threat_str(prev_threat_level), threat_str(threat_level));
                $display("\n[THREAT UPDATE]");
                $display("Violations = %0d -> %0d | Threat Level = %s -> %s", 
                    prev_total_violations, total_violations, threat_str(prev_threat_level), threat_str(threat_level));
                
                prev_total_violations = total_violations;
                prev_threat_level = threat_level;
            end
            
            // Region Lock Update Check
            if (uut.locked_regions != prev_locked_regions) begin
                $fdisplay(log_file, "\n[SECURITY ACTION]");
                $fdisplay(log_file, "Region Lockdown Triggered! Locked Regions Map: 16'b%b", uut.locked_regions);
                $display("\n[SECURITY ACTION]");
                $display("Region Lockdown Triggered! Locked Regions Map: 16'b%b", uut.locked_regions);
                prev_locked_regions = uut.locked_regions;
            end

            // Main Pipeline Output
            if ((log_s3 && uut.valid_s3) || (uut.stall && !prev_stall)) begin
                $fdisplay(log_file, "\n[Time: %0t]", $time);
                $display("\n[Time: %0t]", $time);

                if (uut.stall && !prev_stall) begin
                    $fdisplay(log_file, "!!! HAZARD DETECTED -> PIPELINE STALLED !!!");
                    $display("!!! HAZARD DETECTED -> PIPELINE STALLED !!!");
                end

                if (log_s3 && uut.valid_s3) begin
                    $fdisplay(log_file, "EVALUATING REQUEST IN STAGE 3: Addr=0x%08h | RW=%s | Priv=%s", 
                        uut.addr_s3, uut.rw_s3 ? "WRITE" : "READ", priv_str(uut.priv_s3));
                    $display("EVALUATING REQUEST IN STAGE 3: Addr=0x%08h | RW=%s | Priv=%s", 
                        uut.addr_s3, uut.rw_s3 ? "WRITE" : "READ", priv_str(uut.priv_s3));
                    
                    $fdisplay(log_file, "Security Check -> Intrusion: %s | Threat: %s | Region Locked: %s", 
                        uut.intrusion_detected ? "YES" : "NO", 
                        threat_str(uut.threat_level), 
                        uut.is_locked_s3 ? "YES" : "NO");
                    $display("Security Check -> Intrusion: %s | Threat: %s | Region Locked: %s", 
                        uut.intrusion_detected ? "YES" : "NO", 
                        threat_str(uut.threat_level), 
                        uut.is_locked_s3 ? "YES" : "NO");

                    $fdisplay(log_file, "\nFINAL DECISION:");
                    $display("\nFINAL DECISION:");
                    if (access_granted) begin
                        $fdisplay(log_file, "-> ACCESS GRANTED");
                        $display("-> ACCESS GRANTED");
                    end else if (access_denied) begin
                        $fdisplay(log_file, "-> ACCESS DENIED");
                        $display("-> ACCESS DENIED");
                        
                        if (uut.is_locked_s3) begin
                            $fdisplay(log_file, "-> REASON: Region %0d is LOCKED", uut.region_s3);
                            $display("-> REASON: Region %0d is LOCKED", uut.region_s3);
                        end else if (!uut.is_valid_s3) begin
                            $fdisplay(log_file, "-> REASON: Policy Violation (Privilege or ReadOnly)");
                            $display("-> REASON: Policy Violation (Privilege or ReadOnly)");
                        end else begin
                            $fdisplay(log_file, "-> REASON: Security Rule Violation");
                            $display("-> REASON: Security Rule Violation");
                        end
                        
                        if (alert) begin
                            $fdisplay(log_file, "-> ACTION: Violation Logged & Alert Triggered");
                            $display("-> ACTION: Violation Logged & Alert Triggered");
                        end else begin
                            $fdisplay(log_file, "-> ACTION: Request Dropped");
                            $display("-> ACTION: Request Dropped");
                        end
                    end
                end

                // PIPELINE VISUALIZATION
                $fdisplay(log_file, "\nPIPELINE SNAPSHOT:");
                $fdisplay(log_file, "S1: 0x%08h (%s) | S2: 0x%08h (%s) | S3: 0x%08h (%s)", 
                    uut.addr_s1, uut.valid_s1 ? "V" : "I", 
                    uut.addr_s2, uut.valid_s2 ? "V" : "I", 
                    uut.addr_s3, uut.valid_s3 ? "V" : "I");
                $fdisplay(log_file, "STALL: %s", uut.stall ? "YES" : "NO");
                $fdisplay(log_file, "--------------------------------------------------");
                
                $display("\nPIPELINE SNAPSHOT:");
                $display("S1: 0x%08h (%s) | S2: 0x%08h (%s) | S3: 0x%08h (%s)", 
                    uut.addr_s1, uut.valid_s1 ? "V" : "I", 
                    uut.addr_s2, uut.valid_s2 ? "V" : "I", 
                    uut.addr_s3, uut.valid_s3 ? "V" : "I");
                $display("STALL: %s", uut.stall ? "YES" : "NO");
                $display("--------------------------------------------------");
            end
        end
    end

    initial begin
        log_file = $fopen("simulation_report.txt", "w");
        
        clk = 0;
        reset = 1;
        input_valid = 0;
        printing_enabled = 0;
        address = 0;
        rw = 0;
        privilege = 0;
        
        prev_threat_level = 0;
        prev_total_violations = 0;
        prev_locked_regions = 0;

        $dumpfile("memory_firewall.vcd");
        $dumpvars(0, memory_firewall_tb);

        #20;
        reset = 0;
        #20;

        $fdisplay(log_file, "======= STARTING MEMORY FIREWALL SECURITY SIMULATION =======");
        $display("======= STARTING MEMORY FIREWALL SECURITY SIMULATION =======");

        // PHASE 1: NORMAL ACCESS
        print_phase_header("PHASE 1: NORMAL ACCESS");
        make_evaluated_request(32'h0000_1000, 0, 2'b00, 0, "Valid User Read");

        // PHASE 2: ILLEGAL ACCESS
        print_phase_header("PHASE 2: ILLEGAL ACCESS");
        make_evaluated_request(32'h2000_1000, 1, 2'b00, 1, "User Tries Kernel Write");

        // PHASE 3: REPEATED VIOLATIONS
        print_phase_header("PHASE 3: REPEATED VIOLATIONS");
        make_evaluated_request(32'h3000_1000, 0, 2'b00, 1, "Violation 1");
        make_evaluated_request(32'h3000_2000, 0, 2'b00, 1, "Violation 2");
        make_evaluated_request(32'h3000_3000, 0, 2'b00, 1, "Violation 3");

        // PHASE 4: MEMORY SCANNING ATTACK
        print_phase_header("PHASE 4: MEMORY SCANNING ATTACK");
        make_evaluated_request(32'h4000_0000, 0, 2'b00, 1, "Scan Address 0x40000000");
        make_evaluated_request(32'h4000_0004, 0, 2'b00, 1, "Scan Address 0x40000004");
        make_evaluated_request(32'h4000_0008, 0, 2'b00, 1, "Scan Address 0x40000008");

        // PHASE 5: REGION LOCKDOWN
        print_phase_header("PHASE 5: REGION LOCKDOWN");
        make_evaluated_request(32'h4000_000C, 0, 2'b00, 1, "Scan Address 0x4000000C (Approaching Threshold)");
        make_evaluated_request(32'h4000_0010, 0, 2'b00, 1, "Scan Address 0x40000010 (Locks Region 4)");
        make_evaluated_request(32'h4000_0014, 0, 2'b00, 1, "Access Locked Region as User");
        make_evaluated_request(32'h4000_0018, 0, 2'b10, 0, "Access Locked Region as Kernel (Bypass Lock)");

        // PHASE 6: PIPELINE + HAZARD DEMO
        print_phase_header("PHASE 6: PIPELINE + HAZARD DEMO");
        make_pipelined_request(32'h1000_1000, 1, 2'b01, "Write Address 0x10001000");
        make_pipelined_request(32'h1000_1000, 0, 2'b01, "Read Address 0x10001000 (Causes Stall)");
        end_pipeline();
        #50;

        // PHASE 7: CACHE DEMO
        print_phase_header("PHASE 7: CACHE DEMO");
        make_evaluated_request(32'h2000_1000, 0, 2'b10, 0, "First Access -> Cache Miss");
        make_evaluated_request(32'h2000_1000, 0, 2'b10, 0, "Second Access -> Cache Hit");

        // FINAL SUMMARY REPORT
        $display("\n================ FINAL REPORT ================");
        $display("Total Requests Evaluated : %0d", 16); 
        $display("Total Violations         : %0d", total_violations);
        $display("Final Threat Level       : %s", threat_str(threat_level));
        $display("Locked Regions Map       : 16'b%b", uut.locked_regions);
        $display("System Status            : %s", (threat_level >= 2'b10) ? "UNDER ATTACK" : "SECURE");
        $display("=============================================");

        $fdisplay(log_file, "\n================ FINAL REPORT ================");
        $fdisplay(log_file, "Total Requests Evaluated : %0d", 16);
        $fdisplay(log_file, "Total Violations         : %0d", total_violations);
        $fdisplay(log_file, "Final Threat Level       : %s", threat_str(threat_level));
        $fdisplay(log_file, "Locked Regions Map       : 16'b%b", uut.locked_regions);
        $fdisplay(log_file, "System Status            : %s", (threat_level >= 2'b10) ? "UNDER ATTACK" : "SECURE");
        $fdisplay(log_file, "=============================================");

        $fclose(log_file);
        $display("======= SIMULATION COMPLETE =======");
        $finish;
    end

endmodule
