`timescale 1ns/1ps

module memory_firewall_tb;

    // Inputs
    reg clk;
    reg reset;
    reg input_valid;
    reg [31:0] address;
    reg rw;
    reg [1:0] privilege;

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

    // Pipeline Request Task
    task make_pipelined_request(input [31:0] addr, input write_en, input [1:0] priv, input [8*30:1] desc);
        begin
            $display("\n--- %s ---", desc);
            input_valid = 1;
            address = addr;
            rw = write_en;
            privilege = priv;
            
            @(posedge clk);
            
            while (dbg_stall) begin
                @(posedge clk);
            end
            
            // Do NOT immediately turn off valid if we are pipelining back-to-back
            // testbench will manually lower it at the end.
        end
    endtask

    task end_pipeline();
        begin
            input_valid = 0;
            address = 32'h0;
        end
    endtask

    // Pipeline State Monitor
    always @(posedge clk) begin
        if (!reset) begin
            $display("T:%0t | S1(v:%b D:%h) | S2(v:%b D:%h) | S3(v:%b D:%h) | STL:%b CACHE:%b THR:%b",
                $time, dbg_valid_s1, dbg_addr_s1, dbg_valid_s2, dbg_addr_s2, dbg_valid_s3, dbg_addr_s3, dbg_stall, dbg_cache_hit, threat_level);
        end
    end

    initial begin
        clk = 0;
        reset = 1;
        input_valid = 0;
        address = 0;
        rw = 0;
        privilege = 0;

        $dumpfile("memory_firewall.vcd");
        $dumpvars(0, memory_firewall_tb);

        #20;
        reset = 0;
        #20;

        $display("======= STARTING PIPELINE TESTBENCH =======");

        // 1. Normal Pipeline Flow S1->S2->S3
        make_pipelined_request(32'h0000_1000, 0, 2'b00, "Normal Read");
        #40; // Let pipeline drain

        // 2. Cache Hit Demo (repeated same address creates stall initially, but tests cache)
        // Wait, same address back to back causes stall. We will do it with a gap.
        make_pipelined_request(32'h2000_1000, 0, 2'b10, "Cache Miss (Kernel Read)");
        #40;
        make_pipelined_request(32'h2000_1000, 1, 2'b10, "Cache Hit (Kernel Write)");
        #40;

        // 3. Hazard Stall Testing: Back-to-back same address
        make_pipelined_request(32'h1000_1000, 1, 2'b00, "Violation 1 (Triggers Stall next)");
        make_pipelined_request(32'h1000_1000, 1, 2'b00, "Violation 2 (Duplicates Addr)");
        end_pipeline();
        #50;

        // 4. Pipelining 3 Different Addresses (No Stall)
        make_pipelined_request(32'h4000_0000, 0, 2'b00, "Scan 1");
        make_pipelined_request(32'h4000_0004, 0, 2'b00, "Scan 2");
        make_pipelined_request(32'h4000_0008, 0, 2'b00, "Scan 3");
        end_pipeline();
        #50;

        $display("======= SIMULATION COMPLETE =======");
        $finish;
    end

endmodule
