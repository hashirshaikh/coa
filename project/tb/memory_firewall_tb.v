`timescale 1ns/1ps

module memory_firewall_tb;

    // Inputs
    reg clk;
    reg reset;
    reg [31:0] address;
    reg rw;
    reg [1:0] privilege;

    // Outputs
    wire access_granted;
    wire access_denied;
    wire alert;
    wire [1:0] threat_level;
    wire [7:0] total_violations;

    // Instantiate Top Module
    memory_firewall_top uut (
        .clk(clk),
        .reset(reset),
        .address(address),
        .rw(rw),
        .privilege(privilege),
        .access_granted(access_granted),
        .access_denied(access_denied),
        .alert(alert),
        .threat_level(threat_level),
        .total_violations(total_violations)
    );

    // Clock Generation
    always #5 clk = ~clk;

    // Helper Task for submitting requests
    task make_request(input [31:0] addr, input write_en, input [1:0] priv, input [8*20:1] desc);
        begin
            $display("--- %s ---", desc);
            // Drive inputs
            address = addr;
            rw = write_en;
            privilege = priv;
            
            // Wait for FSM to Evaluate and Resolve
            @(posedge access_granted or posedge access_denied);
            #1; // Output stability margin
            
            // Log status
            $display("Addr:%h RW:%b Priv:%b | Gran:%b Den:%b Alrt:%b ThrLv:%b V_Cnt:%d\n",
                address, rw, privilege, access_granted, access_denied, alert, threat_level, total_violations);
            
            // Wait a few cycles before next transaction
            #20; 
        end
    endtask

    initial begin
        // Initialize Inputs
        clk = 0;
        reset = 1;
        address = 32'b0;
        rw = 0;
        privilege = 2'b00;

        // VCD Dump
        $dumpfile("memory_firewall.vcd");
        $dumpvars(0, memory_firewall_tb);

        // De-assert reset
        #20;
        reset = 0;
        #20;

        $display("======= STARTING MEMORY FIREWALL TESTBENCH =======");

        // 1. Normal Access: User Privilege reading User Region
        make_request(32'h0000_1000, 0, 2'b00, "Normal Read User Region");
        
        // 2. Illegal Kernel Write
        make_request(32'h2000_1000, 1, 2'b10, "Illegal Kernel Write");

        // 3. User Writing System (Escalation to SUSPICIOUS at V=3)
        make_request(32'h1000_1000, 1, 2'b00, "Violation 1");
        make_request(32'h1000_1004, 1, 2'b00, "Violation 2");
        make_request(32'h1000_1008, 1, 2'b00, "Violation 3 (SUSPICION)");

        // 4. Sequential Scan Detector Test (Should jump to ATTACK)
        make_request(32'h4000_0000, 0, 2'b00, "Scan 1");
        make_request(32'h4000_0004, 0, 2'b00, "Scan 2");
        make_request(32'h4000_0008, 0, 2'b00, "Scan 3 (ATTACK JUMP)");

        // 5. Reaching CRITICAL (V >= 7) and Locking Region 4 (Ext Kernel)
        // Region 4 is 0x4...
        make_request(32'h4000_1000, 1, 2'b00, "Viol 4 (on Reg 4)");
        make_request(32'h4000_1004, 1, 2'b00, "Viol 5 (on Reg 4)");
        make_request(32'h4000_1008, 1, 2'b00, "Viol 6 (on Reg 4)");
        make_request(32'h4000_100C, 1, 2'b00, "Viol 7 (CRITICAL & LOCK)");

        // 6. Privilege Bypass Test
        // Region 4 is locked. USER (2'b00) should be denied, 
        // but KERNEL (2'b10) should be granted (Region 4 normally allows KERNEL).
        make_request(32'h4000_2000, 0, 2'b00, "USER on Locked (Deny)");
        make_request(32'h4000_2004, 0, 2'b10, "KERNEL on Locked (Grant)");

        $display("======= SIMULATION COMPLETE =======");
        $finish;
    end

endmodule
