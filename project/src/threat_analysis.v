module threat_analysis (
    input clk,
    input reset,
    input log_en,
    input [31:0] address,
    input [7:0] total_violations,
    output reg [1:0] threat_level
);
    reg [31:0] last_attack_addr;
    reg [3:0] repeated_attack_cnt;
    reg [3:0] scan_cnt;

    // Threat Levels: 00=NORMAL, 01=SUSPICIOUS, 10=ATTACK, 11=CRITICAL
    always @(posedge clk or posedge reset) begin
        if (reset) begin
            threat_level <= 2'b00;
            last_attack_addr <= 32'h0;
            repeated_attack_cnt <= 4'd0;
            scan_cnt <= 4'd0;
        end else if (log_en) begin
            // 1. Pattern Detection Logic
            if (address == last_attack_addr) begin
                if (repeated_attack_cnt < 4'hF)
                    repeated_attack_cnt <= repeated_attack_cnt + 1'b1;
                scan_cnt <= 4'd0; 
            end else if (address == last_attack_addr + 32'd4) begin
                if (scan_cnt < 4'hF)
                    scan_cnt <= scan_cnt + 1'b1;
                repeated_attack_cnt <= 4'd0;
            end else begin
                repeated_attack_cnt <= 4'd0;
                scan_cnt <= 4'd0;
            end
            
            last_attack_addr <= address;

            // 2. Threshold-based Evaluation
            // Base evaluation on total violations
            if (total_violations >= 8'd7)
                threat_level <= 2'b11; // CRITICAL
            else if (total_violations >= 8'd5)
                threat_level <= 2'b10; // ATTACK
            else if (total_violations >= 8'd3)
                threat_level <= 2'b01; // SUSPICIOUS
            else
                threat_level <= 2'b00; // NORMAL

            // 3. Pattern Override (Accelerate escalation)
            if (repeated_attack_cnt >= 4'd3 || scan_cnt >= 4'd3) begin
                if (threat_level < 2'b10) threat_level <= 2'b10; // Jump to ATTACK
            end
            if (repeated_attack_cnt >= 4'd5 || scan_cnt >= 4'd5) begin
                threat_level <= 2'b11; // Jump to CRITICAL
            end
        end
    end
endmodule
