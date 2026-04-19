module region_lock (
    input clk,
    input reset,
    input [3:0] region,
    input log_en,
    input [1:0] threat_level,
    output reg [15:0] locked_regions
);
    // Track violations per region
    reg [7:0] region_violations [0:15];
    integer i;

    always @(posedge clk or posedge reset) begin
        if (reset) begin
            locked_regions <= 16'b0;
            for (i=0; i<16; i=i+1) begin
                region_violations[i] <= 8'd0;
            end
        end else if (log_en) begin
            if (region_violations[region] < 8'hFF)
                region_violations[region] <= region_violations[region] + 1'b1;
            
            // Region lock trigger: ONLY if threat level is CRITICAL
            // and threshold (4 violations in region) is met.
            if (threat_level == 2'b11 && region_violations[region] >= 8'd4) 
                locked_regions[region] <= 1'b1;
        end
    end
endmodule
