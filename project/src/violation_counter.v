module violation_counter (
    input clk,
    input reset,
    input log_en,
    output reg [7:0] total_violations
);
    // Tracks total violations in the system
    always @(posedge clk or posedge reset) begin
        if (reset)
            total_violations <= 8'd0;
        else if (log_en) begin
            // Saturating counter
            if (total_violations < 8'hFF)
                total_violations <= total_violations + 1'b1;
        end
    end
endmodule
