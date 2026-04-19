module logger (
    input clk,
    input reset,
    input log_en,
    input [31:0] address,
    input [3:0] region,
    input rw,
    input [1:0] privilege
);
    // Circular buffer to store the last 4 violations
    reg [40:0] log_buffer [0:3];
    reg [1:0] ptr;

    always @(posedge clk or posedge reset) begin
        if (reset) begin
            ptr <= 2'b0;
            log_buffer[0] <= 41'b0;
            log_buffer[1] <= 41'b0;
            log_buffer[2] <= 41'b0;
            log_buffer[3] <= 41'b0;
        end else if (log_en) begin
            log_buffer[ptr] <= {address, region, rw, privilege};
            ptr <= ptr + 1'b1;
        end
    end
endmodule
