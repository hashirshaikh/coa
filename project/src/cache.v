module cache #(
    parameter ADDR_WIDTH = 32,
    parameter CACHE_LINES = 16
)(
    input clk,
    input reset,
    input [ADDR_WIDTH-1:0] address,
    input rw,
    output cache_hit,
    output cache_miss
);

    localparam INDEX_WIDTH = 4;
    
    wire [INDEX_WIDTH-1:0] index = address[INDEX_WIDTH-1:0];
    wire [ADDR_WIDTH-INDEX_WIDTH-1:0] tag = address[ADDR_WIDTH-1:INDEX_WIDTH];

    reg valid_array [0:CACHE_LINES-1];
    reg [ADDR_WIDTH-INDEX_WIDTH-1:0] tag_array [0:CACHE_LINES-1];

    integer i;

    assign cache_hit = valid_array[index] && (tag_array[index] == tag);
    assign cache_miss = ~cache_hit;

    always @(posedge clk or posedge reset) begin
        if (reset) begin
            for (i=0; i<CACHE_LINES; i=i+1) begin
                valid_array[i] <= 1'b0;
            end
        end else begin
            if (cache_miss) begin
                valid_array[index] <= 1'b1;
                tag_array[index] <= tag;
            end
        end
    end

endmodule
