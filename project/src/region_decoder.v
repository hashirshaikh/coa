module region_decoder (
    input [31:0] address,
    output reg [3:0] region
);
    // MSB-based region decoding
    always @(*) begin
        case (address[31:28])
            4'h0: region = 4'd0;  // User Region
            4'h1: region = 4'd1;  // System Region
            4'h2: region = 4'd2;  // Kernel Region
            4'h3: region = 4'd3;  // Secure Region
            4'h4: region = 4'd4;
            4'h5: region = 4'd5;
            default: region = 4'd15; // Unmapped / Default Secure
        endcase
    end
endmodule
