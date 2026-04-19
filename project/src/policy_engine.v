module policy_engine (
    input [3:0] region,
    output reg [1:0] req_privilege,
    output reg readonly
);
    // Privilege levels: 00=user, 01=system, 10=kernel, 11=secure
    always @(*) begin
        case (region)
            4'd0: begin req_privilege = 2'b00; readonly = 1'b0; end // User: RW
            4'd1: begin req_privilege = 2'b01; readonly = 1'b0; end // System: RW
            4'd2: begin req_privilege = 2'b10; readonly = 1'b1; end // Kernel: RO
            4'd3: begin req_privilege = 2'b11; readonly = 1'b0; end // Secure: RW
            4'd4: begin req_privilege = 2'b10; readonly = 1'b0; end // Ext Kernel: RW
            default: begin req_privilege = 2'b11; readonly = 1'b1; end // Default: Secure RO
        endcase
    end
endmodule
