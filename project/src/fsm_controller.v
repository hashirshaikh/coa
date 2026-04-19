module fsm_controller (
    input clk,
    input reset,
    input [31:0] address,
    input rw,
    input [1:0] privilege,
    input intrusion_detected,
    output reg log_en,
    output reg access_granted,
    output reg access_denied,
    output reg alert
);
    localparam IDLE = 2'b00, EVAL = 2'b01, RESOLVE = 2'b10;
    reg [1:0] state;

    reg [31:0] last_addr;
    reg last_rw;
    reg [1:0] last_priv;
    
    // Detect new access request
    wire new_request = (address != last_addr) || (rw != last_rw) || (privilege != last_priv);

    always @(posedge clk or posedge reset) begin
        if (reset) begin
            state <= IDLE;
            log_en <= 1'b0;
            access_granted <= 1'b0;
            access_denied <= 1'b0;
            alert <= 1'b0;
            last_addr <= 32'hFFFF_FFFF; // Initialization to unusual state
            last_rw <= 1'b0;
            last_priv <= 2'b0;
        end else begin
            case (state)
                IDLE: begin
                    log_en <= 1'b0;
                    if (new_request) begin
                        last_addr <= address;
                        last_rw <= rw;
                        last_priv <= privilege;
                        state <= EVAL;
                        
                        // Clear flags on new request
                        access_granted <= 1'b0;
                        access_denied <= 1'b0;
                        alert <= 1'b0;
                    end
                end
                EVAL: begin
                    if (intrusion_detected) begin
                        access_denied <= 1'b1;
                        alert <= 1'b1;
                        log_en <= 1'b1; // Trigger logging mechanisms
                    end else begin
                        access_granted <= 1'b1;
                    end
                    state <= RESOLVE;
                end
                RESOLVE: begin
                    log_en <= 1'b0; // Log is a one-clock pulse
                    if (new_request) begin
                        last_addr <= address;
                        last_rw <= rw;
                        last_priv <= privilege;
                        state <= EVAL;
                        
                        // Clear flags
                        access_granted <= 1'b0;
                        access_denied <= 1'b0;
                        alert <= 1'b0;
                    end
                end
            endcase
        end
    end
endmodule
