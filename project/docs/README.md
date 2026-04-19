# Adaptive Hardware Memory Firewall

## Project Description
This project implements an intelligent hardware memory firewall in Verilog HDL. It is designed to intercept memory access queries on a standard pipelined processor's memory bus, checking transaction privileges and policies before granting access. Additionally, the firewall dynamically identifies attack patterns (like repetitive access tampering), escalating internal threat levels and independently executing regional memory lockdowns to stave off attackers.

## System Workflow
1. A request comes into the memory subsystem comprising `address`, `rw` flag, and context `privilege`.
2. **`region_decoder`** evaluates the Top-4 bits of the address mapping to a memory region.
3. **`policy_engine`** looks up that region's static access rules.
4. **`access_control`** contrasts the rules with the request's parameters.
5. If denied, or if that memory region was already marked 'locked', **`intrusion_detection`** sets a high flag.
6. The **`fsm_controller`** captures this state, pulses `log_en` which triggers **`violation_counter`**, updates the **`logger`** buffer, evaluates security heuristics in **`threat_analysis`**, and updates lockdown statuses in **`region_lock`**.
7. Based on the FSM state, `access_granted` or `access_denied` is appropriately driven outward.

## Simulation / How to Run (Icarus Verilog)
This codebase avoids proprietary IPs and is fully open-source synthesis/simulation ready.
1. Place the `src/` modular components and `tb/` testbench correctly in directory. 
2. Use the terminal sequence to compile and run:
   ```bash
   iverilog -o sim_out tb/memory_firewall_tb.v src/*.v
   vvp sim_out
   vvp sim_out > simulation_results.txt

   ```
3. To view waveforms:
   ```bash
   gtkwave memory_firewall.vcd
   ```
