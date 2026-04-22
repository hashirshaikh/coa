# 🔐 Adaptive Hardware Memory Firewall (Pipelined COA Design)
## 📌 Project Overview

This project implements a hardware-level adaptive memory firewall in Verilog HDL that operates between a processor and memory subsystem. It enforces secure, policy-based access control while integrating advanced computer architecture features such as pipelining, caching, and hazard handling.

The system not only validates memory accesses but also performs behavior-based intrusion detection, dynamically escalates threat levels, and enforces adaptive region-level lockdowns.

This design combines concepts from computer organization (COA) and hardware security, resulting in a unified, high-performance security subsystem.

## 🧠 Key Features
### 🔹 1. Memory Region-Based Access Control
- Memory space is divided into regions using `region_decoder`
- Each region has predefined access policies (`policy_engine`)
- Access requests are validated in real time (`access_control`)

👉 **Enables:**
- Privilege-based protection (user, system, kernel, secure)
- Read/write permission enforcement

### 🔹 2. Pipelined Architecture (3-Stage)
The system is implemented as a 3-stage pipeline:
- **Stage 1** → Input Capture + Region Decode  
- **Stage 2** → Cache Lookup + Policy + Access Control  
- **Stage 3** → Intrusion Detection + Threat Analysis + Lock + Output

✔ Improves throughput
✔ Models real processor pipeline behavior
✔ Maintains continuous data flow without deadlock

### 🔹 3. Cache Integration (Direct-Mapped Cache)
- Implemented in Stage 2
- Detects cache hit/miss for memory accesses
- Works alongside security checks (not bypassing them)

👉 **Demonstrates:**
- Memory hierarchy concepts
- Integration of performance and security

### 🔹 4. Hazard Detection and Stall Mechanism
- Detects hazards when the same address appears in consecutive pipeline stages
- Uses bubble insertion instead of full pipeline freeze
- `stall = valid_s1 && valid_s2 && (addr_s1 == addr_s2)`

👉 **Ensures:**
- Correct execution order
- No data conflicts
- Deadlock-free operation

### 🔹 5. Forwarding Unit
Forwards updated:
- `locked_regions`
- `threat_level`
From Stage 3 → Stage 2

👉 **Prevents:**
- Stale security decisions
- Incorrect access validation

### 🔹 6. Intrusion Detection System (Hardware-Based)
Detects:
- Unauthorized access
- Illegal writes
- Access to locked regions

👉 **Generates:**
- Alert signal
- Logging trigger

### 🔹 7. Behavioral Threat Analysis
- Tracks repeated and patterned memory accesses
- Dynamically updates threat levels:
  - `00` → Normal  
  - `01` → Suspicious  
  - `10` → Attack  
  - `11` → Critical

👉 **Enables adaptive system response**

### 🔹 8. Adaptive Region Locking
- Locks memory regions under attack
- Enforces stricter rules:
  - Low privilege → denied
  - High privilege → allowed (controlled)

👉 **Provides real-time containment of threats**

### 🔹 9. Violation Logging and Tracking
- `violation_counter` tracks number of attacks
- `logger` records:
  - Address
  - Region
  - Access type
  - Privilege level

👉 **Enables audit and analysis**

### 🔹 10. FSM-Based Control Unit
Controls system behavior:
Detection → Logging → Response
Integrated safely with pipeline using valid gating

👉 **Ensures:**
- Correct output generation
- No loss of pipeline transactions

## ⚙️ System Workflow
1. Memory request enters (address, rw, privilege, input_valid)
2. **Stage 1** decodes region
3. **Stage 2:**
   - Performs cache lookup
   - Applies policy and access control
4. **Stage 3:**
   - Detects intrusion
   - Updates threat level
   - Applies region lock
   - Logs violation
   - Generates final output

## 🚀 Novelty of the Project
While individual components exist in modern processors, this project’s novelty lies in their integration into a unified hardware security pipeline.

### 💡 Key Innovations
- Pipeline-driven security processing (not just performance)
- Hardware-level intrusion detection system
- Behavior-based threat analysis
- Adaptive region lockdown mechanism
- Integration of cache + hazard handling with security logic

👉 Effectively behaves like a **mini hardware security processor**

## 🧪 Simulation Instructions (Icarus Verilog)
**Compile and Run**
```bash
iverilog -o sim_out tb/memory_firewall_tb.v src/*.v
vvp sim_out
vvp sim_out > simulation_results.txt
```
**View Waveforms**
```bash
gtkwave memory_firewall.vcd
```

## 🧪 Testbench Features
The testbench validates:
- Normal memory access flow
- Unauthorized access detection
- Hazard detection and stall behavior
- Cache hit/miss scenarios
- Threat escalation
- Region lockdown enforcement
- Continuous pipeline execution (no deadlock)

## 🏁 Conclusion
This project demonstrates how computer architecture techniques and cybersecurity mechanisms can be co-designed at the hardware level.

It successfully integrates:
- Pipelining
- Cache memory
- Hazard handling
- Intrusion detection
- Adaptive response

👉 **Resulting in a high-performance, intelligent, and secure memory access system**

## 📌 Technologies Used
- Verilog HDL
- Icarus Verilog (Simulation)
- GTKWave (Waveform Analysis)
