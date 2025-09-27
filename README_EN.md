# CyberLabs: Memory Vulnerability Laboratory Collection

A comprehensive collection of hands-on laboratories for learning memory corruption vulnerabilities and exploitation techniques.

## Overview

This repository contains five different memory vulnerability laboratories designed for cybersecurity education. Each lab focuses on a specific type of memory vulnerability and provides hands-on experience with exploitation techniques.

## Laboratories

### 1. Buffer-Overflow Lab
**Module Code:** CL-MEM-002  
**Level:** Intermediate / Advanced  
**Topic:** Stack Buffer Overflow Exploitation

- **Vulnerability:** Stack buffer overflow leading to control flow hijacking
- **Techniques:** Return address overwrite, ROP chains, shellcode injection
- **Tools:** GDB, objdump, pwntools
- **Files:** `vulnerable_code.cpp`, `exploit.py`

### 2. Double-Free Lab
**Module Code:** CL-MEM-006  
**Level:** Advanced  
**Topic:** Heap Exploitation (Double-Free + Use-After-Free)

- **Vulnerability:** Custom heap allocator with double-free and UAF vulnerabilities
- **Techniques:** Free list poisoning, arbitrary write, control flow hijacking
- **Tools:** GDB, pwntools, custom heap analysis
- **Files:** `vulnerable_code.cpp`, `exploit.py`

### 3. Heap-Overflow Lab
**Module Code:** CL-MEM-004  
**Level:** Intermediate / Advanced  
**Topic:** Heap Buffer Overflow Exploitation

- **Vulnerability:** Heap buffer overflow affecting adjacent memory structures
- **Techniques:** Function pointer overwrite, struct manipulation
- **Tools:** GDB, objdump, struct analysis
- **Files:** `zafiyetli_sunucu.cpp`, `exploit.py`

### 4. Memory-Leak Lab
**Module Code:** CL-MEM-003  
**Level:** Intermediate  
**Topic:** Resource Exhaustion (Memory Leak DoS)

- **Vulnerability:** Memory leak leading to Denial of Service and data exposure
- **Techniques:** Continuous memory allocation, resource exhaustion, sensitive data leakage
- **Tools:** ps, watch, gdb, memory monitoring
- **Files:** `vulnerable_server.cpp`, `exploit.py`, `test_exploit.py`

### 5. Use-After-Free Lab
**Module Code:** CL-MEM-002  
**Level:** Intermediate / Advanced  
**Topic:** Use-After-Free Exploitation

- **Vulnerability:** Use-after-free leading to control flow hijacking
- **Techniques:** Dangling pointer exploitation, function pointer overwrite
- **Tools:** GDB, objdump, struct layout analysis
- **Files:** `zafiyetli_sunucu.cpp`, `exploit.py`

## Quick Start

### Prerequisites
- **Linux:** `g++`, `build-essential`, `libc6-dev`, `python3`, `pwntools`
- **macOS:** `g++` (Xcode Command Line Tools), `python3`, `pwntools`

### Running All Labs
```bash
# Test all laboratories
./test_all_labs.sh

# Test individual lab
cd Buffer-Overflow && ./test_lab.sh

# Compile for Linux
cd Heap-Overflow && ./compile_linux.sh
```

### Individual Lab Usage
```bash
# Navigate to lab directory
cd Double-Free

# Compile the vulnerable program
./compile_linux.sh

# Test the lab
./test_lab.sh

# Run the exploit
python3 source_code/exploit.py
```

## Laboratory Structure

Each laboratory follows a consistent structure:

```
Lab-Name/
├── README.md              # Turkish documentation
├── README_EN.md           # English documentation
├── compile_linux.sh       # Linux compilation script
├── test_lab.sh           # Laboratory testing script
├── source_code/          # Source code directory
│   ├── vulnerable_*.cpp   # Vulnerable C++ program
│   └── exploit.py        # Python exploit script
└── compiled/             # Compiled binaries
    └── vulnerable_*      # Compiled vulnerable program
```

## Features

### Cross-Platform Compatibility
- ✅ Linux support with static linking
- ✅ macOS support with dynamic linking
- ✅ Automatic OS detection
- ✅ Platform-specific compilation flags

### Educational Tools
- ✅ Step-by-step exploitation guides
- ✅ GDB debugging examples
- ✅ Memory layout analysis
- ✅ Exploit development techniques

### Testing and Validation
- ✅ Automated testing scripts
- ✅ Vulnerability verification
- ✅ Exploit success validation
- ✅ Memory monitoring tools

## Learning Objectives

By completing these laboratories, students will:

1. **Understand Memory Layouts**
   - Stack, heap, and global variable organization
   - Memory allocation and deallocation mechanisms
   - Pointer arithmetic and memory addressing

2. **Master Exploitation Techniques**
   - Buffer overflow exploitation
   - Heap manipulation and corruption
   - Control flow hijacking methods
   - Payload development and delivery

3. **Develop Analysis Skills**
   - Static analysis with objdump and disassemblers
   - Dynamic analysis with GDB and debuggers
   - Memory forensics and reverse engineering
   - Vulnerability assessment methodologies

4. **Practice Defensive Programming**
   - Secure coding practices
   - Memory protection mechanisms
   - Vulnerability prevention techniques
   - Security testing approaches

## Safety and Legal Notice

⚠️ **IMPORTANT DISCLAIMER**

This laboratory collection is designed **exclusively for educational purposes** within the CyberLabs learning environment. The materials provided here are intended to help cybersecurity professionals:

- Understand defense mechanisms
- Develop vulnerability analysis capabilities
- Learn secure programming practices
- Enhance security testing skills

**Prohibited Uses:**
- Any use outside the CyberLabs educational environment
- Illegal activities or unauthorized system access
- Malicious exploitation of real systems
- Distribution for non-educational purposes

**Responsibility:** All users are responsible for using these materials ethically and legally. The authors and CyberLabs disclaim any responsibility for misuse of these educational materials.

## Contributing

This laboratory collection is part of the CyberLabs educational platform. For questions, suggestions, or contributions, please contact the CyberLabs team.

## License

This project is licensed under the CyberLabs Educational License. See the LICENSE file for details.

---

**CyberLabs** - Advancing Cybersecurity Education Through Hands-On Learning
