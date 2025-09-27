# CyberLabs: Memory Vulnerability Laboratory Collection

**Platform:** CyberLabs Educational System  
**Level:** Beginner - Advanced  
**Topic:** Memory Corruption Vulnerabilities and Exploitation Techniques

## Overview

CyberLabs Memory Vulnerability Laboratory is a comprehensive educational platform designed for cybersecurity professionals to understand memory corruption vulnerabilities and learn exploitation techniques. This platform contains interactive laboratories that simulate real-world vulnerabilities.

## Laboratories

### 1. Buffer-Overflow Lab
**Module Code:** CL-MEM-001  
**Level:** Beginner  
**Topic:** Stack Buffer Overflow

- Understanding stack-based buffer overflow vulnerabilities
- Return address manipulation techniques
- Shellcode writing and execution
- Stack canary bypass methods

### 2. Double-Free Lab
**Module Code:** CL-MEM-006  
**Level:** Advanced  
**Topic:** Heap Double-Free and Use-After-Free

- Design flaws in custom heap managers
- Exploiting double-free vulnerabilities
- Use-After-Free (UAF) attack techniques
- Free list poisoning methods

### 3. Heap-Overflow Lab
**Module Code:** CL-MEM-003  
**Level:** Intermediate  
**Topic:** Heap Buffer Overflow

- Heap-based buffer overflow vulnerabilities
- Heap metadata manipulation
- Heap spraying techniques
- Heap feng shui

### 4. Memory-Leak Lab
**Module Code:** CL-MEM-004  
**Level:** Beginner  
**Topic:** Memory Leak and DoS

- Detecting memory leak vulnerabilities
- Resource exhaustion attacks
- Memory monitoring tools
- DoS (Denial of Service) techniques

### 5. Use-After-Free Lab
**Module Code:** CL-MEM-005  
**Level:** Advanced  
**Topic:** Use-After-Free Exploitation

- Analyzing Use-After-Free vulnerabilities
- Heap layout manipulation
- Function pointer hijacking
- Advanced heap exploitation

### 6. ROP-Vulnerability Lab
**Module Code:** CL-MEM-007  
**Level:** Advanced  
**Topic:** Return-Oriented Programming

- ROP (Return-Oriented Programming) techniques
- NX bit bypass methods
- Gadget finding and chain building
- Shellcode injection
- Platform-specific ROP (Linux x86_64, macOS ARM64)

## Quick Start

### Prerequisites
- **Linux:** `g++`, `build-essential`, `libc6-dev`, `python3`, `pwntools`
- **macOS:** `g++` (Xcode Command Line Tools), `python3`, `pwntools`

### Difficulty Levels

## 🟢 **EASY WAY: With Debug Symbols**
```bash
# Add -g flag in test_lab.sh file
g++ -o compiled/vulnerable_code source_code/vulnerable_code.cpp -g -fno-stack-protector
```
- Easier analysis with debug symbols
- `p &variable` commands work in GDB
- Ideal for educational purposes

## 🔴 **HARD WAY: Without Debug Symbols (Default)**
```bash
# Current compilation (no debug symbols)
g++ -o compiled/vulnerable_code source_code/vulnerable_code.cpp -fno-stack-protector
```
- Closer to real world
- Requires `info functions`, `disassemble` commands
- Production binaries don't have debug symbols

### Running All Labs
```bash
# Test all laboratories
./test_all_labs.sh

# Test individual lab
cd Buffer-Overflow && ./test_lab.sh
cd Double-Free && ./test_lab.sh
cd Heap-Overflow && ./test_lab.sh
cd Memory-Leak && ./test_lab.sh
cd Use-After-Free && ./test_lab.sh
cd ROP-Vulnerability && ./test_lab.sh

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

### 🎯 **Education-Focused Design**
- Each laboratory simulates real-world vulnerabilities
- Step-by-step explanations and detailed documentation
- Interactive debugging guides with GDB

### 🔧 **Multi-Platform Support**
- Linux and macOS compatibility
- Automatic compilation scripts
- Platform-specific optimizations

### 🛠️ **Advanced Tools**
- Automatic address finding systems
- Pwntools integration
- Comprehensive test suites
- Memory monitoring tools
- Two difficulty levels (Easy/Hard)

### 📚 **Comprehensive Documentation**
- Turkish and English README files
- Detailed code explanations
- GDB debugging guides
- Exploit development tutorials

## Learning Objectives

This platform enables participants to:

1. **Memory Management:** Understand memory management in C/C++ programs
2. **Vulnerability Analysis:** Detect various memory vulnerabilities
3. **Exploit Development:** Learn basic and advanced exploit techniques
4. **Debugging:** Use GDB and other tools for debugging
5. **Security:** Understand defense mechanisms

### Detailed Skills
- **Memory Layouts:** Stack, heap, and global variable organization
- **Exploitation Techniques:** Buffer overflow, heap manipulation, control flow hijacking
- **Analysis Skills:** Static analysis, dynamic analysis, memory forensics
- **Defensive Programming:** Secure coding, memory protection, vulnerability prevention

## Security Warning

⚠️ **IMPORTANT:** These laboratories are for educational purposes only. The techniques should:
- Not be used for illegal purposes
- Be tested on your own systems
- Require permission before use on real systems
- Follow ethical hacking principles

## Contributing

This project is open source and welcomes your contributions:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Contact

- **Project Owner:** CyberLabs Education Team
- **GitHub:** [CyberLabs Repository](https://github.com/cyberlabs/memory-vulnerabilities)
- **Email:** education@cyberlabs.com

## Acknowledgments

This project was developed with contributions from the cybersecurity community, especially:
- OWASP community
- Exploit Database (ExploitDB)
- Pwntools developers
- GDB and LLVM projects

---

**Note:** These laboratories are continuously updated. Follow the GitHub repository for the latest version.
