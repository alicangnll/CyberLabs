# Integer Overflow Lab

**Module Code:** CL-MEM-008  
**Level:** Intermediate  
**Topic:** Integer Overflow and Underflow Vulnerabilities

## Overview

The Integer Overflow Lab is a comprehensive educational laboratory designed to understand and exploit integer overflow and underflow vulnerabilities in C/C++ programs. This laboratory contains 5 different scenarios that simulate common integer vulnerabilities found in the real world.

## Vulnerability Types

### 1. Buffer Size Calculation Error
- **Vulnerability:** Inputting negative values to obtain large positive numbers through unsigned casting
- **Result:** Buffer overflow and memory corruption
- **Example:** Inputting `-1` to obtain `0xFFFFFFFF` (4GB) buffer size

### 2. Arithmetic Overflow (Addition)
- **Vulnerability:** Overflow when adding two large positive numbers
- **Result:** Negative result and bypassing security checks
- **Example:** `INT_MAX + 1` = negative value

### 3. Array Bounds Bypass
- **Vulnerability:** Inputting large positive numbers to obtain negative indices
- **Result:** Access beyond array boundaries
- **Example:** Inputting `UINT_MAX` to obtain `-1` index

### 4. Multiplication Overflow
- **Vulnerability:** Overflow when multiplying two large numbers
- **Result:** Negative result and memory allocation error
- **Example:** `65537 * 65537` = overflow

### 5. Subtraction Underflow
- **Vulnerability:** Making `end < start` to obtain negative length
- **Result:** Negative length and memory operations
- **Example:** `start=10, end=5` = `-5` length

## Laboratory Features

### 🎯 **Education-Focused Design**
- Detailed explanations for each vulnerability type
- Step-by-step exploit development guides
- Real-world examples and scenarios

### 🔧 **Multi-Platform Support**
- Linux and macOS compatibility
- x86_64, ARM64, i386 architecture support
- Automatic compilation and test scripts

### 🛠️ **Advanced Tools**
- Interactive exploit menu
- Automatic vulnerability testing
- Comprehensive error analysis
- Cross-platform compatibility

## Quick Start

### Prerequisites
```bash
# Linux
sudo apt-get update
sudo apt-get install g++ build-essential python3

# macOS
xcode-select --install
brew install python3

# Python packages
pip3 install pwntools
```

### Compilation and Testing
```bash
# Compile the laboratory
./compile_linux.sh

# Test it
./test_lab.sh

# Run in interactive mode
./compiled/$(uname -m)/vulnerable_code

# Run the exploit script
python3 source_code/exploit.py
```

## Vulnerability Analysis

### Buffer Size Calculation Error
```cpp
int size;
std::cin >> size;
if (size < 0) {
    size = (unsigned int)size; // Vulnerability: -1 -> 0xFFFFFFFF
}
read(0, buffer, size); // Buffer overflow!
```

### Arithmetic Overflow
```cpp
int len1, len2;
std::cin >> len1 >> len2;
int total_len = len1 + len2; // Vulnerability: INT_MAX + 1 = negative
if (total_len < 0) {
    // Security check bypassed
}
```

### Array Bounds Bypass
```cpp
int index;
std::cin >> index;
if (index < 0) {
    array[index] = value; // Vulnerability: Negative index
}
```

## Exploit Development

### 1. Buffer Size Exploit
```python
# Input negative value to cause overflow
payload = "1\n-1\n" + "A" * 200 + "\n"
```

### 2. Arithmetic Overflow Exploit
```python
# INT_MAX + 1 to cause overflow
payload = "2\n2147483647\n1\n" + "A" * 100 + "\n"
```

### 3. Array Bounds Exploit
```python
# UINT_MAX to get negative index
payload = "3\n4294967295\n0x41414141\n"
```

## Defense Mechanisms

### 1. Integer Overflow Check
```cpp
// Safe addition
if (a > INT_MAX - b) {
    // Overflow detected
    return -1;
}
int result = a + b;
```

### 2. Unsigned Cast Check
```cpp
// Safe cast
if (size < 0 || size > MAX_SIZE) {
    return -1;
}
unsigned int safe_size = (unsigned int)size;
```

### 3. Array Bounds Check
```cpp
// Safe index check
if (index < 0 || index >= array_size) {
    return -1;
}
array[index] = value;
```

## Learning Objectives

This laboratory enables participants to:

1. **Integer Overflow Types:** Understand various integer overflow vulnerabilities
2. **Vulnerability Analysis:** Detect integer vulnerabilities
3. **Exploit Development:** Write integer overflow exploits
4. **Defense Techniques:** Learn secure integer operations
5. **Debugging:** Debug integer vulnerabilities

## GDB Debugging

### Basic Commands
```bash
# Run program in debug mode
gdb ./compiled/$(uname -m)/vulnerable_code

# Set breakpoint
(gdb) break vulnerable_function_1

# Examine variables
(gdb) print size
(gdb) print (unsigned int)size

# View memory layout
(gdb) x/20x $rsp
```

### Integer Overflow Analysis
```bash
# Track arithmetic operations
(gdb) watch total_len
(gdb) print len1 + len2

# Examine cast operations
(gdb) print (unsigned int)-1
(gdb) print (int)0xFFFFFFFF
```

## Test Scenarios

### 1. Basic Functionality
```bash
echo "6" | ./compiled/$(uname -m)/vulnerable_code
```

### 2. Buffer Size Overflow
```bash
echo -e "1\n-1\nAAAA" | ./compiled/$(uname -m)/vulnerable_code
```

### 3. Arithmetic Overflow
```bash
echo -e "2\n2147483647\n1\nAAAA\nBBBB" | ./compiled/$(uname -m)/vulnerable_code
```

### 4. Array Bounds Bypass
```bash
echo -e "3\n4294967295\n0x41414141" | ./compiled/$(uname -m)/vulnerable_code
```

## Security Warning

⚠️ **IMPORTANT:** This laboratory is for educational purposes only. The techniques should:
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
- **GitHub:** [CyberLabs Repository](https://github.com/alicangonullu/CyberLabs)
- **Email:** alicangonullu@yahoo.com

## Acknowledgments

This project was developed with contributions from the cybersecurity community, especially:
- OWASP community
- Exploit Database (ExploitDB)
- Pwntools developers
- GDB and LLVM projects

---

**Note:** This laboratory is continuously updated. Follow the GitHub repository for the latest version.
