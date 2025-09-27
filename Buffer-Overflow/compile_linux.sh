#!/bin/bash

echo "=== Linux Compilation Script for Buffer-Overflow Lab ==="
echo ""

# Check if we're on Linux
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo "[-] This script is for Linux systems only!"
    echo "[-] Current OS: $OSTYPE"
    exit 1
fi

echo "[+] Detected Linux system"
echo ""

# Create compiled directory if it doesn't exist
mkdir -p compiled

# Compile with Linux-specific flags for buffer overflow
echo "[+] Compiling vulnerable_code.cpp for Linux (Buffer Overflow)..."
g++ -m64 -fno-stack-protector -z execstack -no-pie -Wno-stringop-overflow -o compiled/vulnerable_code source_code/vulnerable_code.cpp

if [ $? -eq 0 ]; then
    echo "[+] Compilation successful!"
    echo "[+] Binary created: compiled/vulnerable_code"
    
    # Make it executable
    chmod +x compiled/vulnerable_code
    
    # Test the binary
    echo ""
    echo "[+] Testing the compiled binary..."
    echo "test" | ./compiled/vulnerable_code > /dev/null 2>&1
    if [ $? -eq 0 ] || [ $? -eq 139 ]; then  # 139 is SIGSEGV, expected for buffer overflow
        echo "[+] Binary works correctly!"
    else
        echo "[-] Binary test failed"
    fi
    
    # Get target function address
    echo ""
    echo "[+] Finding target function address..."
    TARGET_ADDR=$(objdump -d compiled/vulnerable_code | grep "win_function" | head -1 | cut -d' ' -f1)
    if [ ! -z "$TARGET_ADDR" ]; then
        echo "[+] Target function address: 0x$TARGET_ADDR"
        echo "[+] Update exploit.py with this address if needed"
    else
        echo "[-] Could not find target function address"
    fi
    
else
    echo "[-] Compilation failed!"
    echo ""
    echo "Common issues and solutions:"
    echo "1. Install g++: sudo apt-get install g++"
    echo "2. Install build-essential: sudo apt-get install build-essential"
    echo "3. For execstack issues, try: sudo apt-get install execstack"
    echo "4. Enable execstack: sudo execstack -c compiled/vulnerable_code"
    exit 1
fi

echo ""
echo "=== Compilation Complete ==="
echo "You can now run: python3 source_code/exploit.py"
echo "Note: You may need to update the target address in exploit.py"
