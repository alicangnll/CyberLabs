#!/bin/bash

echo "=== Linux Compilation Script for Double-Free Lab ==="
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

# Compile with Linux-specific flags
echo "[+] Compiling vulnerable_code.cpp for Linux..."
g++ -std=c++11 -o compiled/vulnerable_code source_code/vulnerable_code.cpp \
    -no-pie \
    -g \
    -Wno-unused-result \
    -Wno-stringop-overflow \
    -static-libgcc \
    -static-libstdc++

if [ $? -eq 0 ]; then
    echo "[+] Compilation successful!"
    echo "[+] Binary created: compiled/vulnerable_code"
    
    # Make it executable
    chmod +x compiled/vulnerable_code
    
    # Test the binary
    echo ""
    echo "[+] Testing the compiled binary..."
    echo "help" | ./compiled/vulnerable_code | grep -q "Available commands" && echo "[+] Binary works correctly!" || echo "[-] Binary test failed"
    
else
    echo "[-] Compilation failed!"
    echo ""
    echo "Common issues and solutions:"
    echo "1. Install g++: sudo apt-get install g++"
    echo "2. Install build-essential: sudo apt-get install build-essential"
    echo "3. For static linking issues, try: sudo apt-get install libc6-dev"
    exit 1
fi

echo ""
echo "=== Compilation Complete ==="
echo "You can now run: python3 source_code/exploit.py"
