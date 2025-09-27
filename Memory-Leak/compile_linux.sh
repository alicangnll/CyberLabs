#!/bin/bash

echo "=== Linux Compilation Script for Memory-Leak Lab ==="
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

# Compile with Linux-specific flags for memory leak
echo "[+] Compiling vulnerable_server.cpp for Linux (Memory Leak)..."
g++ -o compiled/vulnerable_server source_code/vulnerable_server.cpp -g -static-libgcc -static-libstdc++

if [ $? -eq 0 ]; then
    echo "[+] Compilation successful!"
    echo "[+] Binary created: compiled/vulnerable_server"
    
    # Make it executable
    chmod +x compiled/vulnerable_server
    
    # Test the binary
    echo ""
    echo "[+] Testing the compiled binary..."
    echo "test" | timeout 2 ./compiled/vulnerable_server > /dev/null 2>&1
    if [ $? -eq 0 ] || [ $? -eq 124 ]; then  # 124 is timeout, expected for memory leak
        echo "[+] Binary works correctly!"
    else
        echo "[-] Binary test failed"
    fi
    
    # Show memory leak information
    echo ""
    echo "[+] Memory leak information:"
    echo "    - Each input triggers 10 bytes of memory leak"
    echo "    - Use 'ps' or 'top' to monitor memory usage"
    echo "    - Run exploit.py to trigger the leak"
    
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
echo "Monitor memory usage with: watch -n 1 'ps -p \$(pgrep vulnerable_server) -o %mem,rss,vsz,cmd'"
