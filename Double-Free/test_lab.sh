#!/bin/bash

echo "=== Double-Free Lab Test Script ==="
echo ""

# Check if compiled binary exists
if [ ! -f "compiled/vulnerable_code" ]; then
    echo "[-] Compiled binary not found. Compiling..."
    
    # Create compiled directory if it doesn't exist
    mkdir -p compiled
    
    # Detect OS and set appropriate flags
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "[+] Detected Linux, using Linux-specific flags"
        g++ -std=c++11 -o compiled/vulnerable_code source_code/vulnerable_code.cpp -no-pie -Wno-unused-result -Wno-stringop-overflow -static-libgcc -static-libstdc++
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "[+] Detected macOS, using macOS-specific flags"
        g++ -std=c++11 -o compiled/vulnerable_code source_code/vulnerable_code.cpp -no-pie -Wno-unused-result -Wno-stringop-overflow
    else
        echo "[+] Unknown OS, using generic flags"
        g++ -std=c++11 -o compiled/vulnerable_code source_code/vulnerable_code.cpp -Wno-unused-result
    fi
    
    if [ $? -ne 0 ]; then
        echo "[-] Compilation failed!"
        exit 1
    fi
    echo "[+] Compilation successful!"
fi

echo "[+] Testing vulnerable program..."
echo ""

# Test 1: Basic functionality
echo "Test 1: Basic functionality"
echo "alloc" | ./compiled/vulnerable_code | grep -q "alloc idx=0" && echo "[+] Basic alloc works" || echo "[-] Basic alloc failed"

echo ""

# Test 2: Double-free vulnerability
echo "Test 2: Double-free vulnerability (should not crash)"
echo -e "alloc\nfree 0\nfree 0\nquit" | ./compiled/vulnerable_code > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "[+] Double-free vulnerability confirmed (no crash)"
else
    echo "[-] Double-free test failed"
fi

echo ""

# Test 3: Exploit script
echo "Test 3: Running exploit script..."
if command -v python3 &> /dev/null; then
    if python3 -c "import pwn" 2>/dev/null; then
        echo "Running exploit..."
        python3 source_code/exploit.py 2>&1 | grep -q "Exploit completed" && echo "[+] Exploit script runs successfully!" || echo "[-] Exploit script failed"
    else
        echo "[-] pwntools not installed. Install with: pip3 install pwntools"
    fi
else
    echo "[-] Python3 not found"
fi

echo ""
echo "=== Lab Test Complete ==="
