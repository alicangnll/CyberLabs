#!/bin/bash

echo "=== Buffer-Overflow Lab Test Script ==="
echo ""

# Check if compiled binary exists
if [ ! -f "compiled/vulnerable_code" ]; then
    echo "[-] Compiled binary not found. Compiling..."
    
    # Detect OS and set appropriate flags
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "[+] Detected Linux, using Linux-specific flags"
        g++ -m64 -fno-stack-protector -z execstack -no-pie -o compiled/vulnerable_code source_code/vulnerable_code.cpp
        # Enable execstack if needed
        if command -v execstack &> /dev/null; then
            execstack -c compiled/vulnerable_code 2>/dev/null || true
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "[+] Detected macOS, using macOS-specific flags"
        g++ -m64 -fno-stack-protector -o compiled/vulnerable_code source_code/vulnerable_code.cpp
    else
        echo "[+] Unknown OS, using generic flags"
        g++ -m64 -o compiled/vulnerable_code source_code/vulnerable_code.cpp
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
echo "test" | ./compiled/vulnerable_code > /dev/null 2>&1
if [ $? -eq 0 ] || [ $? -eq 139 ]; then  # 139 is SIGSEGV, expected
    echo "[+] Basic program execution works"
else
    echo "[-] Basic program execution failed"
fi

echo ""

# Test 2: Buffer overflow vulnerability
echo "Test 2: Buffer overflow vulnerability (should cause segfault)"
echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" | ./compiled/vulnerable_code > /dev/null 2>&1
if [ $? -eq 139 ]; then
    echo "[+] Buffer overflow vulnerability confirmed (segfault as expected)"
else
    echo "[-] Buffer overflow test failed or unexpected behavior"
fi

echo ""

# Test 3: Exploit script
echo "Test 3: Running exploit script..."
if command -v python3 &> /dev/null; then
    echo "Running exploit..."
    python3 source_code/exploit.py > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "[+] Exploit script runs successfully!"
    else
        echo "[-] Exploit script failed (this may be normal if target address needs updating)"
    fi
else
    echo "[-] Python3 not found"
fi

echo ""

# Test 4: Get target function address
echo "Test 4: Finding target function address..."
if command -v objdump &> /dev/null; then
    TARGET_ADDR=$(objdump -d compiled/vulnerable_code | grep "win_function" | head -1 | cut -d' ' -f1)
    if [ ! -z "$TARGET_ADDR" ]; then
        echo "[+] Target function address: 0x$TARGET_ADDR"
        echo "[+] Update exploit.py with this address if needed"
    else
        echo "[-] Could not find target function address"
    fi
else
    echo "[-] objdump not found, cannot determine target address"
fi

echo ""
echo "=== Lab Test Complete ==="
