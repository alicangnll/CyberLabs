#!/bin/bash

echo "=== Linux Compilation Script for Heap-Overflow Lab ==="
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

# Compile with Linux-specific flags for heap overflow
echo "[+] Compiling zafiyetli_sunucu.cpp for Linux (Heap Overflow)..."
g++ -o compiled/zafiyetli_sunucu source_code/zafiyetli_sunucu.cpp -no-pie -g -fno-stack-protector

if [ $? -eq 0 ]; then
    echo "[+] Compilation successful!"
    echo "[+] Binary created: compiled/zafiyetli_sunucu"
    
    # Make it executable
    chmod +x compiled/zafiyetli_sunucu
    
    # Test the binary
    echo ""
    echo "[+] Testing the compiled binary..."
    echo "test" | ./compiled/zafiyetli_sunucu > /dev/null 2>&1
    if [ $? -eq 0 ] || [ $? -eq 139 ]; then  # 139 is SIGSEGV, expected for heap overflow
        echo "[+] Binary works correctly!"
    else
        echo "[-] Binary test failed"
    fi
    
    # Get target function address
    echo ""
    echo "[+] Finding target function address..."
    TARGET_ADDR=$(objdump -d compiled/zafiyetli_sunucu | grep "basariMesaji" | head -1 | cut -d' ' -f1)
    if [ ! -z "$TARGET_ADDR" ]; then
        echo "[+] Target function address: 0x$TARGET_ADDR"
        echo "[+] Update exploit.py with this address if needed"
    else
        echo "[-] Could not find target function address"
    fi
    
    # Create test payload
    echo ""
    echo "[+] Creating test payload..."
    python3 -c 'with open("compiled/test_payload.bin", "wb") as f: f.write(b"A" * 43)' 2>/dev/null || echo "[-] Could not create test payload"
    
else
    echo "[-] Compilation failed!"
    echo ""
    echo "Common issues and solutions:"
    echo "1. Install g++: sudo apt-get install g++"
    echo "2. Install build-essential: sudo apt-get install build-essential"
    echo "3. For heap overflow issues, check ASLR: echo 0 | sudo tee /proc/sys/kernel/randomize_va_space"
    exit 1
fi

echo ""
echo "=== Compilation Complete ==="
echo "You can now run: python3 source_code/exploit.py"
echo "Note: You may need to update the target address in exploit.py"
