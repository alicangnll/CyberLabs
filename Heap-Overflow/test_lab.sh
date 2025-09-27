#!/bin/bash

echo "=== Heap-Overflow Lab Test Script ==="
echo ""

# Check if compiled binary exists
if [ ! -f "compiled/zafiyetli_sunucu" ]; then
    echo "[-] Compiled binary not found. Compiling..."
    
    # Create compiled directory if it doesn't exist
    mkdir -p compiled
    
    # Detect OS and set appropriate flags
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "[+] Detected Linux, using Linux-specific flags"
        g++ -o compiled/zafiyetli_sunucu source_code/zafiyetli_sunucu.cpp -no-pie -g -fno-stack-protector
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "[+] Detected macOS, using macOS-specific flags"
        g++ -o compiled/zafiyetli_sunucu source_code/zafiyetli_sunucu.cpp -no-pie -g -fno-stack-protector
    else
        echo "[+] Unknown OS, using generic flags"
        g++ -o compiled/zafiyetli_sunucu source_code/zafiyetli_sunucu.cpp -g
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
echo "test" | ./compiled/zafiyetli_sunucu > /dev/null 2>&1
if [ $? -eq 0 ] || [ $? -eq 139 ]; then  # 139 is SIGSEGV, expected
    echo "[+] Basic program execution works"
else
    echo "[-] Basic program execution failed"
fi

echo ""

# Test 2: Heap overflow vulnerability
echo "Test 2: Heap overflow vulnerability (should cause segfault)"
echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" | ./compiled/zafiyetli_sunucu > /dev/null 2>&1
if [ $? -eq 139 ]; then
    echo "[+] Heap overflow vulnerability confirmed (segfault as expected)"
else
    echo "[-] Heap overflow test failed or unexpected behavior"
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
    TARGET_ADDR=$(objdump -d compiled/zafiyetli_sunucu | grep "basariMesaji" | head -1 | cut -d' ' -f1)
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

# Test 5: Create test payload
echo "Test 5: Creating test payload..."
if command -v python3 &> /dev/null; then
    python3 -c 'with open("compiled/test_payload.bin", "wb") as f: f.write(b"A" * 43)' 2>/dev/null
    if [ -f "compiled/test_payload.bin" ]; then
        echo "[+] Test payload created successfully"
    else
        echo "[-] Failed to create test payload"
    fi
else
    echo "[-] Python3 not found, cannot create test payload"
fi

echo ""
echo "=== Lab Test Complete ==="
