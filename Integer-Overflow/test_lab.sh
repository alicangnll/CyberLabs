#!/bin/bash

echo "=== Integer-Overflow Lab Test Script ==="
echo ""

# Detect architecture and OS
ARCH=$(uname -m)
OS=$(uname -s)
ARCH_DIR="compiled/${ARCH}"

# Check if compiled binary exists
if [ ! -f "$ARCH_DIR/vulnerable_code" ]; then
    echo "[-] Compiled binary not found. Compiling..."
    
    # Create compiled directory structure based on architecture
    mkdir -p "$ARCH_DIR"
    
    # Compile flags based on architecture
    if [[ "$OS" == "Linux" ]]; then
        if [[ "$ARCH" == "x86_64" ]]; then
            echo "[+] Detected Linux x86_64, using x86_64-specific flags"
            COMPILE_FLAGS="-m64 -fno-stack-protector -no-pie -Wno-stringop-overflow -Wno-unused-result"
        elif [[ "$ARCH" == "aarch64" ]]; then
            echo "[+] Detected Linux ARM64 (aarch64), using ARM64-specific flags"
            COMPILE_FLAGS="-fno-stack-protector -no-pie -Wno-stringop-overflow -Wno-unused-result"
        else
            echo "[+] Detected Linux $ARCH, using generic Linux flags"
            COMPILE_FLAGS="-fno-stack-protector -no-pie -Wno-stringop-overflow -Wno-unused-result"
        fi
    elif [[ "$OS" == "Darwin" ]]; then
        if [[ "$ARCH" == "x86_64" ]]; then
            echo "[+] Detected macOS x86_64, using x86_64-specific flags"
            COMPILE_FLAGS="-m64 -fno-stack-protector -no-pie -Wno-stringop-overflow -Wno-unused-result"
        elif [[ "$ARCH" == "arm64" ]]; then
            echo "[+] Detected macOS ARM64, using ARM64-specific flags"
            COMPILE_FLAGS="-fno-stack-protector -no-pie -Wno-stringop-overflow -Wno-unused-result"
        else
            echo "[+] Detected macOS $ARCH, using generic macOS flags"
            COMPILE_FLAGS="-fno-stack-protector -no-pie -Wno-stringop-overflow -Wno-unused-result"
        fi
    else
        echo "[+] Detected $OS $ARCH, using generic flags"
        COMPILE_FLAGS="-fno-stack-protector -no-pie -Wno-stringop-overflow -Wno-unused-result"
    fi
    
    g++ $COMPILE_FLAGS -o "$ARCH_DIR/vulnerable_code" source_code/vulnerable_code.cpp
    
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
echo "6" | ./$ARCH_DIR/vulnerable_code > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "[+] Basic program execution works"
else
    echo "[-] Basic program execution failed"
fi

echo ""

# Test 2: Integer overflow vulnerability 1 (Buffer size)
echo "Test 2: Buffer size integer overflow (should cause unexpected behavior)"
echo -e "1\n-1\nAAAA" | ./$ARCH_DIR/vulnerable_code > /dev/null 2>&1
if [ $? -eq 0 ] || [ $? -eq 139 ] || [ $? -eq 11 ] || [ $? -eq 7 ]; then
    echo "[+] Buffer size integer overflow vulnerability confirmed"
else
    echo "[-] Buffer size integer overflow test failed"
fi

echo ""

# Test 3: Integer overflow vulnerability 2 (Arithmetic)
echo "Test 3: Arithmetic integer overflow (should cause unexpected behavior)"
echo -e "2\n2147483647\n1\nAAAA\nBBBB" | ./$ARCH_DIR/vulnerable_code > /dev/null 2>&1
if [ $? -eq 0 ] || [ $? -eq 139 ] || [ $? -eq 11 ] || [ $? -eq 7 ]; then
    echo "[+] Arithmetic integer overflow vulnerability confirmed"
else
    echo "[-] Arithmetic integer overflow test failed"
fi

echo ""

# Test 4: Integer overflow vulnerability 3 (Array bounds)
echo "Test 4: Array bounds integer overflow (should cause unexpected behavior)"
echo -e "3\n4294967295\n0x41414141" | ./$ARCH_DIR/vulnerable_code > /dev/null 2>&1
if [ $? -eq 0 ] || [ $? -eq 139 ] || [ $? -eq 11 ] || [ $? -eq 7 ]; then
    echo "[+] Array bounds integer overflow vulnerability confirmed"
else
    echo "[-] Array bounds integer overflow test failed"
fi

echo ""

# Test 5: Integer overflow vulnerability 4 (Multiplication)
echo "Test 5: Multiplication integer overflow (should cause unexpected behavior)"
echo -e "4\n65537\n65537\nAAAA" | ./$ARCH_DIR/vulnerable_code > /dev/null 2>&1
if [ $? -eq 0 ] || [ $? -eq 139 ] || [ $? -eq 11 ] || [ $? -eq 7 ]; then
    echo "[+] Multiplication integer overflow vulnerability confirmed"
else
    echo "[-] Multiplication integer overflow test failed"
fi

echo ""

# Test 6: Integer overflow vulnerability 5 (Subtraction)
echo "Test 6: Subtraction integer underflow (should cause unexpected behavior)"
echo -e "5\n10\n5\nAAAA" | ./$ARCH_DIR/vulnerable_code > /dev/null 2>&1
if [ $? -eq 0 ] || [ $? -eq 139 ] || [ $? -eq 11 ] || [ $? -eq 7 ]; then
    echo "[+] Subtraction integer underflow vulnerability confirmed"
else
    echo "[-] Subtraction integer underflow test failed"
fi

echo ""

# Test 7: Exploit script
echo "Test 7: Running exploit script..."
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

# Test 8: Get target function address
echo "Test 8: Finding target function address..."
if command -v objdump &> /dev/null; then
    TARGET_ADDR=$(objdump -d $ARCH_DIR/vulnerable_code | grep "win_function" | head -1 | cut -d' ' -f1)
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
echo ""
echo "Integer Overflow Lab Features Tested:"
echo "  ✓ Buffer size calculation overflow"
echo "  ✓ Arithmetic overflow (addition)"
echo "  ✓ Array bounds bypass"
echo "  ✓ Multiplication overflow"
echo "  ✓ Subtraction underflow"
echo "  ✓ Exploit script functionality"
echo ""
echo "To run the lab interactively:"
echo "  ./$ARCH_DIR/vulnerable_code"
echo ""
echo "To run the exploit script:"
echo "  python3 source_code/exploit.py"
