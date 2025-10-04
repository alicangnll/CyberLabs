#!/bin/bash

echo "=== Linux Compilation Script for Integer-Overflow Lab ==="
echo ""

# Detect architecture and OS, set appropriate flags
ARCH=$(uname -m)
OS=$(uname -s)
ARCH_DIR="compiled/${ARCH}"

# Check compatibility for Integer Overflow lab
echo "[+] Checking system compatibility for Integer Overflow lab..."

# Integer overflow works on most architectures
if [[ "$OS" == "Linux" && "$ARCH" == "x86_64" ]]; then
    echo "[+] ✅ Optimal: Linux x86_64 - Full integer overflow support"
elif [[ "$OS" == "Darwin" && "$ARCH" == "x86_64" ]]; then
    echo "[+] ✅ Good: macOS x86_64 - Full integer overflow support"
elif [[ "$OS" == "Linux" && "$ARCH" == "aarch64" ]]; then
    echo "[+] ✅ Good: Linux ARM64 - Full integer overflow support"
elif [[ "$OS" == "Darwin" && "$ARCH" == "arm64" ]]; then
    echo "[+] ✅ Good: macOS ARM64 - Full integer overflow support"
elif [[ "$OS" == "Linux" && "$ARCH" == "i386" ]]; then
    echo "[+] ✅ Good: Linux i386 - Full integer overflow support"
elif [[ "$OS" == "Linux" && "$ARCH" == "i686" ]]; then
    echo "[+] ✅ Good: Linux i686 - Full integer overflow support"
else
    echo "[+] ⚠️  Limited: $OS $ARCH - Integer overflow may behave differently"
    echo "[+] Continuing with limited functionality..."
fi

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
    elif [[ "$ARCH" == "i386" || "$ARCH" == "i686" ]]; then
        echo "[+] Detected Linux i386/i686, using i386-specific flags"
        COMPILE_FLAGS="-m32 -fno-stack-protector -no-pie -Wno-stringop-overflow -Wno-unused-result"
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

# Compile with architecture-specific flags for integer overflow
echo "[+] Compiling vulnerable_code.cpp for $OS $ARCH (Integer Overflow)..."
echo "[+] Target directory: $ARCH_DIR"
g++ $COMPILE_FLAGS -o "$ARCH_DIR/vulnerable_code" source_code/vulnerable_code.cpp

if [ $? -eq 0 ]; then
    echo "[+] Compilation successful!"
    echo "[+] Binary created: $ARCH_DIR/vulnerable_code"
    
    # Make it executable
    chmod +x "$ARCH_DIR/vulnerable_code"
    
    # Test the binary
    echo ""
    echo "[+] Testing the compiled binary..."
    echo "6" | ./$ARCH_DIR/vulnerable_code > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "[+] Binary works correctly!"
    else
        echo "[-] Binary test failed"
    fi
    
    # Get target function address
    echo ""
    echo "[+] Finding target function address..."
    TARGET_ADDR=$(objdump -d "$ARCH_DIR/vulnerable_code" | grep "win_function" | head -1 | cut -d' ' -f1)
    if [ ! -z "$TARGET_ADDR" ]; then
        echo "[+] Target function address: 0x$TARGET_ADDR"
        echo "[+] Update exploit.py with this address if needed"
    else
        echo "[-] Could not find target function address"
    fi
    
    # Show integer overflow examples
    echo ""
    echo "[+] Integer Overflow Examples:"
    echo "  - Buffer size: -1 (becomes 0xFFFFFFFF)"
    echo "  - Arithmetic: 2147483647 + 1 (INT_MAX + 1)"
    echo "  - Array index: 4294967295 (UINT_MAX, becomes -1)"
    echo "  - Multiplication: 65537 * 65537 (overflow)"
    echo "  - Subtraction: 10 - 5 (underflow)"
    
else
    echo "[-] Compilation failed!"
    echo ""
    echo "Common issues and solutions:"
    echo "1. Install g++: sudo apt-get install g++"
    echo "2. Install build-essential: sudo apt-get install build-essential"
    echo "3. For 32-bit on 64-bit: sudo apt-get install gcc-multilib g++-multilib"
    echo "4. For macOS: xcode-select --install"
    exit 1
fi

echo ""
echo "=== Compilation Complete ==="
echo "You can now run: python3 source_code/exploit.py"
echo "Note: You may need to update the target address in exploit.py"
echo ""
echo "Architecture-specific binary location:"
echo "  $ARCH_DIR/vulnerable_code"
echo ""
echo "Integer Overflow Lab Features:"
echo "  - 5 different integer overflow vulnerabilities"
echo "  - Interactive exploit menu"
echo "  - Educational examples with explanations"
echo "  - Cross-platform compatibility"
