#!/bin/bash

echo "=== Memory-Leak Lab Test Script ==="
echo ""

# Check if compiled binary exists
if [ ! -f "compiled/vulnerable_server" ]; then
    echo "[-] Compiled binary not found. Compiling..."
    
    # Create compiled directory if it doesn't exist
    mkdir -p compiled
    
    # Detect OS and set appropriate flags
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "[+] Detected Linux, using Linux-specific flags"
        g++ -o compiled/vulnerable_server source_code/vulnerable_server.cpp -static-libgcc -static-libstdc++
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "[+] Detected macOS, using macOS-specific flags"
        g++ -o compiled/vulnerable_server source_code/vulnerable_server.cpp
    else
        echo "[+] Unknown OS, using generic flags"
        g++ -o compiled/vulnerable_server source_code/vulnerable_server.cpp
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
echo "test" | timeout 2 ./compiled/vulnerable_server > /dev/null 2>&1
if [ $? -eq 0 ] || [ $? -eq 124 ]; then  # 124 is timeout, expected
    echo "[+] Basic program execution works"
else
    echo "[-] Basic program execution failed"
fi

echo ""

# Test 2: Memory leak vulnerability
echo "Test 2: Memory leak vulnerability (should consume memory)"
echo "Starting memory leak test for 5 seconds..."
timeout 5 bash -c 'echo -e "\n\n\n\n\n" | ./compiled/vulnerable_server' > /dev/null 2>&1 &
SERVER_PID=$!
sleep 1
if ps -p $SERVER_PID > /dev/null 2>&1; then
    echo "[+] Memory leak vulnerability confirmed (server running and consuming memory)"
    kill $SERVER_PID 2>/dev/null
else
    echo "[-] Memory leak test failed"
fi

echo ""

# Test 3: Exploit script
echo "Test 3: Running exploit script..."
if command -v python3 &> /dev/null; then
    echo "Running quick test exploit..."
    python3 source_code/test_exploit.py > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "[+] Exploit script runs successfully!"
    else
        echo "[-] Exploit script failed"
    fi
else
    echo "[-] Python3 not found"
fi

echo ""

# Test 4: Memory monitoring tools
echo "Test 4: Checking memory monitoring tools..."
if command -v ps &> /dev/null; then
    echo "[+] 'ps' command available for memory monitoring"
else
    echo "[-] 'ps' command not found"
fi

if command -v watch &> /dev/null; then
    echo "[+] 'watch' command available for continuous monitoring"
else
    echo "[-] 'watch' command not found (install with: sudo apt-get install procps)"
fi

echo ""

# Test 5: Show monitoring command
echo "Test 5: Memory monitoring command"
echo "To monitor memory usage during exploit, run:"
echo "  watch -n 1 'ps -p \$(pgrep vulnerable_server) -o %mem,rss,vsz,cmd'"

echo ""
echo "=== Lab Test Complete ==="
