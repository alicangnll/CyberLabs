#!/bin/bash

echo "=== CyberLabs - All Labs Test Script ==="
echo ""

# Function to test a lab
test_lab() {
    local lab_name=$1
    local lab_dir=$2
    
    echo "=========================================="
    echo "Testing $lab_name Lab"
    echo "=========================================="
    
    if [ -d "$lab_dir" ]; then
        cd "$lab_dir"
        if [ -f "test_lab.sh" ]; then
            ./test_lab.sh
        else
            echo "[-] test_lab.sh not found in $lab_dir"
        fi
        cd ..
    else
        echo "[-] Lab directory $lab_dir not found"
    fi
    
    echo ""
}

# Test all labs
test_lab "Buffer-Overflow" "Buffer-Overflow"
test_lab "Double-Free" "Double-Free"
test_lab "Heap-Overflow" "Heap-Overflow"
test_lab "Memory-Leak" "Memory-Leak"
test_lab "Use-After-Free" "Use-After-Free"

echo "=========================================="
echo "All Labs Test Complete"
echo "=========================================="
echo ""
echo "Summary:"
echo "- Buffer-Overflow: Stack buffer overflow exploitation"
echo "- Double-Free: Heap double-free and use-after-free exploitation"
echo "- Heap-Overflow: Heap overflow exploitation"
echo "- Memory-Leak: Memory leak DoS exploitation"
echo "- Use-After-Free: Use-after-free exploitation"
echo ""
echo "Each lab includes:"
echo "- compile_linux.sh: Linux compilation script"
echo "- test_lab.sh: Lab testing script"
echo "- source_code/: Source code and exploits"
echo "- compiled/: Compiled binaries"
echo ""
echo "To run individual labs:"
echo "  cd <lab-name> && ./test_lab.sh"
echo ""
echo "To compile for Linux:"
echo "  cd <lab-name> && ./compile_linux.sh"
