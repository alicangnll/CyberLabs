# CyberLabs: Memory Leak Vulnerability Laboratory

**Module Code:** CL-MEM-003

**Level:** Intermediate

**Topic:** Resource Exhaustion Vulnerabilities

## Laboratory Purpose

This laboratory, prepared for the CyberLabs education platform, addresses one of the frequently encountered resource exhaustion vulnerabilities: **Memory Leak**. Participants are expected to gain the following competencies by the end of this laboratory:

  - Understanding the basic causes of Memory Leak vulnerability and its Denial of Service (DoS) effect.
  - Grasping the critical importance of matching `new` and `delete` in dynamic memory management in C++.
  - Compiling C++ programs with `g++`.
  - Writing a Python script that triggers the vulnerability and analyzes leaked data.
  - Proving the impact of the vulnerability by monitoring a process's memory usage live using Linux/macOS system tools (`ps`, `watch`, `gdb`).
  - Detecting and analyzing sensitive data (flag) leaked in memory.

## Disclaimer / Legal Warning

The information provided in this blog post is intended for educational and informational purposes only. It is not intended to encourage or promote any illegal or unethical activities, including hacking, cyberattacks, or any form of unauthorized access to computer systems, networks, or data.

The information provided in this blog post is for educational and informational purposes only. It does not intend to encourage or promote any illegal or unethical activities, including hacking, cyberattacks, or any form of unauthorized access to computer systems, networks, or data.

This laboratory content is designed entirely for the **CyberLabs educational environment**. The purpose of the information and codes here is to help cybersecurity experts better understand defense mechanisms and develop vulnerability analysis capabilities. The use of these materials outside the CyberLabs environment or for illegal purposes is strictly prohibited, and all responsibility belongs to the user.

## Scenario

The laboratory scenario consists of two main components:

1.  `leaky_server.cpp`: Target application written in C++ that intentionally contains a Memory Leak vulnerability.
2.  `trigger_and_log_leak.py`: Python script that continuously sends requests to the vulnerable application to trigger the memory leak and records the program's increasing memory usage to a file.

## Difficulty Levels

## 🟢 **EASY WAY: With Debug Symbols**
```bash
# Add -g flag in test_lab.sh file
g++ -o compiled/vulnerable_server source_code/vulnerable_server.cpp -g -static-libgcc -static-libstdc++
```
- Easier analysis with debug symbols
- `p &variable` commands work in GDB
- Ideal for educational purposes

## 🔴 **HARD WAY: Without Debug Symbols (Default)**
```bash
# Current compilation (no debug symbols)
g++ -o compiled/vulnerable_server source_code/vulnerable_server.cpp -static-libgcc -static-libstdc++
```
- Closer to real world
- Requires `info functions`, `disassemble` commands
- Production binaries don't have debug symbols

## Installation and Execution Steps

### Example Code Analysis

First, we need to examine our codes to analyze the vulnerability, but this time I prefer to do a blind analysis. That is, I want to explain what we experience in a blackbox analysis. You can access the source codes from here.

First, we open our code with GDB in the now classic way.

At this stage, as we explained before, we need to break malloc() and free() variables and stop the debugger at this point. For this, we need to use "break malloc" and "break free" commands.

When we use the relevant values, we see that malloc value is allocated, that is, we make the first check. Unlike overflow vulnerabilities, there is no padding size here, so our goal here is to read the area that is not freed as free().

And we get our BINGO value with the second check, because when we enter the "continue" command, we see that it does not get stuck at the free() breakpoint. This shows us that the area is not freed. At this point, since we detect that malloc exists but there is no free command, we need to write a tool. We can write this in Python language.

```cpp
import subprocess
import time
import sys
import os

VICTIM_PROGRAM = "./vulnerable_server"
```

First, I import the libraries and show the path of the target program.

```cpp
try:
        # We start the victim program as a subprocess.
        p = subprocess.Popen([VICTIM_PROGRAM], stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        print(f"[!] ERROR: '{VICTIM_PROGRAM}' not found. Did you compile the C program?")
        sys.exit(1)

    leak_count = 0
    try:
        while True:
            p.stdin.write(b'\n')
            p.stdin.flush()
            leak_count += 1
            if leak_count % 1000 == 0:
                print(f"[*] {leak_count * 10 / 1024:.2f} KB memory leaked...")
            time.sleep(0.001) # Very short wait to not tire the system
    except (KeyboardInterrupt, BrokenPipeError):
        print("\n[*] Triggering stopped. Terminating victim program.")
        p.terminate()
```

Now I start the program and determine how much leakage there is.

And I see that the data is successfully leaked to the outside. At this stage, I verify the vulnerability and confirm that leakage is occurring in the system.

## Linux Compatibility

This lab is designed to work on both Linux and macOS systems:

### Compilation for Linux
```bash
# Special compilation script for Linux
./compile_linux.sh

# Or manual compilation
g++ -o compiled/vulnerable_server source_code/vulnerable_server.cpp -g -static-libgcc -static-libstdc++
```

### Requirements
- **Linux:** `g++`, `build-essential`, `libc6-dev`
- **macOS:** `g++` (Xcode Command Line Tools)
- **Python:** `python3`, `pwntools`

### Testing
```bash
# Run all tests
./test_lab.sh

# Run exploit
python3 source_code/exploit.py
```

### Memory Monitoring
To monitor memory usage during exploit:
```bash
watch -n 1 'ps -p $(pgrep vulnerable_server) -o %mem,rss,vsz,cmd'
```

The exploit automatically detects system architecture and uses the appropriate packing function.
