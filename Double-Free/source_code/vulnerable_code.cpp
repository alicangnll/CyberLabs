#include <iostream>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

// Simple heap allocator structures
struct Chunk {
    Chunk* next;
    char data[120]; // 128 - 8 = 120 bytes for user data
};

// Global variables
Chunk* g_head = nullptr;
Chunk* slots[16] = {nullptr}; // Track allocated chunks
int slot_count = 0;

// Target function pointer for exploitation
struct Target {
    void (*fn)();
} gTarget;

// Win function - our exploitation target
void win() {
    std::cout << "\n[+] Congratulations! You got a shell!" << std::endl;
    std::cout << "[+] This means you successfully exploited the double-free vulnerability!" << std::endl;
    execl("/bin/sh", "/bin/sh", nullptr);
}

// Simple heap allocator
Chunk* my_alloc() {
    if (g_head == nullptr) {
        // No free chunks, allocate new memory
        Chunk* new_chunk = (Chunk*)malloc(sizeof(Chunk));
        if (new_chunk == nullptr) {
            return nullptr;
        }
        new_chunk->next = nullptr;
        memset(new_chunk->data, 0, 120);
        return new_chunk;
    } else {
        // Take from free list
        Chunk* chunk = g_head;
        g_head = g_head->next;
        memset(chunk->data, 0, 120);
        return chunk;
    }
}

// Simple heap deallocator - VULNERABLE!
void my_free(Chunk* c) {
    if (c == nullptr) return;
    
    // VULNERABILITY: No check if chunk is already freed!
    // This allows double-free attacks
    c->next = g_head;
    g_head = c;
}

// Find free slot
int find_free_slot() {
    for (int i = 0; i < 16; i++) {
        if (slots[i] == nullptr) {
            return i;
        }
    }
    return -1;
}

// Find slot by chunk pointer
int find_slot_by_chunk(Chunk* chunk) {
    for (int i = 0; i < 16; i++) {
        if (slots[i] == chunk) {
            return i;
        }
    }
    return -1;
}

void print_help() {
    std::cout << "\nAvailable commands:" << std::endl;
    std::cout << "  alloc          - Allocate a new chunk" << std::endl;
    std::cout << "  free <idx>     - Free chunk at index" << std::endl;
    std::cout << "  write <idx> <hex_data> - Write hex data to chunk" << std::endl;
    std::cout << "  read <idx>     - Read data from chunk" << std::endl;
    std::cout << "  call           - Call the target function" << std::endl;
    std::cout << "  help           - Show this help" << std::endl;
    std::cout << "  quit           - Exit program" << std::endl;
}

int main() {
    // Initialize target function pointer
    gTarget.fn = nullptr;
    
    std::cout << "=== Double-Free Vulnerability Lab ===" << std::endl;
    std::cout << "This lab demonstrates double-free and use-after-free vulnerabilities" << std::endl;
    std::cout << "in a custom heap allocator." << std::endl;
    std::cout << "\nType 'help' for available commands." << std::endl;
    
    std::string command;
    while (true) {
        std::cout << "\n> ";
        std::cin >> command;
        
        if (command == "alloc") {
            int slot = find_free_slot();
            if (slot == -1) {
                std::cout << "[-] No free slots available!" << std::endl;
                continue;
            }
            
            Chunk* chunk = my_alloc();
            if (chunk == nullptr) {
                std::cout << "[-] Allocation failed!" << std::endl;
                continue;
            }
            
            slots[slot] = chunk;
            slot_count++;
            std::cout << "[+] alloc idx=" << slot << " ptr=" << (void*)chunk << std::endl;
            
        } else if (command == "free") {
            int idx;
            std::cin >> idx;
            
            if (idx < 0 || idx >= 16 || slots[idx] == nullptr) {
                std::cout << "[-] Invalid index or slot is empty!" << std::endl;
                continue;
            }
            
            Chunk* chunk = slots[idx];
            my_free(chunk);
            // VULNERABILITY: Don't clear the slot pointer!
            // This creates a dangling pointer for use-after-free
            // slots[idx] = nullptr; // This line is missing!
            
            slot_count--;
            std::cout << "[+] free idx=" << idx << " ptr=" << (void*)chunk << std::endl;
            
        } else if (command == "write") {
            int idx;
            std::string hex_data;
            std::cin >> idx >> hex_data;
            
            if (idx < 0 || idx >= 16 || slots[idx] == nullptr) {
                std::cout << "[-] Invalid index or slot is empty!" << std::endl;
                continue;
            }
            
            // Convert hex string to bytes
            if (hex_data.length() % 2 != 0) {
                std::cout << "[-] Hex data length must be even!" << std::endl;
                continue;
            }
            
            Chunk* chunk = slots[idx];
            
            // If hex_data is 16 bytes (8 bytes for pointer + 8 bytes), write to next field first
            if (hex_data.length() == 16) {
                // Write to next field (first 8 bytes)
                for (size_t i = 0; i < 16; i += 2) {
                    std::string byte_str = hex_data.substr(i, 2);
                    unsigned char byte_val = (unsigned char)std::stoi(byte_str, nullptr, 16);
                    ((unsigned char*)&chunk->next)[i/2] = byte_val;
                }
                // Write remaining to data field
                for (size_t i = 16; i < hex_data.length() && i < 240; i += 2) {
                    std::string byte_str = hex_data.substr(i, 2);
                    unsigned char byte_val = (unsigned char)std::stoi(byte_str, nullptr, 16);
                    chunk->data[(i-16)/2] = byte_val;
                }
            } else {
                // Write only to data field
                for (size_t i = 0; i < hex_data.length() && i < 240; i += 2) {
                    std::string byte_str = hex_data.substr(i, 2);
                    unsigned char byte_val = (unsigned char)std::stoi(byte_str, nullptr, 16);
                    chunk->data[i/2] = byte_val;
                }
            }
            
            std::cout << "[+] write idx=" << idx << " data=" << hex_data << std::endl;
            
        } else if (command == "read") {
            int idx;
            std::cin >> idx;
            
            if (idx < 0 || idx >= 16 || slots[idx] == nullptr) {
                std::cout << "[-] Invalid index or slot is empty!" << std::endl;
                continue;
            }
            
            Chunk* chunk = slots[idx];
            std::cout << "[+] read idx=" << idx << " data=";
            for (int i = 0; i < 16; i++) {
                printf("%02x", (unsigned char)chunk->data[i]);
            }
            std::cout << std::endl;
            
        } else if (command == "call") {
            if (gTarget.fn == nullptr) {
                std::cout << "[-] Target function not set!" << std::endl;
                continue;
            }
            
            std::cout << "[+] Calling target function..." << std::endl;
            gTarget.fn();
            
        } else if (command == "help") {
            print_help();
            
        } else if (command == "quit") {
            std::cout << "Goodbye!" << std::endl;
            break;
            
        } else {
            std::cout << "[-] Unknown command: " << command << std::endl;
            std::cout << "Type 'help' for available commands." << std::endl;
        }
    }
    
    return 0;
}