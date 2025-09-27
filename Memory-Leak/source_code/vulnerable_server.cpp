#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <cstring>

const char* SECRET_FLAG = "FLAG: sybercode_are_the_best";

void vulnerable_func() {
    char* ptr = new char[64];
    
    if (ptr != nullptr) {
        strncpy(ptr, SECRET_FLAG, 63);
        ptr[63] = '\0';
    }
}

int main() {
    std::cerr << "Memory Leak Lab basladi." << std::endl;
    
    while (std::cin.get() != EOF) {
        vulnerable_func();
    }

    return 0;
}
