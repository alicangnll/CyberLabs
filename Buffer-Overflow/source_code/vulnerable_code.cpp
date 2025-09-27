#include <iostream>
#include <unistd.h>

void win_function() {
    std::cout << "\n--- Zafiyet Basariyla Somuruldu! ---\n" << std::endl;
}

void vulnerable_function() {
    char buffer[64];

    std::cout << "Giris yapin: " << std::endl;
    
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wstringop-overflow"
    read(0, buffer, 256);
    #pragma GCC diagnostic pop
}

int main() {
    vulnerable_function();
    return 0;
}