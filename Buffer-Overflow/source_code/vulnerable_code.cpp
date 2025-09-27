// vuln_stdin.cpp
#include <iostream>
#include <unistd.h> // read fonksiyonu için

// Amacımız, programın akışını bu fonksiyona yönlendirmek.
void win_function() {
    // Python betiğinin yakalayabilmesi için özel bir başarı mesajı yazdırıyoruz.
    std::cout << "\n--- Zafiyet Basariyla Somuruldu! ---\n" << std::endl;
}

// Zafiyeti barındıran fonksiyon
void vulnerable_function() {
    char buffer[64]; // Sadece 64 byte'lık bir arabellek

    std::cout << "Payload bekleniyor..." << std::endl;
    
    // ZAFİYET: Standart girdiden (stdin) 256 byte'a kadar veri okunuyor.
    // 64 byte'lık buffer'a sığmayacağı için yığın taşması meydana gelecek.
    // Bu kasıtlı bir zafiyettir - compiler warning'ini bastırıyoruz
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wstringop-overflow"
    read(0, buffer, 256);
    #pragma GCC diagnostic pop
}

int main() {
    vulnerable_function();
    return 0;
}