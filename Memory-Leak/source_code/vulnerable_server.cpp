#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <cstring>

// Flag to be leaked
const char* SECRET_FLAG = "FLAG: sybercode_are_the_best";

/**
 * @brief Her çağrıldığında 64 byte'lık bellek sızdırır ve flag'i yazar.
 */
void vulnerable_func() {
    // C++'ın 'new[]' operatörü ile heap üzerinde 64 byte'lık yer ayır.
    char* ptr = new char[64];
    
    // Ayrılan belleğe flag'i yaz.
    if (ptr != nullptr) {
        strncpy(ptr, SECRET_FLAG, 63);
        ptr[63] = '\0'; // Null terminator
    }

    // HATA: 'new[]' ile ayrılan bu belleğin 'delete[] ptr;' ile
    // serbest bırakılması gerekirdi. Bu satırın olmaması zafiyete neden olur.
}

/**
 * @brief Ana program döngüsü.
 */
int main() {
    // std::cerr kullanarak hata/bilgi akışına yazdırıyoruz.
    std::cerr << "[KURBAN] C++ Bellek Sızdırma Programı Başladı." << std::endl;
    std::cerr << "Saldırgan betikten sinyal bekleniyor..." << std::endl;
    
    // Python'dan sürekli karakter/sinyal bekle.
    // Akış sonlanana kadar (EOF) döngü devam eder.
    while (std::cin.get() != EOF) {
        vulnerable_func();
    }

    return 0;
}
