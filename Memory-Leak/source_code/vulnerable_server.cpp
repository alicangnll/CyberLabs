#include <iostream>
#include <cstdlib> // Gerekli değilse de standart olarak eklenir
#include <unistd.h> // getpid() fonksiyonu için (Linux/macOS)

/**
 * @brief Her çağrıldığında 10 byte'lık bellek sızdırır.
 */
void vulnerable_func() {
    // C++'ın 'new[]' operatörü ile heap üzerinde 10 byte'lık yer ayır.
    char* ptr = new char[10];
    
    // Ayrılan belleğe bir işlem yapılıyormuş gibi göstermek için.
    if (ptr != nullptr) {
        ptr[0] = 'L';
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
