#include <cstdio>
#include <cstdlib>

// Exploit için enjekte edilecek fonksiyon
void basariMesaji() {
    printf(">>> KONTROL ELE GECIRILDI! Zafiyet basariyla istismar edildi.\n");
}

// Zafiyeti barındıran veri yapısı (struct).
typedef struct {
    char kullaniciVerisi[100]; // Dışarıdan veri almak için kullanılacak 100 byte'lık bir buffer alanı.
    void (*islemYapPtr)(); // Programın akışını değiştirmek için üzerine yazılacak olan fonksiyon işaretçisi.
} Session;

// Programın başlangıç noktası.
int main() {
    // Ekrana (standart hata akışına) programın başladığını belirten bir mesaj yazdırır.
    fprintf(stderr, "[KURBAN] Program baslatildi.\n");
    Session* ses = (Session*)malloc(sizeof(Session)); // 'Session' yapısı için heap alanında yer ayırır.
    fflush(stdout);  // Alanı serbest bırakır
    fread(ses->kullaniciVerisi, 1, 108, stdin); // kullaniciVerisi değerini islemYapPtr üzerine yazar
    if (ses && ses->islemYapPtr) {
        // Exploit başarılıysa, bu komut 'basariMesaji' fonksiyonunu çalıştırır.
        ses->islemYapPtr();
    }
    return 0;
}
