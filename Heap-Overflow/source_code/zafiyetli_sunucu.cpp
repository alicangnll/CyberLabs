#include <iostream>
#include <cstdio>
#include <cstring>

// Saldırganın çalıştırmayı hedeflediği fonksiyon.
void basariMesaji() {
    std::cout << ">>> KONTROL ELE GECIRILDI!" << std::endl;
}

// Normalde çalışması gereken meşru fonksiyon.
void normalIslem() {
    std::cout << ">>> Normal islem gerceklestirildi." << std::endl;
}


struct KullaniciVerisi {
    char kullanici_adi[40];
    void (*yetki_kontrol_func)();
};

int main() {
    std::cerr << "[KURBAN] Direkt Heap Overflow programi baslatildi." << std::endl;

    // 1. Bellek HEAP üzerinde tahsis ediliyor.
    KullaniciVerisi *kullanici = new KullaniciVerisi();
    kullanici->yetki_kontrol_func = normalIslem;
    std::cerr << "Kullanici adinizi girin: ";
    scanf("%s", kullanici->kullanici_adi);

    if (kullanici && kullanici->yetki_kontrol_func) {
        kullanici->yetki_kontrol_func();
    }
    delete kullanici;
    return 0;
}
