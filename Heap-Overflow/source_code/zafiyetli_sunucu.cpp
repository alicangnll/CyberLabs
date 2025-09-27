#include <iostream>
#include <cstdio>
#include <cstring>

void basariMesaji() {
    std::cout << ">>> KONTROL ELE GECIRILDI!" << std::endl;
}

void normalIslem() {
    std::cout << ">>> Normal islem gerceklestirildi." << std::endl;
}


struct KullaniciVerisi {
    char kullanici_adi[40];
    void (*yetki_kontrol_func)();
};

int main() {
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
