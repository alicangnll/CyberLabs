#include <cstdio>
#include <cstdlib>

void basariMesaji() {
    printf(">>> KONTROL ELE GECIRILDI! Zafiyet basariyla istismar edildi.\n");
}

typedef struct {
    char kullaniciVerisi[100];
    void (*islemYapPtr)();
} Session;

int main() {
    fprintf(stderr, "Use-After-Free Lab basladi.\n");
    Session* ses = (Session*)malloc(sizeof(Session));
    fflush(stdout);
    fread(ses->kullaniciVerisi, 1, 108, stdin);
    if (ses && ses->islemYapPtr) {
        ses->islemYapPtr();
    }
    return 0;
}
