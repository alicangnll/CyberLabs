#include <cstdio>
#include <cstddef> // C++'ta offsetof için

// Zafiyetli programdaki struct'ın aynısı
typedef struct {
    char kullaniciVerisi[100];
    void (*islemYapPtr)();
} Session;

int main() {
    printf("Boyut (sizeof(Session)): %zu byte\n", sizeof(Session));
    printf("islemYapPtr'nin baslangic konumu (offsetof): %zu byte\n", offsetof(Session, islemYapPtr));
    return 0;
}
