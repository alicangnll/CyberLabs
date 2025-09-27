# CyberLabs: Memory Leak (Bellek Sızıntısı) Zafiyeti Laboratuvarı

**Modül Kodu:** CL-MEM-003

**Seviye:** Orta

**Konu:** Kaynak Tüketimi Zafiyetleri (Resource Exhaustion)

## Laboratuvarın Amacı

Bu laboratuvar, CyberLabs eğitim platformu için hazırlanmış olup, sık karşılaşılan kaynak tüketimi zafiyetlerinden biri olan **Memory Leak (Bellek Sızıntısı)** konusunu ele almaktadır. Katılımcıların bu laboratuvar sonunda aşağıdaki yetkinlikleri kazanması hedeflenmektedir:

  - Memory Leak zafiyetinin temel nedenlerini ve Denial of Service (DoS) etkisini anlamak.
  - C++'ta dinamik bellek yönetiminde `new` ve `delete` eşleşmesinin kritik önemini kavramak.
  - `g++` ile C++ programı derlemek.
  - Python ile zafiyeti tetikleyen ve sızdırılan veriyi analiz eden bir betik yazmak.
  - Linux/macOS sistem araçları (`ps`, `watch`, `gdb`) ile bir sürecin bellek kullanımını canlı olarak izleyerek zafiyetin etkisini kanıtlamak.
  - Bellekte sızdırılan hassas veriyi (flag) tespit etme ve analiz etme.

## Disclaimer / Yasal Uyarı

The information provided in this blog post is intended for educational and informational purposes only. It is not intended to encourage or promote any illegal or unethical activities, including hacking, cyberattacks, or any form of unauthorized access to computer systems, networks, or data.

Bu blog yazısında sağlanan bilgiler yalnızca eğitim ve bilgilendirme amaçlıdır. Bilgisayar korsanlığı, siber saldırılar veya bilgisayar sistemlerine, ağlara veya verilere herhangi bir şekilde yetkisiz erişim de dahil olmak üzere herhangi bir yasa dışı veya etik olmayan faaliyeti teşvik etme veya reklamlama amacı taşımaz.

Bu laboratuvar içeriği, tamamen **CyberLabs eğitim ortamı** için tasarlanmıştır. Buradaki bilgi ve kodların amacı, siber güvenlik uzmanlarının savunma mekanizmalarını daha iyi anlamalarına ve zafiyet analizi yeteneklerini geliştirmelerine yardımcı olmaktır. Bu materyallerin CyberLabs ortamı dışında veya yasa dışı amaçlarla kullanılması kesinlikle yasaktır ve tüm sorumluluk kullanıcıya aittir.

## Senaryo

Laboratuvar senaryosu, iki ana bileşenden oluşmaktadır:

1.  `leaky_server.cpp`: İçerisinde kasıtlı olarak bir Memory Leak zafiyeti barındıran, C++ ile yazılmış hedef uygulama.
2.  `trigger_and_log_leak.py`: Zafiyetli uygulamaya sürekli istek göndererek bellek sızıntısını tetikleyen ve programın artan bellek kullanımını bir dosyaya kaydeden Python betiği.

## Kurulum ve Çalıştırma Adımları

### Örnek Kod İncelemesi

Öncelikle zafiyetin incelemesi için kodlarımızı incelememiz gerekiyor lakin bu sefer ben kör bir inceleme yapmayı tercih ediyorum. Yani blackbox (kara kutu) bir incelemede neler yaşarız bunu anlatmak istiyorum. Siz kaynak kodlarına buradan ulaşabilirsiniz.

<img width="638" height="348" alt="resim" src="https://github.com/user-attachments/assets/eaea2d5e-07bf-4785-af59-a818cede16de" />

Öncelikle kodumuzu GDB ile artık klasikleşmiş bir şekilde açıyoruz.

<img width="627" height="471" alt="resim" src="https://github.com/user-attachments/assets/e77b2668-3c36-4692-add1-a93348fb9e0d" />

Bu aşamada daha önce açıkladığımız üzere malloc() ve free() değişkenlerini break ederek bu noktada debugger'ı durdurmamız gerekiyor. Bunu sağlamak için "break malloc" ve "break free" komutlarını kullanmamız gerekiyor.

<img width="692" height="572" alt="resim" src="https://github.com/user-attachments/assets/f3180aa0-8930-48ce-b121-25dfa73c7277" />

İlgili değerleri kullandığımızda malloc değerinin ayrıldığını görüyoruz yani birinci çinkoyu yapıyoruz. Overflow zafiyetlerinden farklı olarak burada bir padding size yok yani burada free() olarak serbest bırakılmamış alanı okumak amacımız.

<img width="681" height="627" alt="resim" src="https://github.com/user-attachments/assets/650083e2-3c6d-408e-8501-6384a7bd0995" />

Ve ikinci çinko ile BINGO değerimizi elde ediyoruz zira "continue" komutunu girdiğimizde free() breakpointine takılmadığını görüyoruz. Bu da alanın serbest bırakılmadığını bize gösteriyor. Bu noktada malloc olduğu lakin free komutunun olmadığı tespitini yaptığımız için bir araç yazmamız gerekiyor. Bunu Python dilinde yazabiliriz. 

```cpp
import subprocess
import time
import sys
import os

VICTIM_PROGRAM = "./vulnerable_server"
```

Öncelikle kütüphaneleri içeriye aktarıyorum ve hedef programın yolunu gösteriyorum.

```cpp
try:
        # Kurban programı bir alt süreç olarak başlatıyoruz.
        p = subprocess.Popen([VICTIM_PROGRAM], stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        print(f"[!] HATA: '{VICTIM_PROGRAM}' bulunamadi. C programını derlediniz mi?")
        sys.exit(1)

    leak_count = 0
    try:
        while True:
            p.stdin.write(b'\n')
            p.stdin.flush()
            leak_count += 1
            if leak_count % 1000 == 0:
                print(f"[*] {leak_count * 10 / 1024:.2f} KB bellek sızdırıldı...")
            time.sleep(0.001) # Sistemi yormamak için çok kısa bir bekleme
    except (KeyboardInterrupt, BrokenPipeError):
        print("\n[*] Tetikleme durduruldu. Kurban program sonlandırılıyor.")
        p.terminate()
```

Şimdi programı başlatıp ne kadar sızıntı olduğunu belirliyorum.

<img width="537" height="613" alt="resim" src="https://github.com/user-attachments/assets/7c3e423f-bcb9-4bf0-8a40-12e34a8ec818" />

Ve verilerin başarıyla dışarıya sızdırıldığını görüyorum. Bu aşamada artık zafiyeti doğruluyor ve sistemde sızıntının yaşandığını doğruluyorum.

Okuduğunuz için teşekkürler. 
