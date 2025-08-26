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

