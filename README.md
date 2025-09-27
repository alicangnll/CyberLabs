# CyberLabs: Bellek Zafiyetleri Laboratuvarı

**Platform:** CyberLabs Eğitim Sistemi  
**Seviye:** Başlangıç - İleri  
**Konu:** Bellek Bozulması Zafiyetleri ve Sömürü Teknikleri

## Genel Bakış

CyberLabs Bellek Zafiyetleri Laboratuvarı, siber güvenlik uzmanlarının bellek bozulması zafiyetlerini anlamaları ve sömürü tekniklerini öğrenmeleri için tasarlanmış kapsamlı bir eğitim platformudur. Bu platform, gerçek dünyadaki zafiyetleri simüle eden interaktif laboratuvarlar içerir.

## Laboratuvarlar

### 1. Buffer-Overflow Lab
**Modül Kodu:** CL-MEM-001  
**Seviye:** Başlangıç  
**Konu:** Stack Buffer Overflow

- Stack-based buffer overflow zafiyetlerini anlama
- Return address manipülasyonu
- Shellcode yazma ve çalıştırma
- Stack canary bypass teknikleri

### 2. Double-Free Lab
**Modül Kodu:** CL-MEM-006  
**Seviye:** İleri  
**Konu:** Heap Double-Free ve Use-After-Free

- Özel heap yöneticisindeki tasarım hataları
- Double-free zafiyetlerinin sömürülmesi
- Use-After-Free (UAF) saldırıları
- Freelist poisoning teknikleri

### 3. Heap-Overflow Lab
**Modül Kodu:** CL-MEM-003  
**Seviye:** Orta  
**Konu:** Heap Buffer Overflow

- Heap-based buffer overflow zafiyetleri
- Heap metadata manipülasyonu
- Heap spraying teknikleri
- Heap feng shui

### 4. Memory-Leak Lab
**Modül Kodu:** CL-MEM-004  
**Seviye:** Başlangıç  
**Konu:** Memory Leak ve DoS

- Bellek sızıntısı zafiyetlerini tespit etme
- Resource exhaustion saldırıları
- Memory monitoring araçları
- DoS (Denial of Service) teknikleri

### 5. Use-After-Free Lab
**Modül Kodu:** CL-MEM-005  
**Seviye:** İleri  
**Konu:** Use-After-Free Exploitation

- Use-After-Free zafiyetlerinin analizi
- Heap layout manipülasyonu
- Function pointer hijacking
- Advanced heap exploitation

### 6. ROP-Vulnerability Lab
**Modül Kodu:** CL-MEM-007  
**Seviye:** İleri  
**Konu:** Return-Oriented Programming

- ROP (Return-Oriented Programming) teknikleri
- NX bit bypass yöntemleri
- Gadget bulma ve chain oluşturma
- Shellcode enjeksiyonu
- Platform-specific ROP (Linux x86_64, macOS ARM64)

## Özellikler

### 🎯 **Eğitim Odaklı Tasarım**
- Her laboratuvar gerçek dünyadaki zafiyetleri simüle eder
- Adım adım açıklamalar ve detaylı dokümantasyon
- GDB ile interaktif debugging rehberleri

### 🔧 **Çoklu Platform Desteği**
- Linux ve macOS uyumluluğu
- Otomatik derleme script'leri
- Platform-specific optimizasyonlar

### 🛠️ **Gelişmiş Araçlar**
- Otomatik adres bulma sistemleri
- Pwntools entegrasyonu
- Kapsamlı test suite'leri
- Memory monitoring araçları
- İki farklı zorluk seviyesi (Kolay/Zor)

### 📚 **Kapsamlı Dokümantasyon**
- Türkçe ve İngilizce README dosyaları
- Detaylı kod açıklamaları
- GDB debugging rehberleri
- Exploit development tutorial'ları

## Hızlı Başlangıç

### Gereksinimler
```bash
# Linux
sudo apt-get update
sudo apt-get install g++ build-essential libc6-dev python3 python3-pip

# macOS
xcode-select --install
brew install python3

# Python paketleri
pip3 install pwntools
```

### Zorluk Seviyeleri

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

### Tüm Laboratuvarları Test Etme
```bash
# Tüm lab'ları test et
./test_all_labs.sh

# Belirli bir lab'ı test et
cd Buffer-Overflow && ./test_lab.sh
cd Double-Free && ./test_lab.sh
cd Heap-Overflow && ./test_lab.sh
cd Memory-Leak && ./test_lab.sh
cd Use-After-Free && ./test_lab.sh
cd ROP-Vulnerability && ./test_lab.sh
```

### Linux için Derleme
```bash
# Tüm lab'ları Linux için derle
for lab in */; do
    cd "$lab"
    if [ -f "compile_linux.sh" ]; then
        ./compile_linux.sh
    fi
    cd ..
done
```

## Laboratuvar Yapısı

Her laboratuvar aşağıdaki yapıya sahiptir:

```
Lab-Name/
├── README.md              # Türkçe dokümantasyon
├── README_EN.md           # İngilizce dokümantasyon
├── compile_linux.sh       # Linux derleme script'i
├── test_lab.sh           # Test script'i
├── source_code/          # Kaynak kodlar
│   ├── vulnerable_code.cpp
│   └── exploit.py
└── compiled/             # Derlenmiş binary'ler
    └── vulnerable_code
```

## Eğitim Hedefleri

Bu platform ile katılımcılar:

1. **Bellek Yönetimi:** C/C++ programlarda bellek yönetimini anlayacak
2. **Zafiyet Analizi:** Çeşitli bellek zafiyetlerini tespit edebilecek
3. **Exploit Development:** Temel ve ileri seviye exploit tekniklerini öğrenecek
4. **Debugging:** GDB ve diğer araçlarla debugging yapabilecek
5. **Güvenlik:** Savunma mekanizmalarını anlayacak

## Disclaimer / Yasal Uyarı

Bu laboratuvar içeriği, tamamen **CyberLabs eğitim ortamı** için tasarlanmıştır. Buradaki bilgi ve kodların amacı, siber güvenlik uzmanlarının savunma mekanizmalarını daha iyi anlamalarına ve zafiyet analizi yeteneklerini geliştirmelerine yardımcı olmaktır.

### Yasak Kullanımlar
- CyberLabs eğitim ortamı dışında kullanım
- Yasa dışı faaliyetler veya yetkisiz sistem erişimi
- Gerçek sistemlerin kötü niyetli sömürülmesi
- Eğitim dışı amaçlarla dağıtım

### Sorumluluk
Bu materyallerin CyberLabs ortamı dışında veya yasa dışı amaçlarla kullanılması kesinlikle yasaktır ve tüm sorumluluk kullanıcıya aittir. Yazarlar ve CyberLabs, bu eğitim materyallerinin kötüye kullanımından sorumlu değildir.

## Güvenlik Uyarısı

⚠️ **ÖNEMLİ:** Bu laboratuvarlar sadece eğitim amaçlıdır. Bu tekniklerin:
- Yasal olmayan amaçlarla kullanılması yasaktır
- Kendi sistemlerinizde test etmeniz önerilir
- Gerçek sistemlerde kullanmadan önce izin alın
- Etik hacking prensiplerine uygun kullanın

## Katkıda Bulunma

Bu proje açık kaynaklıdır ve katkılarınızı bekliyoruz:

1. Fork yapın
2. Feature branch oluşturun (`git checkout -b feature/AmazingFeature`)
3. Commit yapın (`git commit -m 'Add some AmazingFeature'`)
4. Push yapın (`git push origin feature/AmazingFeature`)
5. Pull Request oluşturun

## Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için `LICENSE` dosyasına bakın.

## İletişim

- **Proje Sahibi:** CyberLabs Eğitim Ekibi
- **GitHub:** [CyberLabs Repository](https://github.com/cyberlabs/memory-vulnerabilities)
- **E-posta:** education@cyberlabs.com

## Teşekkürler

Bu proje, siber güvenlik topluluğunun katkılarıyla geliştirilmiştir. Özellikle:
- OWASP topluluğu
- Exploit Database (ExploitDB)
- Pwntools geliştiricileri
- GDB ve LLVM projeleri

---

**Not:** Bu laboratuvarlar sürekli güncellenmektedir. En son sürümü için GitHub repository'sini takip edin.
