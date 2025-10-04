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

// Integer overflow zafiyeti 2: Aritmetik overflow
void vulnerable_function_2() {
    char buffer[128];
    int len1, len2;
    
    std::cout << "İlk string uzunluğu: ";
    std::cin >> len1;
    std::cout << "İkinci string uzunluğu: ";
    std::cin >> len2;
    
    // Integer overflow: İki pozitif sayının toplamı negatif olabilir
    int total_len = len1 + len2;
    
    if (total_len < 0) {
        std::cout << "Toplam uzunluk negatif! Güvenlik kontrolü atlanıyor..." << std::endl;
        // total_len negatif olduğunda malloc çok büyük bellek ayırır
        char* dynamic_buffer = new char[total_len]; // Integer overflow!
        std::cout << "Dinamik buffer oluşturuldu (boyut: " << total_len << ")" << std::endl;
        delete[] dynamic_buffer;
    } else if (total_len > 200) {
        std::cout << "Çok büyük toplam uzunluk!" << std::endl;
        return;
    }
    
    std::cout << "İlk string girin: ";
    read(0, buffer, len1);
    buffer[len1] = '\0';
    
    std::cout << "İkinci string girin: ";
    read(0, buffer + len1, len2);
    buffer[len1 + len2] = '\0';
    
    std::cout << "Birleştirilmiş string: " << buffer << std::endl;
}

// Integer overflow zafiyeti 3: Array bounds bypass
void vulnerable_function_3() {
    int array[10];
    int index;
    
    std::cout << "Array indeksi girin (0-9): ";
    std::cin >> index;
    
    // Integer overflow: Büyük pozitif sayı girilirse negatif olur
    if (index < 0) {
        std::cout << "Negatif indeks! Güvenlik kontrolü atlanıyor..." << std::endl;
        // index negatif olduğunda array bounds dışına erişim
        array[index] = 0x41414141; // Buffer overflow!
        std::cout << "Array[" << index << "] = " << std::hex << array[index] << std::endl;
    } else if (index >= 10) {
        std::cout << "Geçersiz indeks!" << std::endl;
        return;
    }
    
    std::cout << "Değer girin: ";
    std::cin >> array[index];
    std::cout << "Array[" << index << "] = " << array[index] << std::endl;
}

// Integer overflow zafiyeti 4: Multiplication overflow
void vulnerable_function_4() {
    char buffer[256];
    int width, height;
    
    std::cout << "Genişlik girin: ";
    std::cin >> width;
    std::cout << "Yükseklik girin: ";
    std::cin >> height;
    
    // Integer overflow: İki büyük sayının çarpımı taşabilir
    int total_size = width * height;
    
    if (total_size < 0) {
        std::cout << "Çarpım sonucu negatif! Güvenlik kontrolü atlanıyor..." << std::endl;
        // total_size negatif olduğunda malloc çok büyük bellek ayırır
        char* image_buffer = new char[total_size]; // Integer overflow!
        std::cout << "Image buffer oluşturuldu (boyut: " << total_size << ")" << std::endl;
        delete[] image_buffer;
    } else if (total_size > 1000) {
        std::cout << "Çok büyük boyut!" << std::endl;
        return;
    }
    
    std::cout << "Image verisi girin: ";
    read(0, buffer, total_size);
    buffer[total_size] = '\0';
    
    std::cout << "Image boyutu: " << total_size << " byte" << std::endl;
}

// Integer overflow zafiyeti 5: Subtraction underflow
void vulnerable_function_5() {
    char buffer[100];
    int start, end;
    
    std::cout << "Başlangıç pozisyonu: ";
    std::cin >> start;
    std::cout << "Bitiş pozisyonu: ";
    std::cin >> end;
    
    // Integer underflow: end < start olduğunda negatif sonuç
    int length = end - start;
    
    if (length < 0) {
        std::cout << "Negatif uzunluk! Güvenlik kontrolü atlanıyor..." << std::endl;
        // length negatif olduğunda memcpy çok büyük kopya yapar
        char* temp_buffer = new char[length]; // Integer underflow!
        std::cout << "Temp buffer oluşturuldu (boyut: " << length << ")" << std::endl;
        delete[] temp_buffer;
    } else if (length > 100) {
        std::cout << "Çok büyük uzunluk!" << std::endl;
        return;
    }
    
    std::cout << "Veri girin: ";
    read(0, buffer, length);
    buffer[length] = '\0';
    
    std::cout << "Kopyalanan veri: " << buffer << std::endl;
}

void show_menu() {
    std::cout << "\n=== Integer Overflow Zafiyet Laboratuvarı ===" << std::endl;
    std::cout << "1. Buffer boyutu hesaplama hatası" << std::endl;
    std::cout << "2. Aritmetik overflow (toplama)" << std::endl;
    std::cout << "3. Array bounds bypass" << std::endl;
    std::cout << "4. Multiplication overflow" << std::endl;
    std::cout << "5. Subtraction underflow" << std::endl;
    std::cout << "6. Çıkış" << std::endl;
    std::cout << "Seçiminizi yapın (1-6): ";
}

int main() {
    int choice;
    
    std::cout << "Integer Overflow Zafiyet Laboratuvarına Hoş Geldiniz!" << std::endl;
    std::cout << "Bu laboratuvarda çeşitli integer overflow zafiyetlerini öğreneceksiniz." << std::endl;
    
    while (true) {
        show_menu();
        std::cin >> choice;
        
        switch (choice) {
            case 1:
                vulnerable_function_1();
                break;
            case 2:
                vulnerable_function_2();
                break;
            case 3:
                vulnerable_function_3();
                break;
            case 4:
                vulnerable_function_4();
                break;
            case 5:
                vulnerable_function_5();
                break;
            case 6:
                std::cout << "Çıkış yapılıyor..." << std::endl;
                return 0;
            default:
                std::cout << "Geçersiz seçim!" << std::endl;
                break;
        }
    }
    
    return 0;
}
