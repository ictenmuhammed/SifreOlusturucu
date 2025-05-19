# SifreOlusturucu

Bu Basit Bir şifre oluşturucu değil bu şifre oluşturucu bazı şifreleme algoritmaları kullanarak şifreler güvenliği 2 katına çıkarıcak kadar güçlüdür yaptığı şifreleme algoritmaları şöyledir;

MD5: 32 karakter (128 bit)

SHA256: 64 karakter (256 bit)

SHA512: 128 karakter (512 bit)

SHA3-512: 128 karakter (512 bit)

bcrypt: 60 karakter (hash formatı)

argon2id: Genellikle 95 karakter civarı (hash formatı)

scrypt: Değişken, genelde 64 karakter civarı (512 bit)

PBKDF2: Çıktı uzunluğuna bağlı, genelde 64 karakter (512 bit)

AES-256 CBC: 256 bit (32 byte) — ancak çıktı genelde Base64 veya Hex formatında kodlanır, uzunluk değişir

HMAC: HMAC çıktısı, kullanılan hash fonksiyonuna bağlıdır;

HMAC-MD5: 128 bit (16 byte) → 32 hex karakter

HMAC-SHA256: 256 bit (32 byte) → 64 hex karakter

HMAC-SHA512: 512 bit (64 byte) → 128 hex karakter
