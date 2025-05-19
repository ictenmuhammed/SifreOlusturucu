import random
import string
import hashlib
import bcrypt
from argon2 import PasswordHasher
import os
import json
import hmac
import secrets
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Random import get_random_bytes
import base64
from hashlib import sha3_512
from datetime import datetime, timedelta

# Sifre olusturma fonksiyonu (harf, rakam, ozel karakterler)
def generate_password(length=12, use_special_chars=False):
    """Verilen uzunlukta, harf, rakam ve istege bagli ozel karakter iceren bir sifre olusturur."""
    characters = string.ascii_letters + string.digits  # Kucuk/buyuk harf ve rakamlar
    if use_special_chars:
        characters += string.punctuation  # Ozel karakterler eklenebilir
    # Rastgele sifre olusturma
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

# Sifreleme yontemleri (MD5, SHA, bcrypt, vb.)
def md5_hash(password):
    """Verilen sifreyi MD5 ile sifreler."""
    return hashlib.md5(password.encode()).hexdigest()

def sha256_hash(password):
    """Verilen sifreyi SHA256 ile sifreler."""
    return hashlib.sha256(password.encode()).hexdigest()

def sha512_hash(password):
    """Verilen sifreyi SHA512 ile sifreler."""
    return hashlib.sha512(password.encode()).hexdigest()

def sha3_512_hash(password):
    """Verilen sifreyi SHA3-512 ile sifreler."""
    return sha3_512(password.encode()).hexdigest()

def bcrypt_hash(password, salt=None):
    """Verilen sifreyi bcrypt ile sifreler."""
    if not salt:
        salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

def argon2id_hash(password):
    """Verilen sifreyi argon2id ile sifreler."""
    ph = PasswordHasher()
    return ph.hash(password)

def scrypt_hash(password, salt=None):
    """Verilen sifreyi scrypt ile sifreler."""
    if not salt:
        salt = secrets.token_bytes(16)
    key = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=64)
    return base64.b64encode(key).decode()

def pbkdf2_hash(password, salt=None, iterations=100000):
    """Verilen sifreyi PBKDF2 ile sifreler."""
    if not salt:
        salt = secrets.token_bytes(16)
    key = PBKDF2(password.encode(), salt, dkLen=32, count=iterations)
    return key.hex()

def aes_encrypt(password, encryption_key):
    """Verilen sifreyi AES-256 CBC ile sifreler."""
    salt = get_random_bytes(16)
    cipher = AES.new(encryption_key.encode(), AES.MODE_CBC, iv=salt)
    padded_password = password + (16 - len(password) % 16) * chr(16 - len(password) % 16)
    ciphertext = cipher.encrypt(padded_password.encode())
    return base64.b64encode(salt + ciphertext).decode()

def hmac_hash(password, key):
    """Verilen sifreyi HMAC ile sifreler."""
    return hmac.new(key.encode(), password.encode(), hashlib.sha256).hexdigest()

# Zamanlayici (Gecici sifreler)
def set_expiration_time(expiration_unit, value):
    """Sifrenin gecerliligi icin bir zamanlayici ayarlar."""
    now = datetime.now()
    if expiration_unit == 'dakika':
        return now + timedelta(minutes=value)
    elif expiration_unit == 'saat':
        return now + timedelta(hours=value)
    elif expiration_unit == 'gun':
        return now + timedelta(days=value)

# Sifreyi dosyaya kaydetme
def save_password(application_name, password, hashed_password, method, expiration_time=None):
    data = {
        'application': application_name,
        'password': password,
        'hashed_password': hashed_password,
        'method': method,
        'expiration_time': expiration_time
    }
    
    # Dosya yolu (programin calistigi dizin)
    file_path = "saved_passwords.json"
    
    # Dosyayi okuma ve veriyi ekleme
    if os.path.exists(file_path):
        with open(file_path, "r") as file:
            passwords_data = json.load(file)
    else:
        passwords_data = []

    passwords_data.append(data)

    # Dosyayi tekrar yazma
    with open(file_path, "w") as file:
        json.dump(passwords_data, file, indent=4)
    print("Sifre basariyla kaydedildi!")

# Ana program
def main():
    print("Sifre Olusturucu ve Sifreleme Araci")
    print("=====================================")

    # Kullanıcıdan şifre uzunluğunu al
    length = int(input("Sifre uzunlugunu girin (8 ve daha fazla): "))

    # Kullanıcıdan özel karakter kullanma tercihini al
    use_special_chars = input("Ozel karakterler de icerisin mi? (Evet/Hayir): ").strip().lower() == 'evet'

    # Sifre olustur
    password = generate_password(length, use_special_chars)
    print(f"Oluşturulan Sifre: {password}")

    # Kullanıcıdan şifrenin kalıcı mı yoksa geçici mi olduğunu sor
    password_type = input("Sifre kalici mi yoksa gecici mi olacak? (kalici/gecici): ").strip().lower()

    expiration_time = None
    if password_type == 'gecici':
        # Geçici şifre seçildi, süresi için bir zaman dilimi belirleyin
        expiration_unit = input("Gecerlilik suresi birimi (dakika/saat/gun): ").strip().lower()
        expiration_value = int(input(f"Gecerlilik suresi (kaç {expiration_unit}): "))
        expiration_time = set_expiration_time(expiration_unit, expiration_value)

        # Geçerlilik süresi tarih formatında string'e çeviriliyor
        expiration_time_str = expiration_time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"Bu sifre {expiration_time_str} tarihine kadar gecerli olacak.")
        expiration_time = expiration_time_str

    # Sifreleme seçeneklerini göster
    print("\nSifreyi hangi yontemle sifrelemek istersiniz?")
    print("1. MD5 ile sifrele")
    print("2. SHA256 ile sifrele")
    print("3. SHA512 ile sifrele")
    print("4. SHA3-512 ile sifrele")
    print("5. bcrypt ile sifrele")
    print("6. argon2id ile sifrele")
    print("7. scrypt ile sifrele")
    print("8. PBKDF2 ile sifrele")
    print("9. AES-256 CBC ile sifrele")
    print("10. HMAC ile sifrele")
    print("11. Sifreyi oldugu gibi goster (sifreleme yapma)")

    choice = input("Seciminizi yapin (1, 2, 3, 4, 5, 6, 7, 8, 9, 10 veya 11): ")

    # Uygulama adı al
    application_name = input("Sifreyi hangi uygulama icin kullanacaksiniz? (Ornegin: Discord, Facebook, E-posta): ").strip()

    # Sifreleme ve kaydetme işlemi
    if choice == "1":
        hashed_password = md5_hash(password)
        save_password(application_name, password, hashed_password, 'MD5', expiration_time)
    elif choice == "2":
        hashed_password = sha256_hash(password)
        save_password(application_name, password, hashed_password, 'SHA256', expiration_time)
    elif choice == "3":
        hashed_password = sha512_hash(password)
        save_password(application_name, password, hashed_password, 'SHA512', expiration_time)
    elif choice == "4":
        hashed_password = sha3_512_hash(password)
        save_password(application_name, password, hashed_password, 'SHA3-512', expiration_time)
    elif choice == "5":
        hashed_password = bcrypt_hash(password)
        save_password(application_name, password, hashed_password, 'bcrypt', expiration_time)
    elif choice == "6":
        hashed_password = argon2id_hash(password)
        save_password(application_name, password, hashed_password, 'argon2id', expiration_time)
    elif choice == "7":
        hashed_password = scrypt_hash(password)
        save_password(application_name, password, hashed_password, 'scrypt', expiration_time)
    elif choice == "8":
        hashed_password = pbkdf2_hash(password)
        save_password(application_name, password, hashed_password, 'PBKDF2', expiration_time)
    elif choice == "9":
        encryption_key = input("AES icin bir anahtar girin: ")
        encrypted_password = aes_encrypt(password, encryption_key)
        save_password(application_name, password, encrypted_password, 'AES-256 CBC', expiration_time)
    elif choice == "10":
        key = input("HMAC icin bir anahtar girin: ")
        hashed_password = hmac_hash(password, key)
        save_password(application_name, password, hashed_password, 'HMAC', expiration_time)
    elif choice == "11":
        print(f"Sifre oldugu gibi: {password}")
        save_password(application_name, password, "Sifrelenmemis Parola", 'None', expiration_time)
    else:
        print("Gecersiz secim!")

if __name__ == "__main__":
    main()
