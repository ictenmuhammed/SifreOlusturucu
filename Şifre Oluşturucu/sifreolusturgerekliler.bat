@echo off
echo Python ortamini kontrol ediyorum...
python --version
if %errorlevel% neq 0 (
    echo Python bulunamadi. Lutfen Python'u yukleyin ve PATH seçeneğini seçin.
    exit /b
)

echo Gerekli kutuphaneleri yuklemek icin pip kullaniliyor...

echo random kutuphanesi yukleniyor... (Python standard library zaten yüklüdür.)
echo string kutuphanesi yukleniyor... (Python standard library zaten yüklüdür.)
echo hashlib kutuphanesi yukleniyor... (Python standard library zaten yüklüdür.)
echo os kutuphanesi yukleniyor... (Python standard library zaten yüklüdür.)
echo json kutuphanesi yukleniyor... (Python standard library zaten yüklüdür.)
echo datetime kutuphanesi yukleniyor... (Python standard library zaten yüklüdür.)

echo bcrypt kutuphanesi yukleniyor...
pip install bcrypt

echo argon2 kutuphanesi yukleniyor...
pip install argon2

echo pycryptodome kutuphanesi yukleniyor...
pip install pycryptodome

echo hmac kutuphanesi yukleniyor... (Python standard library zaten yüklüdür.)
echo secrets kutuphanesi yukleniyor... (Python standard library zaten yüklüdür.)

echo base64 kutuphanesi yukleniyor... (Python standard library zaten yüklüdür.)
echo sha3_512 kutuphanesi yukleniyor...
pip install hashlib  (Python standard library, sha3_512 zaten içeriyor.)

echo Tum kutuphaneler basariyla yuklendi.
pause
