from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import hashlib
import os

def derive_key(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)

def encrypt_file(filepath, password):
    with open(filepath, 'rb') as f:
        data = f.read()

    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(password, salt)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()

    ext = os.path.splitext(filepath)[1]
    ext_bytes = ext.encode().ljust(10, b' ')[:10]

    return salt + iv + ext_bytes + encrypted

def decrypt_file(filepath, password):
    with open(filepath, 'rb') as f:
        data = f.read()

    salt = data[:16]
    iv = data[16:32]
    ext_bytes = data[32:42]
    encrypted_data = data[42:]
    ext = ext_bytes.decode().strip() or ".bin"

    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()

    # Unpad with error check
    unpadder = padding.PKCS7(128).unpadder()
    try:
        final_data = unpadder.update(decrypted_padded) + unpadder.finalize()
    except ValueError:
        raise ValueError("❌ Incorrect password or corrupted file.")

    return final_data, ext
