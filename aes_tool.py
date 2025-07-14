# --- Import Required Libraries ---
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # For AES encryption/decryption
from cryptography.hazmat.backends import default_backend                      # Backend for cryptography operations
from cryptography.hazmat.primitives import padding                            # For PKCS7 padding
import hashlib                                                                # For password-based key derivation
import os                                                                     # For random salt, IV, and file operations

# --- Derive a 256-bit key using PBKDF2 with SHA-256 ---
def derive_key(password, salt):
    # Convert password to bytes and derive a strong key using salt
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)

# --- Encrypt a file using AES-256-CBC ---
def encrypt_file(filepath, password):
    # Step 1: Read original file content
    with open(filepath, 'rb') as f:
        data = f.read()

    # Step 2: Generate 16-byte salt and IV
    salt = os.urandom(16)
    iv = os.urandom(16)

    # Step 3: Derive encryption key from password
    key = derive_key(password, salt)

    # Step 4: Pad the data using PKCS7 to make it AES block size aligned
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Step 5: Set up AES cipher in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Step 6: Encrypt the padded data
    encrypted = encryptor.update(padded_data) + encryptor.finalize()

    # Step 7: Get original file extension (e.g., .jpg, .pdf)
    ext = os.path.splitext(filepath)[1]
    ext_bytes = ext.encode().ljust(10, b' ')[:10]  # Fixed 10-byte extension storage

    # Step 8: Return combined encrypted content: [salt][iv][ext][encrypted_data]
    return salt + iv + ext_bytes + encrypted

# --- Decrypt an encrypted file using AES-256-CBC ---
def decrypt_file(filepath, password):
    # Step 1: Read the encrypted file content
    with open(filepath, 'rb') as f:
        data = f.read()

    # Step 2: Extract components: salt, IV, extension, and encrypted content
    salt = data[:16]
    iv = data[16:32]
    ext_bytes = data[32:42]              # Fixed 10 bytes for file extension
    encrypted_data = data[42:]
    ext = ext_bytes.decode().strip() or ".bin"  # Recover original extension or fallback

    # Step 3: Re-derive the encryption key from password and salt
    key = derive_key(password, salt)

    # Step 4: Set up AES cipher in CBC mode and decrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()

    # Step 5: Unpad the decrypted data (may raise error if password is wrong)
    unpadder = padding.PKCS7(128).unpadder()
    try:
        final_data = unpadder.update(decrypted_padded) + unpadder.finalize()
    except ValueError:
        # Incorrect padding usually means wrong password or file corruption
        raise ValueError("❌ Incorrect password or corrupted file.")

    # Step 6: Return the decrypted file content and its original extension
    return final_data, ext
