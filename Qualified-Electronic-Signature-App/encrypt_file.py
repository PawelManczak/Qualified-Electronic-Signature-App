from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def encrypt_file(file_path, s_key):
    # Read the content of the file
    key = generate_aes_key(s_key, 32)
    with open(file_path, 'rb') as file:
        plaintext = file.read()

    # Initialize AES cipher with provided key
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(b'\0' * 16), backend=backend)
    encryptor = cipher.encryptor()

    # Pad the plaintext to match block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    # Encrypt the padded plaintext
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Write the encrypted data to a new file
    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(ciphertext)

    return encrypted_file_path


def generate_aes_key(password, key_length):
    salt = b'salt_123'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key
