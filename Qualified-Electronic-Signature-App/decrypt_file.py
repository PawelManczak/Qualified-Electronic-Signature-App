from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from encrypt_file import generate_aes_key


def decrypt_file(encrypted_file_path, s_key):

    key = generate_aes_key(s_key, 32)
    # Read the content of the encrypted file
    with open(encrypted_file_path, 'rb') as encrypted_file:
        ciphertext = encrypted_file.read()

    # Initialize AES cipher with provided key
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(b'\0' * 16), backend=backend)
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the decrypted data
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(decrypted_data) + unpadder.finalize()

    # Write the decrypted data to a new file
    decrypted_file_path = encrypted_file_path[:-4]  # Remove the .enc extension
    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(plaintext)

    return decrypted_file_path