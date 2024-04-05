import tkinter as tk
from tkinter import filedialog

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def encrypt():
    encrypt_dialog = tk.Toplevel()
    encrypt_dialog.title("Enter key")

    encrypt_label = tk.Label(encrypt_dialog, text="Enter key for enctyption:")
    encrypt_label.pack()

    encrypt_entry = tk.Entry(encrypt_dialog)
    encrypt_entry.pack()

    result_label = tk.Label(encrypt_dialog, text="")
    result_label.pack()

    def encrypt_with_key():
        key = encrypt_entry.get()

        if len(key) == 0:
            result_label.config(text="Key cannot be empty")
        else:
            file_path = filedialog.askopenfilename(title="Select file to encrypt", filetypes=(("All files", "*.*"),))

            encrypt_file(file_path, key)

            result_label.config(text="File encrypted successfully")

            def close():
                encrypt_dialog.destroy()

            close_button = tk.Button(encrypt_dialog, text="close", command=close)
            close_button.pack()

    sign_button = tk.Button(encrypt_dialog, text="Encrypt", command=encrypt_with_key)
    sign_button.pack()

    encrypt_dialog.mainloop()


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
