import tkinter as tk
from tkinter import filedialog

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from encrypt_file import generate_aes_key


def decrypt():
    decrypt_dialog = tk.Toplevel()
    decrypt_dialog.title("Enter key")

    decrypt_label = tk.Label(decrypt_dialog, text="Enter key for decryption:")
    decrypt_label.pack()

    decrypt_entry = tk.Entry(decrypt_dialog)
    decrypt_entry.pack()

    result_label = tk.Label(decrypt_dialog, text="")
    result_label.pack()

    def decrypt_with_key():
        key = decrypt_entry.get()

        if len(key) == 0:
            result_label.config(text="Key cannot be empty")
        else:
            file_path = filedialog.askopenfilename(title="Select file to decrypt", filetypes=(("All files", "*.*"),))

            decrypt_file(file_path, key)

            result_label.config(text="File decrypted successfully")

            def close():
                decrypt_dialog.destroy()

            close_button = tk.Button(decrypt_dialog, text="close", command=close)
            close_button.pack()

    sign_button = tk.Button(decrypt_dialog, text="Decrypt", command=decrypt_with_key)
    sign_button.pack()

    decrypt_dialog.mainloop()


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
