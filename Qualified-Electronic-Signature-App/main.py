import tkinter as tk
from tkinter import filedialog

from check_external_drive import check_external_drive
from decrypt_file import decrypt_file
from encrypt_file import encrypt_file
from load_keys import load_public_key_from_pem, load_private_key_from_pem, check_private_key_file_exists
from sign_pdf_with_private_key import create_xml_signature
from verify_signature import verify_signature


# CLIENT_CERT_KEY = "1234"

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


def sign(private_key_path):
    password_dialog = tk.Toplevel()
    password_dialog.title("Enter Password")

    password_label = tk.Label(password_dialog, text="Enter password:")
    password_label.pack()

    password_entry = tk.Entry(password_dialog, show="*")
    password_entry.pack()

    result_label = tk.Label(password_dialog, text="")
    result_label.pack()

    def sign_with_password():
        password = password_entry.get()

        private_key = load_private_key_from_pem(private_key_path, password)

        if private_key is not None:

            file_path = filedialog.askopenfilename(title="Select file to sign",
                                                   filetypes=(("PDF files", "*.pdf"), ("all files", "*.*")))
            if file_path:
                result = create_xml_signature(file_path, private_key)
                if result:
                    result_label.config(text="File signed successfully")

                    def close():
                        password_dialog.destroy()

                    close_button = tk.Button(password_dialog, text="close", command=close)
                    close_button.pack()
                else:
                    result_label.config(text="Failed to sign!")
            else:
                result_label.config(text="No file selected")
        else:
            result_label.config(text="Incorrect password or private key not found.")

    sign_button = tk.Button(password_dialog, text="Sign", command=sign_with_password)
    sign_button.pack()

    password_dialog.mainloop()


def verify(public_key):
    original_file = filedialog.askopenfilename(title="Select file",
                                               filetypes=(("PDF files", "*.pdf"), ("all files", "*.*")))
    signature = filedialog.askopenfilename(title="Select signature of original file",
                                           filetypes=(("XML files", "*.xml"), ("all files", "*.*")))

    return verify_signature(original_file, signature, public_key)


def main():
    root = tk.Tk()
    root.title("File Signer")
    external_drive_path = check_external_drive()

    is_private_key_present = False
    public_key = load_public_key_from_pem("/Users/pawelmanczak/PG sem 6/BSK/public_key.pem")

    label = tk.Label(root, text="Waiting for pendrive...")
    label.pack()

    result_label = tk.Label(root, text="")
    result_label.pack()

    def update_sign_label():
        sign(external_drive_path)

    sign_button = tk.Button(root, text="Sign File", command=update_sign_label)
    sign_button.pack()

    def update_verify_label():
        result = verify(public_key)
        if result:
            result_label.config(text=f"File verified successfully")
        else:
            result_label.config(text="Failed to verified file!")

    verify_button = tk.Button(root, text="Verify file", command=update_verify_label)
    verify_button.pack()

    encrypt_button = tk.Button(root, text="Encrypt File", command=encrypt)
    encrypt_button.pack()

    decrypt_button = tk.Button(root, text="Decrypt File", command=decrypt)
    decrypt_button.pack()

    def update_usb_stick_status():
        nonlocal external_drive_path, is_private_key_present

        external_drive_path = check_external_drive()
        if external_drive_path is not None:
            label.config(text=f"Pendrive path: {str(external_drive_path)}")
            is_private_key_present = check_private_key_file_exists(external_drive_path)
            if is_private_key_present is True:
                label.config(text=f"Pendrive with private key in: {str(external_drive_path)}")
                sign_button.config(state=tk.NORMAL)
            else:
                label.config(text="Private key not found on the pendrive.")
                sign_button.config(state=tk.DISABLED)
        else:
            label.config(text="Waiting for pendrive...")
            sign_button.config(state=tk.DISABLED)

        root.after(5000, update_usb_stick_status)

    update_usb_stick_status()
    root.mainloop()


if __name__ == "__main__":
    main()
