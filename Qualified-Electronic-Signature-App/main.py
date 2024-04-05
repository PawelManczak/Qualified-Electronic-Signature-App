import tkinter as tk

from check_external_drive import check_external_drive
from decrypt_file import decrypt
from encrypt_file import encrypt
from load_keys import load_public_key_from_pem, check_private_key_file_exists
from sign import sign
from verify_signature import verify


# CLIENT_CERT_KEY = "1234"


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

        root.after(500, update_usb_stick_status)

    update_usb_stick_status()
    root.mainloop()


if __name__ == "__main__":
    main()
