import tkinter as tk
from tkinter import filedialog

from check_external_drive import check_external_drive
from load_keys import load_public_key_from_pem, load_private_key_from_pem
from sign_pdf_with_private_key import create_xml_signature
from verify_signature import verify_signature

CLIENT_CERT_KEY = "1234"


def sign_pdf(private_key):
    file_path = filedialog.askopenfilename(title="Select PDF file to sign",
                                           filetypes=(("PDF files", "*.pdf"), ("all files", "*.*")))
    if file_path:
        create_xml_signature(file_path, private_key)
        return True

    return False


def verify_pdf(public_key):
    original_file = filedialog.askopenfilename(title="Select pdf",
                                               filetypes=(("PDF files", "*.pdf"), ("all files", "*.*")))
    signature = filedialog.askopenfilename(title="Select signature of original file",
                                           filetypes=(("XML files", "*.xml"), ("all files", "*.*")))

    return verify_signature(original_file, signature, public_key)


def main():
    root = tk.Tk()
    root.title("PDF Signer")
    external_drive_path = check_external_drive()

    private_key = load_private_key_from_pem(external_drive_path, CLIENT_CERT_KEY)
    public_key = load_public_key_from_pem("/Users/pawelmanczak/PG sem 6/BSK/public_key.pem")

    label = tk.Label(root, text="Waiting for pendrive...")
    label.pack()

    result_label = tk.Label(root, text="")
    result_label.pack()

    def update_sign_label():
        result = sign_pdf(private_key)
        if result:
            result_label.config(text=f"PDF signed successfully")
        else:
            result_label.config(text="Failed to sign PDF!")

    sign_button = tk.Button(root, text="Sign PDF", command=update_sign_label)
    sign_button.pack()

    def update_verify_label():
        result = verify_pdf(public_key)
        if result:
            result_label.config(text=f"PDF verified successfully")
        else:
            result_label.config(text="Failed to verified PDF!")

    verify_button = tk.Button(root, text="Verify PDF", command=update_verify_label)
    verify_button.pack()

    def update_usb_stick_status():
        nonlocal external_drive_path
        external_drive_path = str(check_external_drive())
        if external_drive_path is not None:
            label.config(text=f"Pendrive path: {external_drive_path}")

            if private_key is not None:
                label.config(text=f"Pendrive with private key in: {external_drive_path}")
            else:
                label.config(text="Private key not found on the pendrive.")
        else:
            label.config(text="Waiting for pendrive...")

        root.after(5000, update_usb_stick_status)

    update_usb_stick_status()
    root.mainloop()


if __name__ == "__main__":
    main()
