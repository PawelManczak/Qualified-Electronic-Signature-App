import tkinter as tk
from tkinter import filedialog

from check_external_drive import check_external_drive
from load_keys import load_public_key_from_pem, load_private_key_from_pem, check_private_key_file_exists
from sign_pdf_with_private_key import create_xml_signature
from verify_signature import verify_signature

CLIENT_CERT_KEY = "1234"


def sign_pdf(private_key_path):
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

            file_path = filedialog.askopenfilename(title="Select PDF file to sign",
                                                   filetypes=(("PDF files", "*.pdf"), ("all files", "*.*")))
            if file_path:
                result = create_xml_signature(file_path, private_key)
                if result:
                    result_label.config(text="PDF signed successfully")

                    def close():
                        password_dialog.destroy()

                    close_button = tk.Button(password_dialog, text="close", command=close)
                    close_button.pack()
                else:
                    result_label.config(text="Failed to sign PDF!")
            else:
                result_label.config(text="No file selected")
        else:
            result_label.config(text="Incorrect password or private key not found.")

    sign_button = tk.Button(password_dialog, text="Sign", command=sign_with_password)
    sign_button.pack()

    password_dialog.mainloop()


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

    is_private_key_present = False
    public_key = load_public_key_from_pem("/Users/pawelmanczak/PG sem 6/BSK/public_key.pem")

    label = tk.Label(root, text="Waiting for pendrive...")
    label.pack()

    result_label = tk.Label(root, text="")
    result_label.pack()

    def update_sign_label():
        sign_pdf(external_drive_path)
        print("RESUL SIGNA: " + str("!@3"))
        # if result:
        #   result_label.config(text=f"PDF signed successfully")
        # else:
        #   result_label.config(text="Failed to sign PDF!")

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
