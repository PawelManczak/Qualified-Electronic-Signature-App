import os
import re
import tkinter as tk
from subprocess import Popen, PIPE
from tkinter import filedialog

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from load_keys import load_public_key_from_pem, load_private_key_from_pem
from verify_signature import verify_signature
from sign_pdf_with_private_key import create_xml_signature

CLIENT_CERT_KEY = "1234"


def load_private_key_from_pfx(external_drive_path):
    pfx_file_path = os.path.join(external_drive_path, "certificate.pfx")
    with open(pfx_file_path, "rb") as f:
        try:
            private_key, certificate, additional_certificates = serialization.pkcs12.load_key_and_certificates(
                f.read(), CLIENT_CERT_KEY.encode()
            )
            return private_key, certificate.public_key()
        except ValueError:
            print("Incorrect password for private key.")
            return None


def check_external_drive():
    DISKUTIL = ["/usr/sbin/diskutil", "activity"]

    with Popen(DISKUTIL, stdout=PIPE, encoding="UTF-8") as diskutil:
        for line in diskutil.stdout:
            if line.startswith("***DiskAppeared"):
                match = re.search(r"DAVolumeName = '([^']+)'", line)
                if match:
                    volume_name = match.group(1)
                    print(volume_name)
                    if "<null>" in volume_name:
                        print("not found")
                        return None
                    external_drive_path = f"/Volumes/{volume_name}/"
                    return external_drive_path
    return None





def main():
    root = tk.Tk()
    root.title("PDF Signer")

    label = tk.Label(root, text="Waiting for pendrive...")
    label.pack()

    def update_label():
        external_drive_path = check_external_drive()
        if external_drive_path is not None:
            label.config(text=f"Pendrive path: {external_drive_path}")
            private_key = load_private_key_from_pem(external_drive_path, CLIENT_CERT_KEY)
            public_key = load_public_key_from_pem("/Users/pawelmanczak/PG sem 6/BSK/public_key.pem")
            if private_key is not None:
                label.config(text=f"Pendrive with private key in: {external_drive_path}")
                file_path = filedialog.askopenfilename(title="Select PDF file to sign",
                                                       filetypes=(("PDF files", "*.pdf"), ("all files", "*.*")))

                if file_path:
                    create_xml_signature("/Users/pawelmanczak/PG sem 6/BSK/___.pdf", private_key)

                    verify_signature("/Users/pawelmanczak/PG sem 6/BSK/___.pdf",
                                                     "/Users/pawelmanczak/PG sem 6/BSK/____signature.xml",
                                                     public_key=public_key)
                    label.config(text=f"PDF signed successfully: {os.path.basename(file_path)}")

            else:
                label.config(text="Private key not found on the pendrive.")
        else:
            label.config(text="Waiting for pendrive...")

        root.after(5000, update_label)

    update_label()
    root.mainloop()


if __name__ == "__main__":
    main()
