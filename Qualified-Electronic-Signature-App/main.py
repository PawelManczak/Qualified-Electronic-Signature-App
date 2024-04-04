import os
import re
import sys
from subprocess import Popen, PIPE
from time import sleep
import tkinter as tk
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

CLIENT_CERT_KEY = "1234"


def load_private_key_from_pfx(external_drive_path):
    pfx_file_path = os.path.join(external_drive_path, "certificate.pfx")
    with open(pfx_file_path, "rb") as f:
        try:
            private_key, certificate, additional_certificates = serialization.pkcs12.load_key_and_certificates(
                f.read(), CLIENT_CERT_KEY.encode()
            )

            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

            return private_key_pem.decode()
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
                        print("123")
                        return None
                    external_drive_path = f"/Volumes/{volume_name}/"
                    return external_drive_path
    return None


def main():
    root = tk.Tk()
    root.title("Pendrive Detector")

    label = tk.Label(root, text="Czekam na podłączenie pendrive'a...")
    label.pack()

    def update_label():
        external_drive_path = check_external_drive()
        if external_drive_path is not None:
            label.config(text=f"Pendrive path: {external_drive_path}")
            private_key = load_private_key_from_pfx(external_drive_path)
            if private_key is not None:
                label.config(text=f"Pendrive with secret in: {external_drive_path}")
        else:
            label.config(text="Waiting for pendrive...")

        root.after(5000, update_label)

    update_label()
    root.mainloop()


if __name__ == "__main__":
    main()