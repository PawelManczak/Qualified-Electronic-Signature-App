import os
import re
import sys
from subprocess import Popen, PIPE
from time import sleep

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

CLIENT_CERT_KEY = "12345"

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


def check_external_drive(callback):
    DISKUTIL = ["/usr/sbin/diskutil", "activity"]

    while True:
        with Popen(DISKUTIL, stdout=PIPE, encoding="UTF-8") as diskutil:
            # Detect the first subsequent "Disk Appeared" event
            for line in diskutil.stdout:
                if line.startswith("***DiskAppeared"):
                    match = re.search(r"DAVolumeName = '([^']+)'", line)

                    if match:
                        volume_name = match.group(1)
                        external_drive_path = f"/Volumes/{volume_name}/"
                        sleep(5)
                        callback(external_drive_path)

                    break
                sleep(5)


def main():
    def on_external_drive_change(external_drive_path):
        print("Detected change in external drive:", external_drive_path)
        private_key = load_private_key_from_pfx(external_drive_path)
        if private_key is not None:
            print("Private key from PFX file:", private_key)

    try:
        check_external_drive(on_external_drive_change)
    except KeyboardInterrupt:
        sys.exit(1)


if __name__ == "__main__":
    main()
