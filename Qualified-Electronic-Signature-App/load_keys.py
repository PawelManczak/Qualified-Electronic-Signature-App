import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12


def load_public_key_from_pem(cert_path):
    public_cert_path = cert_path
    with open(public_cert_path, "rb") as f:
        try:
            public_key = serialization.load_pem_public_key(
                f.read()
            )
            return public_key
        except ValueError:
            print("Error occurred")
            return None


def load_private_key_from_pem(external_drive_path, password):
    public_cert_path = os.path.join(external_drive_path, "private_key.pem")
    with open(public_cert_path, "rb") as f:
        try:
            public_key = serialization.load_pem_private_key(
                f.read(),
                password.encode()
            )
            return public_key
        except ValueError:
            print("Incorrect password for private key.")
            return None

def load_private_key_from_pfx(external_drive_path, password):
    pfx_file_path = os.path.join(external_drive_path, "certificate.pfx")
    with open(pfx_file_path, "rb") as f:
        try:
            private_key, certificate, additional_certificates = serialization.pkcs12.load_key_and_certificates(
                f.read(), password.encode()
            )
            return private_key, certificate.public_key()
        except ValueError:
            print("Incorrect password for private key.")
            return None
