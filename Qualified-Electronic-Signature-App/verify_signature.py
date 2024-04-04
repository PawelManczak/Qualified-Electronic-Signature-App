from PyPDF2 import PdfReader
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import xml.etree.ElementTree as ET


def verify_signature(pdf_path, xml_path, public_key):
    with open(pdf_path, 'rb') as file:
        document_hash = hashes.Hash(hashes.SHA256())
        document_hash.update(file.read())
        document_digest = document_hash.finalize()

    tree = ET.parse(xml_path)
    root = tree.getroot()
    encrypted_hash_text = root.find('EncryptedHash').text
    signature = eval(encrypted_hash_text)
    try:
        public_key.verify(
            signature,
            document_digest,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("Signature verified successfully.")
    except Exception:
        print("Invalid signature.")
