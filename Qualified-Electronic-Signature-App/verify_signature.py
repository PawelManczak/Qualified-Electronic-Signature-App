import xml.etree.ElementTree as ET
from tkinter import filedialog

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def verify(public_key):
    original_file = filedialog.askopenfilename(title="Select file",
                                               filetypes=(("PDF files", "*.pdf"), ("all files", "*.*")))
    signature = filedialog.askopenfilename(title="Select signature of original file",
                                           filetypes=(("XML files", "*.xml"), ("all files", "*.*")))

    return verify_signature(original_file, signature, public_key)


def verify_signature(file_path, xml_path, public_key):
    with open(file_path, 'rb') as file:
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
        return True
    except Exception:
        print("Invalid signature.")
        return False
