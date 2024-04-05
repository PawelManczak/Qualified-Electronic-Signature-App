import datetime
import os
import xml.etree.ElementTree as ET

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def create_xml_signature(document_path, private_key):
    # Calculate hash of the document
    with open(document_path, 'rb') as file:
        document_hash = hashes.Hash(hashes.SHA256())
        document_hash.update(file.read())
        document_digest = document_hash.finalize()

    # Encrypt the hash using User A's private RSA key
    encrypted_hash = private_key.sign(
        document_digest,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    # Create XML signature file with document identification, user information, encrypted hash, and timestamp
    root = ET.Element("Signature")

    document_info = ET.SubElement(root, "DocumentInfo")
    file_size = str(os.path.getsize(document_path))
    file_extension = os.path.splitext(document_path)[1]
    file_last_modified = str(datetime.datetime.fromtimestamp(os.path.getmtime(document_path)))
    document_info.attrib["size"] = file_size
    document_info.attrib["extension"] = file_extension
    document_info.attrib["last_modified"] = file_last_modified

    user_info = ET.SubElement(root, "UserInfo")
    user_info.text = "User A"  # Provide user information

    encrypted_hash_element = ET.SubElement(root, "EncryptedHash")
    encrypted_hash_element.text = str(encrypted_hash)

    timestamp = ET.SubElement(root, "Timestamp")
    timestamp.text = str(datetime.datetime.now())

    xml_tree = ET.ElementTree(root)
    xml_signature_path = os.path.splitext(document_path)[0] + "_signature.xml"
    xml_tree.write(xml_signature_path)

    return xml_signature_path

