import datetime
import os
import tkinter as tk
import xml.etree.ElementTree as ET
from tkinter import filedialog

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from load_keys import load_private_key_from_pem


def sign(private_key_path):
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

            file_path = filedialog.askopenfilename(title="Select file to sign",
                                                   filetypes=(("PDF files", "*.pdf"), ("all files", "*.*")))
            if file_path:
                result = create_xml_signature(file_path, private_key)
                if result:
                    result_label.config(text="File signed successfully")

                    def close():
                        password_dialog.destroy()

                    close_button = tk.Button(password_dialog, text="close", command=close)
                    close_button.pack()
                else:
                    result_label.config(text="Failed to sign!")
            else:
                result_label.config(text="No file selected")
        else:
            result_label.config(text="Incorrect password or private key not found.")

    sign_button = tk.Button(password_dialog, text="Sign", command=sign_with_password)
    sign_button.pack()

    password_dialog.mainloop()


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
