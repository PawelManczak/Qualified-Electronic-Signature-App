# Qualified-Electronic-Signature-App

Description:
This project aims to develop a software tool for emulating the qualified electronic signature, including signing documents and basic encryption operations. The application will adhere to the XAdES standard for electronic signatures and utilize RSA and AES algorithms for encryption and decryption.

<img width="448" alt="image" src="https://github.com/PawelManczak/Qualified-Electronic-Signature-App/assets/64583165/7406953b-adac-43c0-924a-ddd6a97c2a0f">

Features:
- Emulation of a hardware token (pendrive) for storing the private RSA key.
- Encryption of the private RSA key using AES algorithm with user's PIN.
- XML signature file creation according to XAdES standard.
- Verification of signatures by a second user.
- Basic encryption and decryption using RSA keys.
- GUI interface supporting file selection for signing and encryption/decryption.
- Messages for application status indication.

Commands to generate keys:

To generate 4096 RSA key:

```openssl genpkey -algorithm RSA -out private_key.pem -aes256```

To generate public key:

```openssl req -new -x509 -key private_key.pem -out public_cert.pem```

To generate .pfx cerificate:

```openssl pkcs12 -export -in public_cert.pem -inkey private_key.pem -out certificate.pfx```
