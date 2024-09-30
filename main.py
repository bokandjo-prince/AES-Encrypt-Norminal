import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from os import stat, remove

# encryption/decryption buffer size - 64K
bufferSize = 64 * 1024
password = "Jevousaimetousbeaucoup<3"

# Generate a 128-bit nonce (required for GCM mode)
nonce = os.urandom(12)  # Note: GCM mode requires a 96-bit nonce

# encrypt
with open("1ESBasketballPass_randomaccess_500_32.bin", "rb") as fIn:
    with open("2ESBasketballPass_randomaccess_500_32.bin.aes", "wb") as fOut:
        # Create a Cipher object with AES-256-GCM
        cipher = Cipher(algorithms.AES(password.encode()), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()

        # Write the nonce to the output file (required for decryption)
        fOut.write(nonce)

        # Encrypt the file stream
        while True:
            chunk = fIn.read(bufferSize)
            if not chunk:
                break
            encrypted_chunk = encryptor.update(chunk)
            fOut.write(encrypted_chunk)

        # Write the authentication tag to the output file (required for decryption)
        fOut.write(encryptor.finalize())

# decrypt
with open("2ESBasketballPass_randomaccess_500_32.bin.aes", "rb") as fIn:
    try:
        with open("2ENC1ESBasketballPass_randomaccess_500_32.bin", "wb") as fOut:
            # Read the nonce from the input file
            nonce = fIn.read(12)

            # Create a Cipher object with AES-256-GCM
            cipher = Cipher(algorithms.AES(password.encode()), modes.GCM(nonce), backend=default_backend())
            decryptor = cipher.decryptor()

            # Decrypt the file stream
            while True:
                chunk = fIn.read(bufferSize)
                if not chunk:
                    break
                decrypted_chunk = decryptor.update(chunk)
                fOut.write(decrypted_chunk)
            # Read the authentication tag from the input file
            tag = fIn.read(16)
            # Verify the authentication tag
            decryptor.finalize_with_tag(tag)

    except ValueError:
        # remove output file on error
        remove("2ENC1ESBasketballPass_randomaccess_500_32.bin")
        print("Authentication failed")
    else:
        print("Authentication successful")
        print("Decrypted data is written")
