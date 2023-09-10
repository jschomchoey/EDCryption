from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

def encrypt_file(input_file, output_file, key):
    cipher = AES.new(key, AES.MODE_EAX)
    
    with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
        ciphertext, tag = cipher.encrypt_and_digest(infile.read())
        outfile.write(cipher.nonce)
        outfile.write(tag)
        outfile.write(ciphertext)

def decrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
        nonce = infile.read(16)
        tag = infile.read(16)
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        ciphertext = infile.read()

        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            outfile.write(plaintext)
        except ValueError:
            print("Decryption failed. The key may be incorrect.")

if __name__ == "__main__":
    input_file = "C:\Data\Code\EDCryption\examplefile\Linux-Command-2.txt"
    encrypted_file = "encrypted_file.txt"  # Change the output file extension to .txt
    decrypted_file = "Linux-Command-2.txt"
    key = get_random_bytes(16)  # 128-bit AES key

    # Encrypt the input file
    encrypt_file(input_file, encrypted_file, key)
    print(f"File '{input_file}' has been encrypted and saved as '{encrypted_file}'.")

    # Decrypt the encrypted file
    decrypt_file(encrypted_file, decrypted_file, key)
    print(f"File '{encrypted_file}' has been decrypted and saved as '{decrypted_file}'.")
