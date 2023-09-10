from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def pad(text):
    # Pad the text to be a multiple of 16 bytes (AES block size)
    return text + b' ' * (16 - len(text) % 16)

def encrypt_file(input_file, output_file, key):
    cipher = AES.new(key, AES.MODE_CBC)

    with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
        outfile.write(cipher.iv)

        while True:
            # Read a block of data from the input file
            plaintext_block = infile.read(16)
            if len(plaintext_block) == 0:
                break

            # Encrypt the block and write it to the output file
            ciphertext_block = cipher.encrypt(pad(plaintext_block))
            outfile.write(ciphertext_block)

def decrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
        iv = infile.read(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)

        while True:
            # Read an encrypted block of data from the input file
            ciphertext_block = infile.read(16)
            if len(ciphertext_block) == 0:
                break

            # Decrypt the block and write it to the output file
            decrypted_block = cipher.decrypt(ciphertext_block)
            outfile.write(decrypted_block.rstrip(b' '))

if __name__ == "__main__":
    input_file = "C:\Data\Code\EDCryption\examplefile\\textfile_thai_long.txt"
    encrypted_file = "encrypted_file.txt"
    decrypted_file = "decrypted.txt"
    key = get_random_bytes(16)  # 128-bit AES key

    # Encrypt the input file
    encrypt_file(input_file, encrypted_file, key)
    print(f"File '{input_file}' has been encrypted and saved as '{encrypted_file}'.")

    # Decrypt the encrypted file
    decrypt_file(encrypted_file, decrypted_file, key)
    print(f"File '{encrypted_file}' has been decrypted and saved as '{decrypted_file}'.")
