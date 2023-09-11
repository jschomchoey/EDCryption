import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from zlib import compress, decompress

# Constants
BLOCK_SIZE = 16  # AES block size in bytes

def encrypt(input_file, output_file, key):
    # Generate a random initialization vector (IV)
    iv = os.urandom(BLOCK_SIZE)

    # Create an AES cipher object in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Read the input PNG file
    with open(input_file, 'rb') as file:
        data = file.read()

    # Exclude PNG header (first 8 bytes), trailer (last 12 bytes), and metadata (if present)
    header = data[:8]
    trailer = data[-12:]
    metadata = data[8:-12]

    # Compress the metadata using the Deflate algorithm
    compressed_metadata = compress(metadata)

    # Pad the compressed metadata to be a multiple of BLOCK_SIZE
    padded_metadata = pad(compressed_metadata, BLOCK_SIZE)

    # Encrypt the padded metadata
    encrypted_metadata = cipher.encrypt(padded_metadata)

    # Combine the header, encrypted metadata, and trailer
    encrypted_data = header + encrypted_metadata + trailer

    # Write the IV and encrypted data to the output file
    with open(output_file, 'wb') as file:
        file.write(iv + encrypted_data)

def decrypt(input_file, output_file, key):
    # Read the input file
    with open(input_file, 'rb') as file:
        data = file.read()

    # Extract the IV from the beginning of the data
    iv = data[:BLOCK_SIZE]

    # Create an AES cipher object in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Extract the encrypted data (header + encrypted metadata + trailer)
    encrypted_data = data[BLOCK_SIZE:]

    # Decrypt the encrypted data
    decrypted_metadata = cipher.decrypt(encrypted_data)

    # Unpad the decrypted metadata
    unpadded_metadata = unpad(decrypted_metadata, BLOCK_SIZE)

    # Decompress the metadata using the Deflate algorithm
    metadata = decompress(unpadded_metadata)

    # Combine the header, decrypted metadata, and trailer
    decrypted_data = data[:8] + metadata + data[-12:]

    # Write the decrypted data to the output file
    with open(output_file, 'wb') as file:
        file.write(decrypted_data)

if __name__ == "__main__":
    # Define the input and output file paths
    input_file = "C:\Data\Code\EDCryption\examplefile\code.png"
    encrypted_file = "encrypted.png"
    decrypted_file = "decrypted.png"

    # Define a secret key (32 bytes for AES-256)
    key = b'SuperSecretKey1234567890'

    # Encrypt the PNG file while excluding header, trailer, and metadata
    encrypt(input_file, encrypted_file, key)
    print("Encryption complete. Encrypted file:", encrypted_file)

    # Decrypt the encrypted PNG file and restore header, trailer, and metadata
    decrypt(encrypted_file, decrypted_file, key)
    print("Decryption complete. Decrypted file:", decrypted_file)
