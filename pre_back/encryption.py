from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt_file(input_file, output_file, key):
    # Generate a random initialization vector (IV)
    iv = get_random_bytes(16)

    # Create an AES cipher object
    cipher = AES.new(key, AES.MODE_CBC, iv)

    with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
        # Write the IV to the output file (it's needed for decryption)
        outfile.write(iv)

        while True:
            # Read a chunk of data from the input file
            chunk = infile.read(16)
            if len(chunk) == 0:
                break
            elif len(chunk) % 16 != 0:
                # Pad the last block if it's not a multiple of 16
                chunk += b' ' * (16 - len(chunk) % 16)

            # Encrypt and write the chunk to the output file
            encrypted_chunk = cipher.encrypt(chunk)
            outfile.write(encrypted_chunk)

if __name__ == "__main__":
    input_file = "C:\\Data\\Code\\EDCryption\\examplefile\\textfile_thai_long.txt"
    output_file = "encrypted_file.txt"
    key = get_random_bytes(32)  # 256-bit AES key

    encrypt_file(input_file, output_file, key)
    print(f"File '{input_file}' has been encrypted and saved as '{output_file}'.")
