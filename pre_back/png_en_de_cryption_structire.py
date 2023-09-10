from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Define your encryption key and IV (Initialization Vector)
key = get_random_bytes(16)  # 128-bit key (AES-128)
iv = get_random_bytes(16)   # 128-bit IV

# Create AES cipher objects for encryption and decryption
cipher_encrypt = AES.new(key, AES.MODE_CBC, iv)
cipher_decrypt = AES.new(key, AES.MODE_CBC, iv)

# Read the PNG file data into memory (binary)
with open('C:\Data\Code\EDCryption\examplefile\code.png', 'rb') as file:
    image_data = file.read()

# Find the start and end of the image data chunk
start_marker = b'\x49\x44\x41\x54'  # IDAT chunk signature
end_marker = b'\x49\x45\x4e\x44'    # IEND chunk signature
start_index = image_data.find(start_marker)
end_index = image_data.find(end_marker)

if start_index == -1 or end_index == -1:
    raise ValueError("No valid image data found in the PNG file")

# Extract the image data chunk (excluding header and trailer)
image_data_chunk = image_data[start_index + 4:end_index]

# Encrypt the image data chunk
encrypted_data_chunk = cipher_encrypt.encrypt(pad(image_data_chunk, AES.block_size))

# Replace the original image data chunk with the encrypted data
modified_image_data = image_data[:start_index + 4] + encrypted_data_chunk + image_data[end_index:]

# Save the modified PNG data to a new file
with open('encrypted_image.png', 'wb') as file:
    file.write(modified_image_data)

# Decrypt the encrypted data chunk
decrypted_data_chunk = unpad(cipher_decrypt.decrypt(encrypted_data_chunk), AES.block_size)

# Replace the encrypted data chunk with the decrypted data
restored_image_data = image_data[:start_index + 4] + decrypted_data_chunk + image_data[end_index:]

# Save the restored PNG data to a new file
with open('restored_image.png', 'wb') as file:
    file.write(restored_image_data)
