from PIL import Image
from Crypto.Cipher import AES

filename = "/Users/jschomchoey/Data/Code/EDCryption/examplefile/Image/Forest.jpeg"
filename_out = "tux_encrypted"
format = "png"
key = "aaaabbbbccccdddd"

# AES requires that plaintexts be a multiple of 16, so we have to pad the data
def pad(data):
    return data + b"\x00" * (16 - len(data) % 16)

# Maps the RGB
def convert_to_RGB(data):
    r, g, b = tuple(
        map(lambda d: [data[i] for i in range(0, len(data)) if i % 3 == d], [0, 1, 2])
    )
    pixels = tuple(zip(r, g, b))
    return pixels

def process_image(filename):
    # Opens image and converts it to RGB format for PIL
    im = Image.open(filename)
    data = im.convert("RGB").tobytes()

    # Since we will pad the data to satisfy AES's multiple-of-16 requirement, we will store the original data length and "unpad" it later.
    original = len(data)

    # Encrypts using desired AES mode (we'll set it to ECB by default)
    encrypted_data = aes_cbc_encrypt(key, pad(data))[:original]

    # Create a new PIL Image object and save the old image data into the new image.
    im2 = Image.new(im.mode, im.size)
    im2.putdata(convert_to_RGB(encrypted_data))

    # Save image
    im2.save(filename_out + "." + format, format)

def aes_cbc_encrypt(key, data, mode=AES.MODE_CBC):
    IV = "A" * 16  # We'll manually set the initialization vector to simplify things
    aes = AES.new(key.encode("utf8"), mode, IV.encode("utf8"))
    new_data = aes.encrypt(data)
    return new_data

def aes_ecb_decrypt(key, data, mode=AES.MODE_CBC):
    aes = AES.new(key.encode("utf8"), mode)
    decrypted_data = aes.decrypt(data)
    return decrypted_data.rstrip(b"\x00")  # Remove padding

def process_decrypted_image(filename):
    # Opens encrypted image and converts it to RGB format for PIL
    im = Image.open(filename)
    data = im.convert("RGB").tobytes()

    # Decrypt using AES ECB mode
    decrypted_data = aes_ecb_decrypt(key, data)

    # Create a new PIL Image object and save the decrypted image
    im2 = Image.new(im.mode, im.size)
    im2.putdata(convert_to_RGB(decrypted_data))

    # Save the decrypted image
    im2.save("decrypted_" + filename, format)

# Process the image for encryption
process_image(filename)

# Process the encrypted image for decryption
process_decrypted_image(filename_out + "." + format)

from PIL import Image

im1 = Image.open(r'C:\Users\Ron\Desktop\Test\summer.png')
im1.save(r'C:\Users\Ron\Desktop\Test\new_summer.jpg')
