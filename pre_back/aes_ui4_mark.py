import tkinter as tk
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

def encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padtext = pad(plaintext.encode(), AES.block_size)
    ctext = cipher.encrypt(padtext)
    encodedctext = base64.b64encode(ctext)
    return encodedctext

def decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decodedctext = base64.b64decode(ciphertext)
    padded_plaintext = cipher.decrypt(decodedctext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    return plaintext.decode("utf-8")

def encrypt_button_clicked():
    plaintext = plaintext_entry.get()
    enc = encrypt(plaintext, key)
    result_label.config(text="Encrypted data: " + enc.decode())

def decrypt_button_clicked():
    ciphertext = ciphertext_entry.get()
    decrypted = decrypt(ciphertext, key)
    result_label.config(text="Decrypted data: " + decrypted)

# Generate a random encryption key
key = get_random_bytes(16)

# Create the main window
root = tk.Tk()
root.title("AES Encryption/Decryption")

# Create and place widgets
plaintext_label = tk.Label(root, text="Enter the plaintext:")
plaintext_label.pack()

plaintext_entry = tk.Entry(root)
plaintext_entry.pack()

encrypt_button = tk.Button(root, text="Encrypt", command=encrypt_button_clicked)
encrypt_button.pack()

ciphertext_label = tk.Label(root, text="Enter the ciphertext:")
ciphertext_label.pack()

ciphertext_entry = tk.Entry(root)
ciphertext_entry.pack()

decrypt_button = tk.Button(root, text="Decrypt", command=decrypt_button_clicked)
decrypt_button.pack()

result_label = tk.Label(root, text="")
result_label.pack()

root.mainloop()
