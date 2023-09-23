# Update v1.5.1-beta
from tkinter import *
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox
from tkinter.filedialog import askopenfile
import tkinter as tk

import os

from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

import hashlib

from PIL import Image

# screen
app = tk.Tk()
app.title("EDCryption 1.5.1 Beta")
# app.config(bg="skyblue")

app.minsize(800, 400)
app.maxsize(800, 400)
app.resizable(False, False)


# switch to encrytion page
def switch_to_encryption_page():
    notebook.select(encryption_frame)


# switch to decrytion page
def switch_to_decryption_page():
    notebook.select(decryption_frame)


# open file in encrytion page
def openfile_en():
    file = filedialog.askopenfile(
        mode="r",
        filetypes=[
            ("All Files", "*.*"),
            ("Text Files", "*.txt"),
            ("Picture Files", "*.bmp *.png *.jpg *.jpeg"),
            ("Vector Files", "*.pdf"),
            ("Music Files", "*.mp3"),
            ("Video Files", "*.mp4 *.mov"),
        ],
    )
    if file:
        path_entry_en.delete(0, END)
        filepath = os.path.abspath(file.name)
        path_entry_en.insert(END, str(filepath))


# open file in decrytion page
def openfile_de():
    file = filedialog.askopenfile(
        mode="r",
        filetypes=[
            ("All Files", "*.*"),
            ("Text Files", "*.txt"),
            ("Picture Files", "*bmp *.png *.jpg *.jpeg"),
            ("Vector Files", "*.pdf"),
            ("Music Files", "*.mp3"),
            ("Video Files", "*.mp4 *.mov"),
        ],
    )
    if file:
        path_entry_de.delete(0, END)
        filepath = os.path.abspath(file.name)
        path_entry_de.insert(END, str(filepath))


def filetype(plaintext):
    file_name, file_extension = os.path.splitext(plaintext)
    print(file_extension)
    return file_extension


# encrytion function
def encrypt_file(input_file, output_file, key):
    cipher = AES.new(key, AES.MODE_EAX)

    with open(input_file, "rb") as infile, open(output_file, "wb") as outfile:
        ciphertext, tag = cipher.encrypt_and_digest(infile.read())
        outfile.write(cipher.nonce)
        outfile.write(tag)
        outfile.write(ciphertext)


# decrytion function
def decrypt_file(input_file, output_file, key):
    with open(input_file, "rb") as infile, open(output_file, "wb") as outfile:
        nonce = infile.read(16)
        tag = infile.read(16)
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        ciphertext = infile.read()

        try:
            plaintext = cipher.decrypt(ciphertext)
            outfile.write(plaintext)
        except ValueError:
            print("Decryption failed. The key may be incorrect.")


# press encrytion button
def encrypt_button_clicked():
    progress_en.delete("1.0", "end")
    progress_en.insert(tk.END, "Encrypting... \n")

    text = password_entry_en.get()
    print(text)

    # print key
    padded_byte_object = make_16_bytes(text)
    print(padded_byte_object)
    print(len(padded_byte_object))
    key_en = padded_byte_object

    # path file
    plaintext = path_entry_en.get()

    filetype_en = filetype(plaintext)

    encrypted_file = "encrypted_file" + filetype_en

    print(filetype_en)

    if (
        filetype_en == ".png"
        or filetype_en == ".jpg"
        or filetype_en == ".jpeg"
        or filetype_en == ".ppm"
        or filetype_en == ".gif"
        or filetype_en == ".tiff"
        or filetype_en == ".bmp"
    ):
        # image encrypt
        if filetype_en == ".png":
            format = "png"
        elif filetype_en == ".jpg":
            format = "jpeg"
        elif filetype_en == ".jpeg":
            format = "jpeg"
        elif filetype_en == ".ppm":
            format = "ppm"
        elif filetype_en == ".gif":
            format = "gif"
        elif filetype_en == ".tiff":
            format = "tiff"
        elif filetype_en == ".bmp":
            format = "bmp"

        print("image file detected")
        filename_out = "encrypted_img"
        filename = plaintext
        key = key_en
        process_image(filename, key, format, filename_out)
    else:
        # all file encrypt
        print("non-image file detected")
        encrypt_file(plaintext, encrypted_file, key_en)

    # md5 check
    # md5check = plaintext
    # md5_hash = hashlib.md5()
    # with open(md5check, "rb") as f:
    # Read and update hash in chunks of 4K
    # for byte_block in iter(lambda: f.read(4096), b""):
    # md5_hash.update(byte_block)

    # print
    progress_en.insert(tk.END, "Input File:  " + plaintext + "\n")
    # progress_en.insert(tk.END, "MD5 Checksum:  " + md5_hash.hexdigest() + "\n")
    dir_path = os.path.dirname(os.path.realpath(encrypted_file))
    progress_en.insert(
        tk.END, "File encrypted as:  " + dir_path + "\\" + encrypted_file + "\n"
    )


# press decrytion button
def decrypt_button_clicked():
    progress_de.delete("1.0", "end")
    progress_de.insert(tk.END, "Decrypting... \n")
    text = password_entry_de.get()
    print(text)
    padded_byte_object = make_16_bytes(text)
    print(padded_byte_object)
    print(len(padded_byte_object))

    key_de = padded_byte_object
    ciphertext = path_entry_de.get()

    filetype_de = filetype(ciphertext)
    decrypted_file = "decrypted_file" + filetype_de

    if (
        filetype_de == ".png"
        or filetype_de == ".jpg"
        or filetype_de == ".jpeg"
        or filetype_de == ".ppm"
        or filetype_de == ".gif"
        or filetype_de == ".tiff"
        or filetype_de == ".bmp"
    ):
        # image encrypt
        if filetype_de == ".png":
            format = "png"
        elif filetype_de == ".jpg":
            format = "jpeg"
        elif filetype_de == ".jpeg":
            format = "jpeg"
        elif filetype_de == ".ppm":
            format = "ppm"
        elif filetype_de == ".gif":
            format = "gif"
        elif filetype_de == ".tiff":
            format = "tiff"
        elif filetype_de == ".bmp":
            format = "bmp"

        print("image file detected")
        filename_out = "encrypted_img"
        filename = ciphertext
        key = key_de
        ##process_image(filename, key, format, filename_out)
        decrypt_image(filename_out, filename, format, key)
        md5check = filename_out
    else:
        # all file encrypt
        print("non-image file detected")
        decrypt_file(ciphertext, decrypted_file, key_de)
        md5check = decrypted_file

    # md5_hash = hashlib.md5()
    # with open(md5check, "rb") as f:
    # Read and update hash in chunks of 4K
    # for byte_block in iter(lambda: f.read(4096), b""):
    # md5_hash.update(byte_block)

    progress_de.insert(tk.END, "Input File:  " + ciphertext + "\n")
    # progress_de.insert(tk.END, "MD5 Checksum:  " + md5_hash.hexdigest() + "\n")
    dir_path = os.path.dirname(os.path.realpath(decrypted_file))
    progress_de.insert(
        tk.END, "File decrypted as:  " + dir_path + "\\" + decrypted_file + "\n"
    )


# make normal password to 16 bytes (128-AES)
def make_16_bytes(text):
    byte_object = bytes(text, "utf-8")
    padding_length = 16 - len(byte_object)
    padding = b"\x01" * padding_length
    padded_byte_object = padding + byte_object
    return padded_byte_object


# ---------------------Image-----------------------


def convert_to_RGB(data):
    r, g, b = tuple(
        map(lambda d: [data[i] for i in range(0, len(data)) if i % 3 == d], [0, 1, 2])
    )
    pixels = tuple(zip(r, g, b))
    return pixels


def process_image(filename, key, format, filename_out):
    # Opens image and converts it to RGB format for PIL
    im = Image.open(filename)
    data = im.convert("RGB").tobytes()

    # Since we will pad the data to satisfy AES's multiple-of-16 requirement, we will store the original data length and "unpad" it later.
    original = len(data)

    # Encrypts using desired AES mode (we'll set it to CBC by default)
    encrypted_data = aes_cbc_encrypt(key, pad(data))[:original]

    # Create a new PIL Image object and save the old image data into the new image.
    im2 = Image.new(im.mode, im.size)
    im2.putdata(convert_to_RGB(encrypted_data))

    # Save image
    if format == "jpeg":
        format2 = "png"
        im2.save(filename_out + "." + format, format2)
    else:
        im2.save(filename_out + "." + format, format)


# CBC Encryption
def aes_cbc_encrypt(key, data, mode=AES.MODE_CBC):
    IV = "A" * 16  # We'll manually set the initialization vector to simplify things
    aes = AES.new(key, mode, IV.encode("utf8"))
    new_data = aes.encrypt(data)
    print("Encrypting")
    return new_data


# CBC Decryption
def aes_cbc_decrypt(key, data, mode=AES.MODE_CBC):
    IV = "A" * 16  # Same initialization vector as used for encryption
    aes = AES.new(key, mode, IV.encode("utf8"))
    decrypted_data = aes.decrypt(data)
    return decrypted_data.rstrip(b"\x00")  # Remove padding


# Decrypt the previously encrypted image
def decrypt_image(filename_out, filename, format, key):
    im = Image.open(filename)
    data = im.convert("RGB").tobytes()

    decrypted_data = aes_cbc_decrypt(key, data)

    # Create a new PIL Image object and save the decrypted data into the new image.
    im2 = Image.new(im.mode, im.size)
    im2.putdata(convert_to_RGB(decrypted_data))

    # Save the decrypted image
    if format == "jpeg":
        format2 = "png"
        im2.save("decrypted" + "." + format, format2)
    else:
        im2.save("decrypted" + "." + format, format)


def pad(data):
    return data + b"\x00" * (16 - len(data) % 16)


# screen tab
notebook = ttk.Notebook(
    app,
)
notebook.pack(fill=tk.BOTH, expand=True)
style = ttk.Style()
style.configure("TNotebook.Tab", padding=(150, 7))

# ----------------------------------- Encryption Part -----------------------------------
encryption_frame = Frame(
    notebook,
)
notebook.add(
    encryption_frame,
    text="Encryption",
)

# path entry
path_frame = Frame(encryption_frame)
path_frame.pack(fill=tk.X, pady=10, padx=20)

Label(path_frame, text="         Path").pack(side="left")

path_entry_en = Entry(path_frame)
path_entry_en.pack(side="left", fill=tk.X, expand=True, padx=10)

# browse path button
button = tk.Button(path_frame, text="Browse", command=openfile_en, height=1, width=10)
button.pack()

# password entry
password_frame = Frame(encryption_frame)
password_frame.pack(fill=tk.X, padx=20)

Label(password_frame, text="Password").pack(side="left")

password_entry_en = Entry(password_frame, show="*")
password_entry_en.pack(side="left", fill=tk.X, expand=True, padx=10)

# encryption button
button = tk.Button(
    password_frame,
    text="Encryption",
    command=lambda: [encrypt_button_clicked()],
    height=1,
    width=10,
)
button.pack()

# progress textbox
progress_frame = Frame(encryption_frame)
progress_frame.pack(fill=tk.X, padx=20, pady=10)

# progress textbox scroll bar
v = Scrollbar(progress_frame, orient="vertical")
v.pack(side=RIGHT, fill="y")

progress_en = Text(progress_frame, yscrollcommand=v.set)

v.config(command=progress_en.yview)

progress_en.pack(fill=tk.BOTH, expand=True)


# ----------------------------------- Decryption Part -----------------------------------
decryption_frame = Frame(notebook)
notebook.add(decryption_frame, text="Decryption")

# path entry
path_frame = Frame(decryption_frame)
path_frame.pack(fill=tk.X, pady=10, padx=20)

Label(path_frame, text="         Path").pack(side="left")

path_entry_de = Entry(path_frame)
path_entry_de.pack(side="left", fill=tk.X, expand=True, padx=10)

# browse path button
button = tk.Button(path_frame, text="Browse", command=openfile_de, height=1, width=10)
button.pack()

# password entry
password_frame = Frame(decryption_frame)
password_frame.pack(fill=tk.X, padx=20)

Label(password_frame, text="Password").pack(side="left")

password_entry_de = Entry(password_frame, show="*")
password_entry_de.pack(side="left", fill=tk.X, expand=True, padx=10)

# decryption button
button = tk.Button(
    password_frame,
    text="Decryption",
    command=lambda: [decrypt_button_clicked()],
    height=1,
    width=10,
)
button.pack()

# progress textbox
progress_frame = Frame(decryption_frame)
progress_frame.pack(fill=tk.X, padx=20, pady=10)

# progress textbox scroll bar
v = Scrollbar(progress_frame, orient="vertical")
v.pack(side=RIGHT, fill="y")

progress_de = Text(progress_frame, yscrollcommand=v.set)

v.config(command=progress_de.yview)

progress_de.pack(fill=tk.BOTH, expand=True)

# end tkinter
app.mainloop()
