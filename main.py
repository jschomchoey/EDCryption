# Update v1.5.3
import tkinter as tk
import os
from tkinter import *
from tkinter import ttk, filedialog
from Crypto.Cipher import AES
from PIL import Image

# screen setup
app = tk.Tk()
app.title("EDCryption 1.5.3")
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
            ("Image Files", "*.png *.jpg *.jpeg *.jp2"),
            ("Image Files", "*.tiff *.ppm *.bmp"),
            ("Music Files", "*.mp3 *.wav"),
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
            ("Image Files", "*.png *.jpg *.jpeg *.jp2"),
            ("Image Files", "*.tiff *.ppm *.bmp"),
            ("Music Files", "*.mp3 *.wav"),
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


# -------------------------- All File ----------------------------
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


# -------------------------- Image ----------------------------
def convert_to_RGB(data):
    r, g, b = tuple(
        map(lambda d: [data[i] for i in range(0, len(data)) if i % 3 == d], [0, 1, 2])
    )
    pixels = tuple(zip(r, g, b))
    return pixels


def encrypt_image(filename, key, format, filename_out):
    # Opens image and converts it to RGB format for PIL
    im = Image.open(filename)
    data = im.convert("RGB").tobytes()

    # Since we will pad the data to satisfy AES's multiple-of-16 requirement, we will store the original data length and "unpad" it later.
    original = len(data)

    # Encrypts using desired AES mode (we'll set it to CBC by default)
    encrypted_data = aes_eax_encrypt(key, pad(data))[:original]

    # Create a new PIL Image object and save the old image data into the new image.
    im2 = Image.new(im.mode, im.size)
    im2.putdata(convert_to_RGB(encrypted_data))

    # Save image
    if format == "jpeg" or format == "jpg" or format == "jp2":
        format2 = "png"
        im2.save("encrypted" + "." + format, format2)
    else:
        im2.save("encrypted" + "." + format, format)


# Decrypt the previously encrypted image
def decrypt_image(filename_out, filename, format, key):
    im = Image.open(filename)
    data = im.convert("RGB").tobytes()

    decrypted_data = aes_eax_decrypt(key, data)

    # Create a new PIL Image object and save the decrypted data into the new image.
    im2 = Image.new(im.mode, im.size)
    im2.putdata(convert_to_RGB(decrypted_data))

    # Save the decrypted image
    if format == "jpeg" or format == "jpg" or format == "jp2":
        format2 = "png"
        im2.save("decrypted" + "." + format, format2)
    else:
        im2.save("decrypted" + "." + format, format)


# EAX Encryption
def aes_eax_encrypt(key, data, mode=AES.MODE_EAX):
    IV = "A" * 16  # We'll manually set the initialization vector to simplify things
    aes = AES.new(key, mode, IV.encode("utf8"))
    new_data = aes.encrypt(data)
    print("Encrypted")
    return new_data


# EAX Decryption
def aes_eax_decrypt(key, data, mode=AES.MODE_EAX):
    IV = "A" * 16  # Same initialization vector as used for encryption
    aes = AES.new(key, mode, IV.encode("utf8"))
    decrypted_data = aes.decrypt(data)
    return decrypted_data.rstrip(b"\x00")  # Remove padding


def pad(data):
    return data + b"\x00" * (16 - len(data) % 16)


# -------------------------- Encryption Button ----------------------------
# press encrytion button
def encrypt_button_clicked():
    # clear progress box
    progress_en.delete("1.0", "end")

    # get password
    password = password_entry_en.get()
    print(password)

    # make key
    key_en = make_16_bytes(password)
    print(key_en)

    # input file path
    inputfile = path_entry_en.get()

    # input file type
    filetype_en = filetype(inputfile)

    # name encrypted file with same extention as input file
    encrypted_file = "encrypted_file" + filetype_en

    # select image file to encryption in image mode
    if (
        filetype_en == ".png"
        or filetype_en == ".jpg"
        or filetype_en == ".jpeg"
        or filetype_en == ".ppm"
        or filetype_en == ".tiff"
        or filetype_en == ".bmp"
    ):
        if filetype_en == ".png":
            format = "png"
        elif filetype_en == ".jpg":
            format = "jpg"
        elif filetype_en == ".jpeg":
            format = "jpeg"
        elif filetype_en == ".ppm":
            format = "ppm"
        elif filetype_en == ".tiff":
            format = "tiff"
        elif filetype_en == ".bmp":
            format = "bmp"

        # debug image mode
        print("image file detected")
        progress_en.insert(tk.END, "Image file detected\n")

        # set file name
        filename_out = "encrypted"
        filename = inputfile

        # process encrypt image
        encrypt_image(filename, key_en, format, filename_out)
    else:
        # all file encrypt
        print("non-image file detected")
        encrypt_file(inputfile, encrypted_file, key_en)

    # print progress
    progress_en.insert(tk.END, "Encrypt Complete\n")
    progress_en.insert(tk.END, "Input File:  " + inputfile + "\n")
    dir_path = os.path.dirname(os.path.realpath(encrypted_file))
    progress_en.insert(
        tk.END, "File encrypted as:  " + dir_path + "\\" + encrypted_file + "\n"
    )


# -------------------------- Decryption Button ----------------------------
# press decrytion button
def decrypt_button_clicked():
    # clear progress box
    progress_de.delete("1.0", "end")

    # get password
    password = password_entry_de.get()
    print(password)

    # make key
    key_de = make_16_bytes(password)
    print(key_de)

    # excrypted file path
    excryptedfile = path_entry_de.get()

    # excrypted file type
    filetype_de = filetype(excryptedfile)

    # name decrypted file with same extention as input file
    decrypted_file = "decrypted_file" + filetype_de

    # select image file to encryption in image mode
    if (
        filetype_de == ".png"
        or filetype_de == ".jpg"
        or filetype_de == ".jpeg"
        or filetype_de == ".ppm"
        or filetype_de == ".tiff"
        or filetype_de == ".bmp"
    ):
        if filetype_de == ".png":
            format = "png"
        elif filetype_de == ".jpg":
            format = "jpg"
        elif filetype_de == ".jpeg":
            format = "jpeg"
        elif filetype_de == ".ppm":
            format = "ppm"
        elif filetype_de == ".tiff":
            format = "tiff"
        elif filetype_de == ".bmp":
            format = "bmp"

        # debug image mode
        print("image file detected")
        progress_en.insert(tk.END, "Image file detected\n")

        # set file name
        filename_out = "decrypted"
        filename = excryptedfile

        # process decrypt image
        decrypt_image(filename_out, filename, format, key_de)
    else:
        # all file encrypt
        print("non-image file detected")
        decrypt_file(excryptedfile, decrypted_file, key_de)

    # print progress
    progress_de.insert(tk.END, "Decrypt Complete\n")
    progress_de.insert(tk.END, "Input File:  " + excryptedfile + "\n")
    dir_path = os.path.dirname(os.path.realpath(decrypted_file))
    progress_de.insert(
        tk.END, "File decrypted as:  " + dir_path + "\\" + decrypted_file + "\n"
    )


# pad plaintext password to 16 bytes (128-AES)
def make_16_bytes(text):
    byte_object = bytes(text, "utf-8")
    padding_length = 16 - len(byte_object)
    padding = b"\x01" * padding_length
    padded_byte_object = padding + byte_object
    return padded_byte_object


# tkinter screen tab
notebook = ttk.Notebook(
    app,
)
notebook.pack(fill=tk.BOTH, expand=True)
style = ttk.Style()
style.configure("TNotebook.Tab", padding=(150, 7))

# ----------------------------------- Encryption Page -----------------------------------
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


# ----------------------------------- Decryption Page -----------------------------------
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
