# Update 1.2.1
from tkinter import *
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox
from tkinter.filedialog import askopenfile
import os
import tkinter as tk

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

import chardet

# Screen
app = tk.Tk()
app.title("Encryption / Decryption")
app.config(bg="skyblue")

app.minsize(700, 350)
app.maxsize(700, 350)
app.resizable(False, False)


# Object
def print_something():
    print("Button working!")


def switch_to_encryption_page():
    notebook.select(encryption_frame)


def switch_to_decryption_page():
    notebook.select(decryption_frame)


def openfile_en():
    file = filedialog.askopenfile(
        mode="r",
        filetypes=[
            ("Text Files", "*.txt"),
            ("Picture Files", "*.png *.jpg *.jpeg"),
            ("Video Files", "*.mp4 *.mov"),
            ("All Files", "*.*"),
        ],
    )
    if file:
        path_entry_en.delete(0, END)
        filepath = os.path.abspath(file.name)
        path_entry_en.insert(END, str(filepath))


def openfile_de():
    file = filedialog.askopenfile(
        mode="r",
        filetypes=[
            ("Text Files", "*.txt"),
            ("Picture Files", "*.png *.jpg *.jpeg"),
            ("Video Files", "*.mp4 *.mov"),
            ("All Files", "*."),
        ],
    )
    if file:
        path_entry_de.delete(0, END)
        filepath = os.path.abspath(file.name)
        path_entry_de.insert(END, str(filepath))


def encrypt(plaintext, key_en):
    cipher = AES.new(key_en, AES.MODE_ECB)
    padtext = pad(plaintext.encode(), AES.block_size)
    ctext = cipher.encrypt(padtext)
    encodedctext = base64.b64encode(ctext)
    return encodedctext


def decrypt(ciphertext, key_de):
    cipher = AES.new(key_de, AES.MODE_ECB)
    decodedctext = base64.b64decode(ciphertext)
    padded_plaintext = cipher.decrypt(decodedctext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    return plaintext.decode("utf-8")


def encrypt_button_clicked():
    progress_en.delete("1.0", "end")

    text = password_entry_en.get()
    print(text)
    padded_byte_object = make_16_bytes(text)
    print(padded_byte_object)
    print(len(padded_byte_object))

    key_en = padded_byte_object

    plaintext = path_entry_en.get()

    rawdata = open(plaintext, "rb").read()
    result = chardet.detect(rawdata)
    charenc = result["encoding"]
    print(charenc)
    if charenc == "utf-8":
        f = open(plaintext, "r", encoding="utf8")
    else:
        f = open(plaintext, "r", encoding="ansi")

    readfile = f.read()
    print(readfile)
    enc = encrypt(readfile, key_en)
    progress_en.insert(tk.END, enc.decode() + "\n")

    # creat encrypted file
    name = "Encrypted"
    with open(name + ".txt", "w") as f:
        f.write(enc.decode())


def decrypt_button_clicked():
    progress_de.delete("1.0", "end")
    text = password_entry_de.get()
    print(text)
    padded_byte_object = make_16_bytes(text)
    print(padded_byte_object)
    print(len(padded_byte_object))

    key_de = padded_byte_object
    ciphertext = path_entry_de.get()

    f = open(ciphertext, "r")
    readfile = f.read()
    print(readfile)

    decrypted = decrypt(readfile, key_de)
    progress_de.insert(tk.END, decrypted + "\n")

    name = "Decrypted"
    with open(name + ".txt", "w", encoding="utf8") as f:
        f.write(decrypted)


def make_16_bytes(text):
    byte_object = bytes(text, "utf-8")
    padding_length = 16 - len(byte_object)
    padding = b"\x00" * padding_length

    padded_byte_object = padding + byte_object

    return padded_byte_object


notebook = ttk.Notebook(
    app,
)
notebook.pack(fill=tk.BOTH, expand=True)

style = ttk.Style()
style.configure("TNotebook.Tab", padding=(141, 7))

# ----------------------------------- Encryption Part -----------------------------------
encryption_frame = Frame(
    notebook,
)
notebook.add(
    encryption_frame,
    text="Encryption",
)

# Path Entry
path_frame = Frame(encryption_frame)
path_frame.pack(fill=tk.X, pady=10, padx=20)

Label(path_frame, text="         Path").pack(side="left")

path_entry_en = Entry(path_frame)
path_entry_en.pack(side="left", fill=tk.X, expand=True, padx=10)

button = tk.Button(path_frame, text="Browse", command=openfile_en, height=1, width=10)
button.pack()

# Password Entry
password_frame = Frame(encryption_frame)
password_frame.pack(fill=tk.X, padx=20)

Label(password_frame, text="Password").pack(side="left")

password_entry_en = Entry(password_frame)
password_entry_en.pack(side="left", fill=tk.X, expand=True, padx=10)

button = tk.Button(
    password_frame,
    text="Encryption",
    command=lambda: [encrypt_button_clicked(), print_something()],
    height=1,
    width=10,
    bg="black",
    fg="#fff",
)
button.pack()

# Progress
progress_frame = Frame(encryption_frame)
progress_frame.pack(fill=tk.X, padx=20, pady=10)

v = Scrollbar(progress_frame, orient="vertical")
v.pack(side=RIGHT, fill="y")

progress_en = Text(progress_frame, yscrollcommand=v.set)

v.config(command=progress_en.yview)

progress_en.pack(fill=tk.BOTH, expand=True)


# ----------------------------------- Decryption Part -----------------------------------
decryption_frame = Frame(notebook)
notebook.add(decryption_frame, text="Decryption")

# Path Entry
path_frame = Frame(decryption_frame)
path_frame.pack(fill=tk.X, pady=10, padx=20)

Label(path_frame, text="         Path").pack(side="left")

path_entry_de = Entry(path_frame)
path_entry_de.pack(side="left", fill=tk.X, expand=True, padx=10)

button = tk.Button(path_frame, text="Browse", command=openfile_de, height=1, width=10)
button.pack()

# Password Entry
password_frame = Frame(decryption_frame)
password_frame.pack(fill=tk.X, padx=20)

Label(password_frame, text="Password").pack(side="left")

password_entry_de = Entry(password_frame)
password_entry_de.pack(side="left", fill=tk.X, expand=True, padx=10)

button = tk.Button(
    password_frame,
    text="Decryption",
    command=lambda: [decrypt_button_clicked(), print_something()],  # can't decrypt
    height=1,
    width=10,
    bg="black",
    fg="#fff",
)
button.pack()

# Progress
progress_frame = Frame(decryption_frame)
progress_frame.pack(fill=tk.X, padx=20, pady=10)

v = Scrollbar(progress_frame, orient="vertical")
v.pack(side=RIGHT, fill="y")

progress_de = Text(progress_frame, yscrollcommand=v.set)

v.config(command=progress_de.yview)

progress_de.pack(fill=tk.BOTH, expand=True)

app.mainloop()
