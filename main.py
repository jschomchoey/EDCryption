# Update 0.1.0
from tkinter import *
from tkinter import ttk
from tkinter import filedialog
from tkinter.filedialog import askopenfile
import os
import tkinter as tk

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

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
            ("All Files", "*."),
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
    plaintext = path_entry_en.get()

    # openfile
    f = open(plaintext, "r")
    readfile = f.read()
    print(readfile)
    # plaintext = f.read()

    enc = encrypt(readfile, key)
    #result_label.config(text="Encrypted data: " + enc.decode())
    progress_en.delete(0, END)
    progress_en.insert(0, enc.decode())
    # progress_en.insert(0,"\n")

    # creat encrypted file
    name = "Encrypted"
    with open(name + ".txt", "w") as f:
        f.write(enc.decode())


def decrypt_button_clicked():
    ciphertext = path_entry_de.get()

    f = open(ciphertext, "r")
    readfile = f.read()
    print(readfile)

    decrypted = decrypt(readfile, key)
    #result_label.config(text="Decrypted data: " + decrypted)
    progress_de.delete(0, END)
    progress_de.insert(0, decrypted)
    # progress_de.insert(0,"\n")

    name = "Decrypted"
    with open(name + ".txt", "w") as f:
        f.write(decrypted)


key = get_random_bytes(16)

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

username_entry = Entry(password_frame)
username_entry.pack(side="left", fill=tk.X, expand=True, padx=10)

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
progress_en = Entry(encryption_frame)
progress_en.pack(fill=tk.BOTH, expand=True, pady=10, padx=20)


# Progress Bar
def pBar():
    progBar["value"] += 10


progBar = ttk.Progressbar(
    encryption_frame,
    orient=HORIZONTAL,
    length=700,
    mode="determinate",
)
progBar.pack(pady=15, padx=20)

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

username_entry = Entry(password_frame)
username_entry.pack(side="left", fill=tk.X, expand=True, padx=10)

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
progress_de = Entry(decryption_frame)
progress_de.pack(fill=tk.BOTH, expand=True, pady=10, padx=20)


# Progress Bar
def pBar():
    progBar["value"] += 10


progBar = ttk.Progressbar(
    decryption_frame,
    orient=HORIZONTAL,
    length=700,
    mode="determinate",
)
progBar.pack(pady=15, padx=20)

#result_label = tk.Label(app, text="")
#result_label.pack()

app.mainloop()
