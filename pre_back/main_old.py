from tkinter import *
from tkinter import ttk
from tkinter import filedialog
from tkinter.filedialog import askopenfile
import os
import tkinter as tk

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
    command=print_something,
    height=1,
    width=10,
    bg="black",
    fg="#fff",
)
button.pack()

# Progress
progress = Entry(encryption_frame)
progress.pack(fill=tk.BOTH, expand=True, pady=10, padx=20)


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
    command=print_something,
    height=1,
    width=10,
    bg="black",
    fg="#fff",
)
button.pack()

# Progress
progress = Entry(decryption_frame)
progress.pack(fill=tk.BOTH, expand=True, pady=10, padx=20)


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

app.mainloop()
