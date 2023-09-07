from tkinter import *
from tkinter import ttk
import tkinter as tk

# Screen
app = tk.Tk()
app.title("Encryption / Decryption")
# app.config(bg="skyblue")

app.minsize(700, 350)
app.resizable(False, False)

# Object
def print_something():
    print("Button bind working!")

# Mode Entry
mode_frame = Frame(app)
mode_frame.pack(fill=tk.X)

button = tk.Button(
    mode_frame, text="Encryption", command=print_something, borderwidth=0, height=2
)
button.pack(side="left", fill=tk.X, expand=True)
button = tk.Button(
    mode_frame, text="Decryption", command=print_something, borderwidth=0, height=2
)
button.pack(side="left", fill=tk.X, expand=True)

# Path Entry
path_frame = Frame(app)
path_frame.pack(fill=tk.X, pady=10, padx=20)

Label(path_frame, text="         Path").pack(side="left")

username_entry = Entry(path_frame)
username_entry.pack(side="left", fill=tk.X, expand=True, padx=10)

button = tk.Button(
    path_frame, text="Browse", command=print_something, height=1, width=10
)
button.pack()

# Password Entry
password_frame = Frame(app)
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
progress = Entry(app)
progress.pack(fill=tk.BOTH,expand=True,pady=10, padx=20)


# Progress Bar
def pBar():
    progBar["value"] += 10


progBar = ttk.Progressbar(
    app,
    orient=HORIZONTAL,
    length=700,
    mode="determinate",
)
progBar.pack(pady=15, padx=20)

app.mainloop()
