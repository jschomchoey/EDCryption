from tkinter import *
from tkinter import ttk
from tkinter import filedialog
from tkinter.filedialog import askopenfile
import os
import tkinter as tk

app = tk.Tk()
app.title("Encryption / Decryption")
app.config(bg="skyblue")

app.minsize(700, 350)
app.maxsize(700, 350)
app.resizable(False, False)

path_entry_en = Entry(app)
path_entry_en.pack(side="left", fill=tk.X, expand=True, padx=10)

button = tk.Button(
    app,
    text="Encryption",
    command=lambda: [encrypt_button_clicked()],
    height=1,
    width=10,
    bg="black",
    fg="#fff",
)
button.pack()


def make_16_bytes(text):
  byte_object = bytes(text, "utf-8")
  padding_length = 16 - len(byte_object)
  padding = b'\x00' * padding_length

  padded_byte_object = padding + byte_object

  return padded_byte_object

def encrypt_button_clicked():
    text = path_entry_en.get()
    print(text)
    padded_byte_object = make_16_bytes(text)
    print(padded_byte_object)

app.mainloop()