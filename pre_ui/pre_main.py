from tkinter import *
from tkinter import ttk
import tkinter as tk

def switch_to_encryption_page():
    notebook.select(encryption_frame)

def switch_to_decryption_page():
    notebook.select(decryption_frame)

app = Tk()
app.title("Encryption / Decryption")
app.minsize(700, 350)
app.resizable(False, False)

notebook = ttk.Notebook(app)
notebook.pack(fill='both', expand=True)

style = ttk.Style()
style.configure("TNotebook.Tab", padding=(175, 7))

# Encryption Page
encryption_frame = Frame(notebook)
notebook.add(encryption_frame, text='Encryption')

encryption_button = Button(encryption_frame, text="Encrypt")
encryption_button.pack(pady=10)

# Decryption Page
decryption_frame = Frame(notebook)
notebook.add(decryption_frame, text='Decryption')

decryption_button = Button(decryption_frame, text="Decrypt")
decryption_button.pack(pady=10)

app.mainloop()
