# Import the required Libraries
from tkinter import *
from tkinter import ttk, filedialog
from tkinter.filedialog import askopenfile
import os
import tkinter as tk

# Create an instance of tkinter frame
win = Tk()

# Set the geometry of tkinter frame
win.geometry("700x350")

def openfile():
   file = filedialog.askopenfile(mode='r', filetypes=[('Python Files', '*.py'),('All Files', '*.')])
   if file:
      filepath = os.path.abspath(file.name)
      username_entry.insert(END, str(filepath))

# Create a Button
ttk.Button(win, text="Browse", command=openfile).pack(pady=20)

username_entry = Entry(win)
username_entry.pack(side="left", fill=tk.X, expand=True, padx=10)

win.mainloop()