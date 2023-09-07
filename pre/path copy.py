# Import the required Libraries
from tkinter import *
from tkinter import ttk, filedialog
from tkinter.filedialog import askopenfile
import os

# Create an instance of tkinter frame
win = Tk()

# Set the geometry of tkinter frame
win.geometry("700x350")

def open_file():
   file = filedialog.askopenfile(mode='r', filetypes=[('Python Files', '*.py'),('All Files', '*.')])
   if file:
      filepath = os.path.abspath(file.name)
      Label(win, text="The File is located at : " + str(filepath), font=('Aerial 11')).pack()

# Add a Label widget
label = Label(win, text="Click the Button to browse the Files", font=('Georgia 13'))
label.pack(pady=10)

# Create a Button
ttk.Button(win, text="Browse", command=open_file).pack(pady=20)

win.mainloop()