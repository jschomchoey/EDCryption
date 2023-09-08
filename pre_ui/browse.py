from tkinter import filedialog
from tkinter import *

root = Tk()
def selection():
    root.filename = filedialog.askopenfile(initialdir = "/",title = "Select file",filetypes = (("files","*.exe"),("all files","*.*")))
    print(root.filename)
Button(text = ' Browse ' ,bd = 3 ,font = ('',10),padx=5,pady=5, command=selection).grid(row=1,column=1)
root.mainloop()