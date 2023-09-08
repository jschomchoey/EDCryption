from tkinter import *
from tkinter import filedialog
import os
import tkinter as tk

root = tk.Tk()
root.withdraw() #use to hide tkinter window

currdir = os.getcwd()
tempdir = filedialog.askdirectory(parent=root, initialdir=currdir, title='Please select a directory')
if len(tempdir) > 0:
    print ("You chose %s" % tempdir)