#Start by importing the Tkinter libraries

from tkinter import *
from tkinter import ttk
#After the import, create the Frame by Using the TK() Method
frame = Tk()
frame.title("LinuxHint - Progress Bar")
frame.geometry("400x200")
window = Frame(frame)
#Method to Increase Progress Value
def pBar():
    progBar['value']+=10
#Build Progressbar
progBar = ttk.Progressbar(frame,orient=HORIZONTAL, length=400,mode="determinate")
progBar.pack(pady=40)
#Build Button
btn = Button(frame, text="Click Here!",command=pBar)
btn.pack(pady=10)
frame.mainloop()