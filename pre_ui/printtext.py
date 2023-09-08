from tkinter import *

root = Tk()
root.geometry("300x300")
root.title(" Q&A ")

def Take_input():
	INPUT = 0
	print(INPUT)
	if(INPUT == "120"):
		Output.insert(END, 'Correct')
	else:
		Output.insert(END, "Wrong answer")

Output = Text(root, height = 5,
			width = 25,
			bg = "light cyan")

Display = Button(root, height = 2,
				width = 20,
				text ="Show",
				command = lambda:Take_input())

Display.pack()
Output.pack()

mainloop()
