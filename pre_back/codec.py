# Define the content you want to write to the file
content = "This is a text file with ANSI encoding."

# Specify the file path and encoding
file_path = "ansi_encoded.txt"
encoding = 'cp1252'  # You can also use 'latin1' for ANSI encoding

# Open the file in write mode with the specified encoding
with open(file_path, 'w', encoding="ansi") as file:
    # Write the content to the file
    file.write(content)

print(f"Text file '{file_path}' with ANSI encoding has been created.")