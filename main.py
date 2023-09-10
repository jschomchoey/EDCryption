# Read the PNG file data into memory (binary)
with open("C:\Data\Code\EDCryption\examplefile\code.png", 'rb') as file:
    image_data = file.read()

# Locate the start and end of the IDAT chunk (where image data begins)
start_marker = b'\x49\x44\x41\x54'  # IDAT chunk signature
start_index = image_data.find(start_marker)

if start_index == -1:
    raise ValueError("No IDAT chunk found in the PNG file")

end_index = start_index + 8  # Length of the IDAT chunk header

# Find the end of the IDAT chunk
while end_index < len(image_data):
    chunk_length = int.from_bytes(image_data[end_index:end_index + 4], byteorder='big')
    if image_data[end_index + 4:end_index + 8] == b'IDAT':
        end_index += 12 + chunk_length
    else:
        break

# Locate the end of the PNG file (IEND chunk)
iend_marker = b'\x49\x45\x4E\x44'  # IEND chunk signature
iend_index = image_data.rfind(iend_marker)

if iend_index == -1:
    raise ValueError("No IEND chunk found in the PNG file")

iend_index += 12  # Length of the IEND chunk

# Extract the non-image data (header, metadata, and non-IEND trailer)
header_metadata_non_iend_trailer = image_data[:start_index]

# Modify the non-image data (for example, you can add or remove metadata)
modified_data = header_metadata_non_iend_trailer  # Modify this part as needed

# Reconstruct the PNG file with the modified non-image data, original IDAT, and IEND chunks
modified_image_data = modified_data + image_data[start_index:end_index] + image_data[iend_index:]

# Save the modified PNG data to a new file
with open('modified_image.png', 'wb') as file:
    file.write(modified_image_data)
