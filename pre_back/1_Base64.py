import base64


with open(
    "/Users/jschomchoey/Data/Code/EDCryption/examplefile/Computer Cover.png", "rb"
) as image2string:
    converted_string = base64.b64encode(image2string.read())
print(converted_string)

with open("encode.png", "wb") as file:
    file.write(converted_string)
