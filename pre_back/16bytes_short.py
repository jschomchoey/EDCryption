def pad_text(text, length):
  padding = length - len(text)
  return text + (chr(0) * padding)

text = "12345"
padded_text = pad_text(text, 16)

print(padded_text)
