from scipy.io import wavfile
import numpy as np

# Read the audio file
fs, data = wavfile.read('/Users/jschomchoey/Data/Code/EDCryption/examplefile/Sound/GLORIA GROOVE - A QUEDA (CLIPE OFICIAL).wav')

p1 = int(input("Enter a prime number: "))
p2 = int(input("Enter another prime number: "))

n = p1 * p2
print("n = p1 * p2 = ", n)

e = int(input("Enter a small, odd number, co-prime with n: "))
k = int(input("Enter value of k:"))
phi = (p1 - 1) * (p2 - 1)
print("phi = ", phi)
d = int((k * phi + 1) / e)
print("d = ", d)
public_key = n, e
private_key = n, d

print("Public Key = ", public_key)
print("Private Key = ", private_key)

# Encryption
encrypted = (data ** e) % n
encrypted = np.asarray(encrypted, dtype=np.int16)

# Save the encrypted audio to a file
wavfile.write('encrypted_rsa.wav', fs, encrypted)
print("Encrypted")

# Decryption
fs, encrypted_data = wavfile.read('encrypted_rsa.wav')
decrypted = (encrypted_data ** d) % n
decrypted = np.asarray(decrypted, dtype=np.int16)

# Save the decrypted audio to a file
wavfile.write('decrypted_rsa.wav', fs, decrypted)
print("Decrypted")
