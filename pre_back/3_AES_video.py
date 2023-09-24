from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from pydub import AudioSegment
import io

# Function to pad data to match AES block size (16 bytes)
def pad(data):
    block_size = 16
    return data + (block_size - len(data) % block_size) * bytes([block_size - len(data) % block_size])

# Function to encrypt audio file using AES
def encrypt_audio(input_file, output_file, key):
    audio = AudioSegment.from_mp3(input_file)
    audio_data = audio.raw_data
    audio_data_padded = pad(audio_data)

    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_audio = cipher.encrypt(audio_data_padded)

    with open(output_file, 'wb') as f:
        f.write(encrypted_audio)

# Function to decrypt audio file using AES
def decrypt_audio(input_file, output_file, key):
    with open(input_file, 'rb') as f:
        encrypted_audio = f.read()

    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_audio_padded = cipher.decrypt(encrypted_audio)
    decrypted_audio = decrypted_audio_padded.rstrip(bytes([decrypted_audio_padded[-1]]))

    # Get audio format information from the original MP3 file
    audio_format = AudioSegment.from_mp3(input_file).export("temp.wav", format="wav").export()
    
    audio = AudioSegment(
        io.BytesIO(decrypted_audio),
        sample_width=audio_format.sample_width,
        frame_rate=audio_format.frame_rate,
        channels=audio_format.channels
    )

    audio.export(output_file, format="mp3")

if __name__ == "__main__":
    input_audio_file = "/Users/jschomchoey/Data/Code/EDCryption/examplefile/Sound/Lost Sky.mp3"
    encrypted_audio_file = "encrypted_audio.enc"
    decrypted_audio_file = "decrypted_audio.mp3"
    encryption_key = get_random_bytes(16)  # AES-128 key

    encrypt_audio(input_audio_file, encrypted_audio_file, encryption_key)
    decrypt_audio(encrypted_audio_file, decrypted_audio_file, encryption_key)
