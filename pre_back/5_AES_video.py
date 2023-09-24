from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from moviepy.editor import VideoFileClip
import numpy as np
import pyglet
import shutil

def encrypt_video(input_file, output_file, key, iv):
    # Initialize the AES cipher in CBC mode with the provided key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Read the MP4 file
    video_clip = VideoFileClip(input_file)

    # Encrypt the video frames and write them to the output file
    with open(output_file, 'wb') as output_stream:
        output_stream.write(key)
        output_stream.write(iv)
        
        for frame in video_clip.iter_frames(fps=video_clip.fps, dtype='uint8'):
            # Convert the numpy array to bytes
            frame_bytes = bytes(frame)
            encrypted_frame = cipher.encrypt(frame_bytes)
            output_stream.write(encrypted_frame)

    print(f'Encryption completed. Encrypted video saved to {output_file}')

def preview_video(video_file):
    player = pyglet.media.Player()
    source = pyglet.media.load(video_file)
    player.queue(source)
    player.play()
    pyglet.app.run()

# Define your encryption key and initialization vector (IV)
key = get_random_bytes(16)
iv = get_random_bytes(16)

# Input and output file paths
input_file = '/Users/jschomchoey/Data/Code/EDCryption/examplefile/Video/The Kid LAROI, Justin Bieber - STAY (Official Video).mp4'
encrypted_file = 'encrypted.mp4'

# Encrypt the video
encrypt_video(input_file, encrypted_file, key, iv)

# Copy the encrypted video to a temporary location for previewing
temp_encrypted_file = 'temp_encrypted.mp4'
shutil.copy(encrypted_file, temp_encrypted_file)

# Preview the encrypted video (temporary file)
preview_video(temp_encrypted_file)
