# Python program to find MD5 hash value of a file
import hashlib
 
filename = "C:\Data\Code\EDCryption\examplefile\long_textfile_thai.txt"
md5_hash = hashlib.md5()
with open(filename,"rb") as f:
    # Read and update hash in chunks of 4K
    for byte_block in iter(lambda: f.read(4096),b""):
        md5_hash.update(byte_block)
    print(md5_hash.hexdigest())