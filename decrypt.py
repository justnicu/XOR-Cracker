import sys
import base64

# Decrypts the encrypted text by XORing the characters found in the input and the key at the same positions modulo KEY_LENGTH
# It is the same as the encrypt function because of the properties of the XOR operation (input ^ key) ^ key = input
def decrypt(encrypted_txt, key):
    decrypted = ''
    idx = 0
    for ch in encrypted_txt:
        decrypted += chr(ord(ch) ^ ord(key[idx]))
        idx = (idx + 1) % len(key)
    return decrypted

# Takes the arguments from the CLI
encrypted_file = sys.argv[1]
decrypted_file = sys.argv[2]
key = sys.argv[3]

# Reads the encrypted input
encrypted_file = open(encrypted_file)
encrypted_txt = encrypted_file.read()

# Decodes the encrypted input from base64
encrypted_txt = base64.b64decode(encrypted_txt)
encrypted_txt = encrypted_txt.decode("utf-8")

# Decrypts the encrypted message
decrypted_txt = decrypt(encrypted_txt, key)

# Creates the ouput file and prints the output
decrypted_file = open(decrypted_file, "w")
print(decrypted_txt, file=decrypted_file)
