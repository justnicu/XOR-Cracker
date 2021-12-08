import sys
import base64

# A function that encrypts a text with a key by XORing the characters found at the same positions modulo KEY_LENGTH
def encrypt(input_txt, key):
    output = ''
    idx = 0
    for ch in input_txt:
        output += chr(ord(ch) ^ ord(key[idx]))
        idx = (idx + 1) % len(key)
    return output

# Takes the arguments from the CLI
input_file = sys.argv[1]
output_file = sys.argv[2]
key = sys.argv[3]

# Reads the input and computes the output
input_file = open(input_file)
input_txt = input_file.read()
output = encrypt(input_txt, key)

# Encodes the output to base64 utf-8 so it can be easily viewed
output = base64.encodebytes(output.encode())
output = output.decode('utf-8')

# Creates the ouput file and prints the output
output_file = open(output_file, "w")
print(output, file=output_file)
