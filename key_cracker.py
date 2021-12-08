import sys
import base64

PROGRESS_BAR_LEN = 50
# English language letter frequency according to pi.math.cornell.edu
LETTER_FREQUENCY = {"A": 0.081200, "B": 0.014900, "C": 0.027100, "D": 0.043200, "E": 0.120200, "F": 0.023000,
                    "G": 0.020300, "H": 0.059200, "I": 0.073100, "J": 0.001000, "K": 0.006900, "L": 0.039800,
                    "M": 0.026100, "N": 0.069500, "O": 0.076800, "P": 0.018200, "Q": 0.001100, "R": 0.060200,
                    "S": 0.062800, "T": 0.091000, "U": 0.028800, "V": 0.011100, "W": 0.020900, "X": 0.001700, "Y": 0.021100, "Z": 0.000700}

# For a given text we try and apply frequency analysis
# For every letter we compute the frequency deviation from the usual English language letter frequency
# We compute the delta value of the text which is the sum of the frequency deviations and return it 
def frequency_analysis(txt):
    freq = {}
    cnt_letters = 0
    for ch in txt:
        ch = str(ch).upper()
        if ch in LETTER_FREQUENCY:
            cnt_letters += 1
            if ch in freq:
                freq[ch] += 1
            else:
                freq[ch] = 1
    delta = 0
    for key in freq.keys():
        freq[key] = freq[key] / cnt_letters
        delta += abs(freq[key] * 100 - LETTER_FREQUENCY[key] * 100)
    return delta

# A function that takes a text encrypted with only one character and tries to guess the character used (the guesses are from a string of allowed characters)
# For every potential character used for encryption we decrypt the text
# We count how many bizzare characters are present in the resulting text and we compute a delta value using frequency analysis (the lower the better)
# We return the most likely character used for encryption based on the delta value and the count of bizzare characters
def crack_sinlge_byte_XOR_cipher(txt, allowed_chars):
    min_delta = 2600
    min_bizzare_chars = len(txt)
    key = ""
    for potential_ch in allowed_chars:
        bizzare_chars = 0
        deciphered_txt = ""
        for letter in txt:
            ch = chr(ord(potential_ch) ^ ord(letter))
            deciphered_txt += ch
            if str(ch).isprintable() == False:
                bizzare_chars += 1
        delta = frequency_analysis(deciphered_txt)
        if delta < min_delta:
            min_delta = delta
            key = potential_ch
            min_bizzare_chars = bizzare_chars
        elif delta == min_delta and bizzare_chars <  min_bizzare_chars:
            min_delta = delta
            key = potential_ch
            min_bizzare_chars = bizzare_chars
    return key

# A function that breaks the text in blocks of length key_length
# If we place the blocks one under the other we cand take the columns and try to crack the character used to encrypt them
# For every column we only take the most likely character used for encryption and we append it to the key then return the key
def crack_key(encrypted_txt, key_len, allowed_chars):
    txt_len = len(encrypted_txt)
    columns = ["" for i in range(key_len)]
    for cnt in range(0, txt_len, key_len):
        block = encrypted_txt[cnt:cnt + key_len]
        for idx in range(key_len):
            if idx < len(block):
                columns[idx] += block[idx]
    key = ""
    for column in columns:
        key += crack_sinlge_byte_XOR_cipher(column, allowed_chars)
    return key

# A function used to score a potential key length
# It breaks the text into blocks of length candidate_len then computes the Hamming Distance (of bytes) of consecutive blocks
# It returns the normalised score
def key_score(encrypted_txt, candidate_len):
    score = 0
    txt_len = len(encrypted_txt)
    for cnt in range(candidate_len, txt_len, candidate_len):
        block1 = encrypted_txt[cnt - candidate_len:cnt]
        block2 = encrypted_txt[cnt:cnt + candidate_len]
        if len(block2) < candidate_len:
            break
        for idx in range(candidate_len):
            score += bin(ord(block1[idx]) ^ ord(block2[idx])).count("1")
    return (score / (txt_len // candidate_len)) / candidate_len

# A function that computes for every potential key length a score of how likely it is to be the actual key length (the lower the score the better)
# It returns the list of [score, key_len] in the order highly likely to unlikely
def key_length(encrypted_txt, max_len_searched):
    max_len_searched = min(max_len_searched, len(encrypted_txt))
    potential_keys = []
    print("Finding key length...")
    for candidate_len in range(1, max_len_searched):
        done_percentage = int(candidate_len / max_len_searched * PROGRESS_BAR_LEN)
        print("\r" + "[" + done_percentage * "=" + (PROGRESS_BAR_LEN - done_percentage) * " " + "]", end='')
        score = key_score(encrypted_txt, candidate_len)
        potential_keys.append([score, candidate_len])
    print("\n\nCracking keys for the corresponding key lengths...")
    potential_keys.sort()
    return potential_keys

# Takes the encrypted file from the CLI
encrypted_file = sys.argv[1]
max_len_searched = int(sys.argv[2])
allowed_chars = sys.argv[3]

# Reads the encrypted input
encrypted_file = open(encrypted_file)
encrypted_txt = encrypted_file.read()

# Decodes the encrypted input from base64
encrypted_txt = base64.b64decode(encrypted_txt)
encrypted_txt = encrypted_txt.decode("utf-8")

# Reads the allowed characters that can appear in the password (the more the slower)
allowed_chars = open(allowed_chars)
allowed_chars = allowed_chars.read()

# Finds the potential key lengths ordered highly likely to unlikely
potential_key_len = key_length(encrypted_txt, max_len_searched)

# For every potential key length it tries to crack the key then prints it
for [score, key_len] in potential_key_len:
    print("If the key length is " + str(key_len) + " than the most probable key is: ", end="")
    print(crack_key(encrypted_txt, key_len, allowed_chars), end="\n\n")
