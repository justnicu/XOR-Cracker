# XOR-Cracker
A python script that takes a XOR cipher encrypted input and tries to crack the key used for encryption.

### How to use:
##### Encrypt script
```
python3 encrypt.py original_text_file encrypted_text_file key
```
It encrypts the text from original_text_file and saves it in encrypted_text_file using base64 encoding.

##### Decrypt script
```
python3 decrypt.py encrypted_text_file decrypted_text_file key
```
Using the key it decrypts the base64 encoded text from encrypted_text_file and saves it in decrypted_text_file.

##### Key cracker script
```
python3 key_cracker.py encrypted_text_file max_key_len allowed_char_file
```
It tries to crack the key used to encrypt the base64 encoded text from encrypted_text_file. It tries key lengths up to max_key_len and tries only characters from allowed_char_file. For every possible key length (ordered from the most likely to least likely) it prints the most likely key.
