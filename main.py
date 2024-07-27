import re
import os
from Cryptodome.Cipher import AES
import base64, marshal, zlib
from Cryptodome.Util.Padding import pad, unpad
import dis, io

variable_pattern = r'(?P<var_name>\b\w{12}\b)\s*=\s*base64\.b64decode\(b["\'](?P<encoded_key>[^"\']+)["\']\)'

encrypted_code_pattern = r'encrypted_code\s*=\s*base64\.b64decode\(b?["\'](?P<encoded_code>[^"\']+)["\']\)'

def decrypt_code(encoded_code, key):
    decoded_encoded_code = base64.b64decode(encoded_code).decode()
    decoded = base64.b64decode(decoded_encoded_code)
    nonce, tag, ct = decoded[:16], decoded[16:32], decoded[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted_padded = cipher.decrypt_and_verify(ct, tag)
    decrypted_code = unpad(decrypted_padded, AES.block_size)
    decompressed_code = zlib.decompress(decrypted_code)
    return marshal.loads(decompressed_code)

def find_patterns_in_file(file_path):
    with open(file_path, 'r') as file:
        content = file.read()

        var_match = re.search(variable_pattern, content)
        if var_match:
            var_name = var_match.group('var_name')
            encoded_key = var_match.group('encoded_key')
            print(f"Found variable '{var_name}' with encoded key: {encoded_key}")
            decoded_key = base64.b64decode(encoded_key)
        else:
            print("Key not found.")
            return

        encrypted_match = re.search(encrypted_code_pattern, content)
        if encrypted_match:
            encoded_code = encrypted_match.group('encoded_code')
            print(f"Found encrypted code: {encoded_code}")
            decoded_code = base64.b64decode(encoded_code)
        else:
            print("Encrypted code not found.")
            return

        if decoded_key and decoded_code:
            decrypted_code_object = decrypt_code(decoded_code, decoded_key)
            
            # Capture disassembled output
            output = io.StringIO()
            dis.dis(decrypted_code_object, file=output)
            output_str = output.getvalue()
            output.close()

            with open("Deobfuscated.txt", "w") as f:
                f.write(output_str)

            print('Deobfuscated (BYTECODE): open Deobfuscated.txt to get the hidden code! (it is not hard to read)')

file_path = input("File name/Path -> ")
find_patterns_in_file(file_path)
