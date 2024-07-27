# Obfuscated Code Decryptor

This Python script helps decrypt obfuscated Python scripts that use base64 encoding and AES encryption. It identifies the encrypted content, decrypts it, and outputs the disassembled bytecode.

## How to Use

1. **Setup**: Ensure you have the required Python libraries installed:
   - `pycryptodome`
   - `zlib`

   You can install `pycryptodome` using pip:
   ```bash
   pip install pycryptodome``` 

Usage:
Place the obfuscated script in the same directory as main.py.
Run main.py using Python:

```bash
python main.py
```
When prompted, enter the name of the obfuscated file you want to decrypt (e.g., obfuscated_script.py).
Output:
- The script will analyze the provided file, decrypt the code, and disassemble the bytecode.
- The disassembled bytecode will be saved in a file named Deobfuscated.txt in the same directory.

What Does This Script Do?
Pattern Matching:

- It searches for specific patterns in the provided file to identify base64-encoded keys and encrypted code sections.
Decryption:

- The script decodes the base64-encoded key and uses it to decrypt the encrypted code using AES in GCM mode.
Disassembly:

- The decrypted code is disassembled using the dis module, and the disassembled bytecode is saved to Deobfuscated.txt for further analysis.

Notes : 
This script is for educational purposes only, use it at your own risk. I am  not responsible for any damage caused by the misuse of this script.
