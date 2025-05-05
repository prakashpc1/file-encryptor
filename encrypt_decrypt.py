from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
import getpass

def encrypt_file(input_file_path, output_file_path, password):
    # Read the input file data
    with open(input_file_path, 'rb') as f:
        data = f.read()
    
    # Generate a random salt and initialization vector (IV)
    salt = os.urandom(16)
    iv = os.urandom(16)
    
    # Derive the encryption key using PBKDF2-HMAC-SHA256
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 key length
        salt=salt,
        iterations=100000  # Adjust based on security requirements
    )
    key = kdf.derive(password.encode())
    
    # Pad the data to fit AES block size
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    # Encrypt the data using AES-CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # Write salt, IV, and ciphertext to the output file
    with open(output_file_path, 'wb') as f:
        f.write(salt)
        f.write(iv)
        f.write(ciphertext)

def decrypt_file(input_file_path, output_file_path, password):
    try:
        # Read the encrypted file data
        with open(input_file_path, 'rb') as f:
            salt = f.read(16)
            iv = f.read(16)
            ciphertext = f.read()
        
        # Derive the decryption key using PBKDF2-HMAC-SHA256
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        key = kdf.derive(password.encode())
        
        # Decrypt the data using AES-CBC
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Unpad the decrypted data
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        
        # Write the decrypted data to the output file
        with open(output_file_path, 'wb') as f:
            f.write(data)
        return True
    except ValueError:
        print("Decryption failed. Incorrect password or corrupted data.")
        return False
    except Exception as e:
        print(f"An error occurred: {e}")
        return False

def main():
    action = input("Choose action - Encrypt (e) or Decrypt (d): ").lower()
    input_path = input("Input file path: ")
    output_path = input("Output file path: ")
    password = getpass.getpass("Enter password: ")
    
    if action == 'e':
        encrypt_file(input_path, output_path, password)
        print("Encryption completed successfully.")
    elif action == 'd':
        success = decrypt_file(input_path, output_path, password)
        if success:
            print("Decryption completed successfully.")
    else:
        print("Invalid action selected. Use 'e' or 'd'.")

if __name__ == "__main__":
    main()
