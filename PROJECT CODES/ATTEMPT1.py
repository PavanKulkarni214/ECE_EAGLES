import os
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Configuration
AES_KEY_SIZE = 32  # 256-bit key
SALT_SIZE = 16  # 128-bit salt
ITERATIONS = 1000  # number of iterations for PBKDF2
HASH_ALGORITHM = hashlib.sha256  # hash algorithm for password verification

class SecureFileProtector:
    def __init__(self):
        self.backend = default_backend()

    def generate_key(self, password, salt):
        kdf = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, ITERATIONS, AES_KEY_SIZE)
        return kdf  # Return the raw key bytes directly

    def encrypt_file(self, file_path, password):
        # Generate a random salt
        salt = os.urandom(SALT_SIZE)
        aes_key = os.urandom(AES_KEY_SIZE)

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        with open(file_path, 'rb') as file:
            file_data = file.read()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(file_data) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

       
        password_key = self.generate_key(password, salt)
        encrypted_aes_key = self.encrypt_aes_key(aes_key, password_key)

        with open(file_path + '.enc', 'wb') as encrypted_file:
            encrypted_file.write(salt + encrypted_aes_key + iv + encrypted_data)

    def decrypt_file(self, file_path, password):
       
        with open(file_path, 'rb') as encrypted_file:
            salt = encrypted_file.read(SALT_SIZE)
            encrypted_aes_key = encrypted_file.read(AES_KEY_SIZE)
            iv = encrypted_file.read(16)
            encrypted_data = encrypted_file.read()

        
        password_key = self.generate_key(password, salt)
        aes_key = self.decrypt_aes_key(encrypted_aes_key, password_key)

        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

       
        with open('decrypted_file.txt', 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)

    def encrypt_aes_key(self, aes_key, password_key):
        cipher = Cipher(algorithms.AES(password_key), modes.ECB(), backend=self.backend)
        encryptor = cipher.encryptor()
        encrypted_aes_key = encryptor.update(aes_key) + encryptor.finalize()
        return encrypted_aes_key

    def decrypt_aes_key(self, encrypted_aes_key, password_key):
        cipher = Cipher(algorithms.AES(password_key), modes.ECB(), backend=self.backend)
        decryptor = cipher.decryptor()
        aes_key = decryptor.update(encrypted_aes_key) + decryptor.finalize()
        return aes_key

def encrypt_file():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return

    password = password_entry.get()
    if not password:
        messagebox.showwarning("Warning", "Please enter a password")
        return

    protector = SecureFileProtector()
    protector.encrypt_file(file_path, password)
    messagebox.showinfo("Info", "File encrypted successfully")

def decrypt_file():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return

    if not password:
        messagebox.showwarning("Warning", "Please enter a password")
        return

    protector = SecureFileProtector()
    protector.decrypt_file(file_path, password)
    messagebox.showinfo("Info", "File decrypted successfully")

root = tk.Tk()
root.title("Secure File Protector")

tk.Label(root, text="Password:").grid(row=0, column=0, padx=10, pady=10)
password_entry = tk.Entry(root, show="*")
password_entry.grid(row=0, column=1, padx=10, pady=10)

tk.Button(root, text="Encrypt File", command=encrypt_file).grid(row=1, column=0, padx=10, pady=10)
tk.Button(root, text="Decrypt File", command=decrypt_file).grid(row=1, column=1, padx=10, pady=10)

root.mainloop()
