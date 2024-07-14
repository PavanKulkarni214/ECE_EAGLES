# -*- coding: utf-8 -*-
"""
Created on Fri Jul 12 14:59:29 2024

@author: Pavan P Kulkarni
"""

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
        # Derive a key from the password using PBKDF2
        kdf = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, ITERATIONS, AES_KEY_SIZE)
        return kdf  # Return the raw key bytes directly

    def encrypt_file(self, file_path, password):
        # Generate a random salt
        salt = os.urandom(SALT_SIZE)
        aes_key = os.urandom(AES_KEY_SIZE)

        # Encrypt the file using AES-256-CBC
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        with open(file_path, 'rb') as file:
            file_data = file.read()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(file_data) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Encrypt the AES key using the password-derived key
        password_key = self.generate_key(password, salt)
        encrypted_aes_key = self.encrypt_aes_key(aes_key, password_key)

        # Store the salt, encrypted AES key, IV, and the encrypted file data
        with open(file_path + '.enc', 'wb') as encrypted_file:
            encrypted_file.write(salt + encrypted_aes_key + iv + encrypted_data)

    def decrypt_file(self, file_path, password):
        try:
            # Read the salt, encrypted AES key, IV, and the encrypted file data
            with open(file_path, 'rb') as encrypted_file:
                salt = encrypted_file.read(SALT_SIZE)
                encrypted_aes_key = encrypted_file.read(AES_KEY_SIZE)
                iv = encrypted_file.read(16)
                encrypted_data = encrypted_file.read()

            # Decrypt the AES key using the password-derived key
            password_key = self.generate_key(password, salt)
            aes_key = self.decrypt_aes_key(encrypted_aes_key, password_key)

            # Decrypt the file data using AES-256-CBC
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=self.backend)
            decryptor = cipher.decryptor()
            decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

            # Write the decrypted file data to a new file named 'decrypted_<original_filename>'
            decrypted_file_path = os.path.join(os.path.dirname(file_path), 'decrypted_' + os.path.basename(file_path).replace('.enc', ''))
            with open(decrypted_file_path, 'wb') as decrypted_file:
                decrypted_file.write(decrypted_data)
            messagebox.showinfo("Info", "File decrypted successfully")
        except Exception as e:
            messagebox.showerror("Error", "Unauthorized key")

    def encrypt_aes_key(self, aes_key, password_key):
        # Encrypt the AES key using the password-derived key
        cipher = Cipher(algorithms.AES(password_key), modes.ECB(), backend=self.backend)
        encryptor = cipher.encryptor()
        encrypted_aes_key = encryptor.update(aes_key) + encryptor.finalize()
        return encrypted_aes_key

    def decrypt_aes_key(self, encrypted_aes_key, password_key):
        # Decrypt the AES key using the password-derived key
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

    password = password_entry.get()
    if not password:
        messagebox.showwarning("Warning", "Please enter a password")
        return

    protector = SecureFileProtector()
    protector.decrypt_file(file_path, password)

# Create the main window
root = tk.Tk()
root.title("Secure File Protector")

# Set the size of the window to cover at least half of the screen
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
root.geometry(f"{screen_width//2}x{screen_height//2}")

# Create and place the password label and entry
title_label = tk.Label(root, text="Secure File Protector", font=("Helvetica", 20, "bold"))
title_label.pack(pady=20)

password_frame = tk.Frame(root)
password_frame.pack(pady=10)

tk.Label(password_frame, text="Password:").pack(side=tk.LEFT, padx=5)
password_entry = tk.Entry(password_frame, show="*", width=30)
password_entry.pack(side=tk.LEFT, padx=5)

# Create and place the buttons
button_frame = tk.Frame(root)
button_frame.pack(pady=20)

encrypt_button = tk.Button(button_frame, text="Encrypt File", command=encrypt_file, width=20, height=2, bg="#4CAF50", fg="white", font=("Helvetica", 12, "bold"))
encrypt_button.pack(side=tk.TOP, pady=10)

decrypt_button = tk.Button(button_frame, text="Decrypt File", command=decrypt_file, width=20, height=2, bg="#F44336", fg="white", font=("Helvetica", 12, "bold"))
decrypt_button.pack(side=tk.TOP, pady=10)

# Start the GUI event loop
root.mainloop()
