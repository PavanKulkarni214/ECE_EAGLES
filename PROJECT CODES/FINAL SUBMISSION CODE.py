# -*- coding: utf-8 -*-
"""
Created on Sun Jul 14 13:23:03 2024

@author: Pavan P Kulkarni
"""

import os
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from datetime import datetime

# Configuration
AES_KEY_SIZE = 32  # 256-bit key
SALT_SIZE = 16  # 128-bit salt
ITERATIONS = 1000  # number of iterations for PBKDF2
HASH_ALGORITHM = hashlib.sha256  # hash algorithm for password verification

class SecureFileProtector:
    def __init__(self, console):
        self.backend = default_backend()
        self.console = console

    def log(self, message):
        timestamp = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
        self.console.insert(tk.END, f"{timestamp} - {message}\n")
        self.console.see(tk.END)

    def generate_key(self, password, salt):
        # Derive a key from the password using PBKDF2
        kdf = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, ITERATIONS, AES_KEY_SIZE)
        return kdf  # Return the raw key bytes directly

    def encrypt_file(self, file_path, password):
        try:
            # Generation of random salt
            salt = os.urandom(SALT_SIZE)
            aes_key = os.urandom(AES_KEY_SIZE)

            # Encrypting the data in a file using AES-256-CBC
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

            self.log("File encrypted successfully")
            messagebox.showinfo("Info", "File encrypted successfully")
        except Exception as e:
            self.log(f"Error: {str(e)}")
            messagebox.showerror("Error", str(e))

    def decrypt_file(self, file_path, password):
        try:
            # Read
            with open(file_path, 'rb') as encrypted_file:
                salt = encrypted_file.read(SALT_SIZE)
                encrypted_aes_key = encrypted_file.read(AES_KEY_SIZE)
                iv = encrypted_file.read(16)
                encrypted_data = encrypted_file.read()

            # Decrypt the AES key using the password-derived key
            password_key = self.generate_key(password, salt)
            aes_key = self.decrypt_aes_key(encrypted_aes_key, password_key)

            # Decrypt the file data
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=self.backend)
            decryptor = cipher.decryptor()
            decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

            # Write the decrypted file data to a new file named 'decrypted'
            decrypted_file_path = os.path.join(os.path.dirname(file_path), 'decrypted_' + os.path.basename(file_path).replace('.enc', ''))
            with open(decrypted_file_path, 'wb') as decrypted_file:
                decrypted_file.write(decrypted_data)
            
            self.log("File decrypted successfully")
            messagebox.showinfo("Info", "File decrypted successfully")
        except Exception as e:
            self.log(f"Error: {str(e)}")
            messagebox.showerror("Error", "Wrong password key")

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

def select_file_path():
    file_path = filedialog.askopenfilename()
    if file_path:
        file_path_entry.config(state=tk.NORMAL)
        file_path_entry.delete(0, tk.END)
        file_path_entry.insert(0, file_path)
        file_path_entry.config(state=tk.DISABLED)

def encrypt_file():
    file_path = file_path_entry.get()
    if not file_path:
        messagebox.showwarning("Warning", "Please select a file")
        return

    password = password_entry.get()
    if not password:
        messagebox.showwarning("Warning", "Please enter a password")
        return

    protector = SecureFileProtector(console)
    protector.encrypt_file(file_path, password)

def decrypt_file():
    file_path = file_path_entry.get()
    if not file_path:
        messagebox.showwarning("Warning", "Please select a file")
        return

    password = password_entry.get()
    if not password:
        messagebox.showwarning("Warning", "Please enter a password")
        return

    protector = SecureFileProtector(console)
    protector.decrypt_file(file_path, password)

# calling the GUI functions
root = tk.Tk()
root.title("Secure File Protector")

# Set the size of the window to cover at least half of the screen
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
root.geometry(f"{screen_width//2}x{screen_height//2}")

# main frame
main_frame = tk.Frame(root)
main_frame.pack(pady=10)

# title label
title_label = tk.Label(main_frame, text="STEALTH COMMANDER", font=("Helvetica", 20, "bold"))
title_label.pack(pady=10)

# the file path selection
file_path_frame = tk.Frame(main_frame)
file_path_frame.pack(pady=10, fill="x")

tk.Label(file_path_frame, text="File Path:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
file_path_entry = tk.Entry(file_path_frame, width=50, state=tk.DISABLED)
file_path_entry.grid(row=0, column=1, padx=5, pady=5)
file_path_button = tk.Button(file_path_frame, text="Browse", command=select_file_path)
file_path_button.grid(row=0, column=2, padx=5, pady=5)

# Creatimg and placing the password label and entry
password_frame = tk.Frame(main_frame)
password_frame.pack(pady=10, fill="x")

tk.Label(password_frame, text="Password:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
password_entry = tk.Entry(password_frame, show="*", width=30)
password_entry.grid(row=0, column=1, padx=5, pady=5)

# Creating and placeing of buttons
button_frame = tk.Frame(main_frame)
button_frame.pack(pady=10, fill="x")

encrypt_button = tk.Button(button_frame, text="Encrypt File", command=encrypt_file, width=20, height=2, bg="#4CAF50", fg="white", font=("Helvetica", 12, "bold"))
encrypt_button.grid(row=0, column=0, padx=5, pady=5, sticky="w")

decrypt_button = tk.Button(button_frame, text="Decrypt File", command=decrypt_file, width=20, height=2, bg="#F44336", fg="white", font=("Helvetica", 12, "bold"))
decrypt_button.grid(row=0, column=1, padx=5, pady=5, sticky="w")

# console frame
console_frame = tk.Frame(root)
console_frame.pack(pady=10, fill="both", expand=True)

console_label = tk.Label(console_frame, text="Console", font=("Helvetica", 12, "bold"))
console_label.pack(anchor="w", padx=5)

console = tk.Text(console_frame, height=10, wrap="word")
console.pack(expand=True, fill="both", padx=10, pady=10)

# Start the GUI loop
root.mainloop()