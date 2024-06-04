import tkinter as tk
from tkinter import simpledialog, messagebox
import socket
import hmac
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import base64
import threading

# Generate DH parameters and keys
parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
client_private_key = parameters.generate_private_key()
client_public_key = client_private_key.public_key()

class ChatClient:
    def __init__(self, master):
        self.master = master
        self.master.title("Secure Chat Client")
        self.frame = tk.Frame(master)
        self.frame.pack()

        self.text_area = tk.Text(self.frame, height=20, width=50)
        self.text_area.pack(side=tk.LEFT, fill=tk.BOTH, padx=10, pady=10)
        self.text_area.config(state=tk.DISABLED)

        self.scrollbar = tk.Scrollbar(self.frame)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.text_area.config(yscrollcommand=self.scrollbar.set)
        self.scrollbar.config(command=self.text_area.yview)

        self.entry = tk.Entry(master, width=50)
        self.entry.pack(side=tk.LEFT, padx=10, pady=10)
        self.entry.bind("<Return>", self.send_message)

        self.send_button = tk.Button(master, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.RIGHT, padx=10, pady=10)

        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect_to_server()

    def connect_to_server(self):
        self.client_socket.connect(("127.0.0.1", 9999))

        # Receive server public key and send client public key
        server_public_key_bytes = self.client_socket.recv(1024)
        self.server_public_key = dh.DHPublicKey.from_public_bytes(server_public_key_bytes)
        self.client_socket.send(self.client_public_key.public_bytes())

        # Generate shared key
        shared_key = self.client_private_key.exchange(self.server_public_key)

        # Derive a key for encryption
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=os.urandom(16), iterations=100000, backend=default_backend())
        self.key = kdf.derive(shared_key)
        self.cipher = Fernet(base64.urlsafe_b64encode(self.key))

        self.authenticate()

    def authenticate(self):
        username = simpledialog.askstring("Username", "Enter your username:")
        self.client_socket.send(username.encode())
        password = simpledialog.askstring("Password", "Enter your password:", show='*')
        self.client_socket.send(password.encode())

        auth_response = self.client_socket.recv(1024).decode()
        if "Failed" in auth_response:
            messagebox.showerror("Authentication Failed", "Invalid username or password")
            self.master.destroy()
        else:
            threading.Thread(target=self.receive_messages).start()

    def send_message(self, event=None):
        message = self.entry.get()
        if message.lower() == 'exit':
            self.client_socket.close()
            self.master.destroy()
        else:
            encrypted_message = self.cipher.encrypt(message.encode())
            message_hmac = hmac.new(self.key, encrypted_message, hashlib.sha256).digest()
            encrypted_message_with_hmac = encrypted_message + b'||' + message_hmac
            self.client_socket.send(encrypted_message_with_hmac)
            self.entry.delete(0, tk.END)

    def receive_messages(self):
        while True:
            response = self.client_socket.recv(1024)
            if not response:
                break
            message, message_hmac = response.split(b'||')
            hmac_calculated = hmac.new(self.key, message, hashlib.sha256).digest()
            if hmac_calculated != message_hmac:
                self.display_message("Message tampered")
            else:
                decrypted_message = self.cipher.decrypt(message).decode()
                self.display_message(f"Server: {decrypted_message}")

    def display_message(self, message):
        self.text_area.config(state=tk.NORMAL)
        self.text_area.insert(tk.END, message + "\n")
        self.text_area.config(state=tk.DISABLED)
        self.text_area.yview(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClient(root)
    root.mainloop()
