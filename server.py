import socket
import threading
import hmac
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import base64

# Generate DH parameters and keys
parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
server_private_key = parameters.generate_private_key()
server_public_key = server_private_key.public_key()

# Predefined user credentials (username: password)
users = {"user1": "password1", "user2": "password2"}

def client_handler(client_socket, client_address):
    try:
        # Diffie-Hellman key exchange
        client_public_key_bytes = client_socket.recv(1024)
        client_public_key = dh.DHPublicKey.from_public_bytes(client_public_key_bytes)
        shared_key = server_private_key.exchange(client_public_key)

        # Derive a key for encryption
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=os.urandom(16), iterations=100000, backend=default_backend())
        key = kdf.derive(shared_key)
        cipher = Fernet(base64.urlsafe_b64encode(key))

        # Authentication
        client_socket.send(b"Username: ")
        username = client_socket.recv(1024).decode()
        client_socket.send(b"Password: ")
        password = client_socket.recv(1024).decode()

        if users.get(username) != password:
            client_socket.send(b"Authentication Failed")
            client_socket.close()
            return

        client_socket.send(b"Authentication Successful")

        while True:
            # Receive encrypted message
            encrypted_message = client_socket.recv(1024)
            if not encrypted_message:
                break

            # Verify message integrity
            message, message_hmac = encrypted_message.split(b'||')
            hmac_calculated = hmac.new(key, message, hashlib.sha256).digest()

            if hmac_calculated != message_hmac:
                client_socket.send(b"Message tampered")
                continue

            # Decrypt message
            decrypted_message = cipher.decrypt(message).decode()
            print(f"Received from {client_address}: {decrypted_message}")

            # Echo back the message
            client_socket.send(encrypted_message)

    finally:
        client_socket.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 9999))
    server.listen(5)
    print("Server listening on port 9999")

    while True:
        client_socket, client_address = server.accept()
        print(f"Accepted connection from {client_address}")

        # Send server public key
        client_socket.send(server_public_key.public_bytes())

        client_handler_thread = threading.Thread(target=client_handler, args=(client_socket, client_address))
        client_handler_thread.start()

if __name__ == "__main__":
    main()
