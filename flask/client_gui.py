# app.py

from flask import Flask, render_template, request
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import socket

app = Flask(__name__)

# Load private key
def load_client_private_key():
    with open("client_private.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

private_key = load_client_private_key()

# Function to encrypt message
def encrypt_message(message, public_key):
    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message

# Function to decrypt message
def decrypt_message(encrypted_message, private_key):
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message.decode()

# Function to establish connection with server
def connect_to_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('localhost', 12345))
    return s

@app.route('/')
def index():
    return render_template('index_2.html')

@app.route('/send_message', methods=['POST'])
def send_message():
    client_message = request.form['client_message']
    s = connect_to_server()
    with s:
        # Send client's public key to server
        with open("client_public.pem", "rb") as key_file:
            client_public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        s.sendall(client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

        # Receive server's public key
        server_public_key_pem = s.recv(4096)
        server_public_key = serialization.load_pem_public_key(
            server_public_key_pem,
            backend=default_backend()
        )

        # Encrypt and send client message
        encrypted_client_message = encrypt_message(client_message, server_public_key)
        s.sendall(len(encrypted_client_message).to_bytes(4, 'big'))
        s.sendall(encrypted_client_message)

        # Receive and decrypt server message
        encrypted_server_message_length = int.from_bytes(s.recv(4), 'big')
        encrypted_server_message = s.recv(encrypted_server_message_length)
        decrypted_server_message = decrypt_message(encrypted_server_message, private_key)

    return decrypted_server_message

if __name__ == '__main__':
    app.run(debug=True)
