from flask import Flask, render_template, request
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# Function to encrypt a message
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

# Function to decrypt a message
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

# Function to load server's private key
def load_server_private_key():
    with open("server_private.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

private_key = load_server_private_key()

@app.route('/')
def index():
    return render_template('index_1.html')

@app.route('/message', methods=['POST'])
def handle_message():
    client_public_key_pem = request.data
    client_public_key = serialization.load_pem_public_key(
        client_public_key_pem,
        backend=default_backend()
    )

    encrypted_client_message = request.form['client_message']
    decrypted_client_message = decrypt_message(encrypted_client_message, private_key)

    # Process decrypted_client_message and prepare server_message here

    server_message = "Response from server"
    encrypted_server_message = encrypt_message(server_message, client_public_key)

    return encrypted_server_message

if __name__ == "__main__":
    app.run(debug=True)
