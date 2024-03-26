from flask import Flask, render_template, request, redirect, url_for
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

shared_secret_key = os.urandom(32)

def encrypt_message(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_message = message + (16 - len(message) % 16) * chr(16 - len(message) % 16)
    ciphertext = encryptor.update(padded_message.encode()) + encryptor.finalize()
    return iv + ciphertext

def decrypt_message(ciphertext, key):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    padding_length = plaintext[-1]
    plaintext = plaintext[:-padding_length]
    return plaintext.decode()

message_data = {}

@app.route('/')
def index():
    return render_template('index.html', message_data=message_data)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    user = request.form['user']
    message = request.form['message']

    if user not in message_data:
        message_data[user] = []

    encrypted_message = encrypt_message(message, shared_secret_key)
    message_data[user].append({"message": encrypted_message.hex(), "time": "now"})

    return redirect(url_for('index'))

@app.route('/decrypt', methods=['POST'])
def decrypt():
    user_decrypt = request.form['user_decrypt']
    message_decrypt_hex = request.form['message_decrypt']

    if user_decrypt in message_data:
        for message in message_data[user_decrypt]:
            if message['message'] == message_decrypt_hex:
                decrypted_message = decrypt_message(bytes.fromhex(message_decrypt_hex), shared_secret_key)
                return render_template('index.html', message_data=message_data, decrypted_message=decrypted_message)

    return render_template('index.html', message_data=message_data, decrypted_message=None)

if __name__ == '__main__':
    app.run(debug=True)


