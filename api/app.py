import logging
from flask import Flask, jsonify, request
from encryption.aes_encryption import encrypt, decrypt

# Create flask app
app = Flask(__name__)

# Configure logging 

logging.basicConfig(
    filename='api.log',         # single log file for the project
    level=logging.INFO,         # capture INFO, WARNING, ERROR, etc
    format='%(asctime)s - $(levelname)s - $(message)s'
)


@app.route("/api/encrypt", methods=["POST"])
def encrypt():

    data = request.json # get JSON payload from client

    if not data or "message" not in data:
        logging.warning("[API] Encrypt request missing 'message'")
        return jsonify({"error": "No message provided"}), 400

    plaintext = data.get("message")
    ciphertext = encrypt(plaintext)
    logging.info(f"[API][ENCRYPTION] Encrypted message successfully")
    return jsonify({"encrypted": ciphertext})


@app.route("/api/decrypt", methods=["POST"])
def decrypt():

    data = request.json

    if not data or "ciphertext" not in data or "nonce" not in data:
        logging.warning("[API] Decrypt request missing 'ciphertext")
        return jsonify({"error": "Missing ciphertext or nonce"}), 400
    
    ciphertext = data.get("ciphertext")
    nonce = data.get("nonce")

    plaintext = decrypt(ciphertext, nonce)
    logging.info(f"[API][DECRYPTION] Decrypted message successfully")
    return jsonify({"decrypted": plaintext})


if __name__ == '__main__':
    app.run(debug=True)