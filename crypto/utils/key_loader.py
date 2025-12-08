import os 
from cryptography.hazmat.primitives import serialization

BASE_DIR = os.path.dirname(os.path.dirname(__file__))   # project root
KEYS_DIR = os.path.join(BASE_DIR, "keys")               # folder storing PEM files

PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "private_key.pem")
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "public_key.pem")

def load_private_key():
    # Load RSA private key from PEM file

    with open(PRIVATE_KEY_PATH, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=()
        )
    return private_key

def load_public_key():
    # Load RSA public key from PEM file

    with open(PUBLIC_KEY_PATH, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
        )
    return public_key