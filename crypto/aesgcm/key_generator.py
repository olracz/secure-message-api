import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_aes_key():
    # Generate a 256-bit AES key and return bytes
    return AESGCM.generate_key(bit_length=256)

def encode_key_base64(key: bytes) -> str:
    # Convert key bytes -> base64 string 
    return base64.b64encode(key).decode()


def decode_key_base64(encoded: str) -> bytes:
    # Convert base64 string -> key bytes
    return base64.b64decode(encoded)