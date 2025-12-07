import os 
import secrets

def generate_nonce(length: int = 12) -> bytes:
    return secrets.token_bytes(length)