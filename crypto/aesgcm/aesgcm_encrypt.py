import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from crypto.utils import b64_encode, generate_nonce
from .validators import validate_key, validate_plaintext


def encrypt(session_key: bytes, plaintext: str):
    validate_key(session_key)
    validate_plaintext(plaintext)

    nonce = generate_nonce()
    plaintext = plaintext.encode('utf-8') 
    aesgcm = AESGCM(session_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    
    return {"ciphertext": b64_encode(ciphertext),
            "nonce": b64_encode(nonce)
    }