from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from crypto.utils import generate_nonce, b64_encode

def encrypt(session_key: bytes, plaintext: str):

    # Generate nonce from utils
    nonce = generate_nonce()

    # Convert plaintext to bytes
    plaintext = plaintext.encode('utf-8')

    # Initialize AESGCM with the session key
    aesgcm = AESGCM(session_key)
                    
    # Encrypt the plaintext using AES-GCM
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    # Encode the ciphertext and nonce to base64 for JSON compatibility
    return {"ciphertext": b64_encode(ciphertext),
            "nonce": b64_encode(nonce)
            }










