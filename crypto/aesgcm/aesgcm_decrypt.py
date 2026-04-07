from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from crypto.utils import b64_decode

def decrypt(session_key: bytes, ciphertext: bytes, nonce: bytes):

    # Decode inputs using utils
    ciphertext_bytes = b64_decode(ciphertext)
    nonce_bytes = b64_decode(nonce)

    # Initialize AESGCM with the session key
    aesgcm = AESGCM(session_key)
   
   # Decrypt the ciphertext using AES-GCM
    plaintext_bytes = aesgcm.decrypt(nonce_bytes,ciphertext_bytes, None)

    return plaintext_bytes.decode('utf-8')