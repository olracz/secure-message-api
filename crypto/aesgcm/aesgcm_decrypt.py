from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from crypto.utils import b64_decode
from .validators import validate_key, validate_ciphertext_and_nonce
from .exceptions import DecryptionError

def decrypt(session_key: bytes, ciphertext: bytes, nonce: bytes):
    validate_key(session_key)
    validate_ciphertext_and_nonce(ciphertext, nonce)

    ciphertext_bytes = b64_decode(ciphertext)
    nonce_bytes = b64_decode(nonce)
    aesgcm = AESGCM(session_key)

    try:
         plaintext_bytes = aesgcm.decrypt(nonce_bytes,ciphertext_bytes, None)

    except InvalidTag:
        raise DecryptionError(
            "Decryption failed - ciphertext may be tampered or key is wrong"
        )
    
    return plaintext_bytes.decode('utf-8')