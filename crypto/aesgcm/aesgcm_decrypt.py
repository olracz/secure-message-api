from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from crypto.utils import b64_decode
import os 
import base64
from dotenv import load_dotenv

load_dotenv()

def decrypt(ciphertext, nonce):

    # Decode inputs using utils
    ciphertext_bytes = b64_decode(ciphertext)
    nonce_bytes = b64_decode(nonce)

    # Decode AES key from env
    aes_key = os.getenv("AES_GCM_KEY")
    decoded_aes_key = base64.urlsafe_b64decode(aes_key)

    # Decrypt
    aesgcm = AESGCM(decoded_aes_key)
    plaintext_bytes = aesgcm.decrypt(nonce_bytes,ciphertext_bytes, None)

    return plaintext_bytes.decode('utf-8')