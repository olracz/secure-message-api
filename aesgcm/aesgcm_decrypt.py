from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os 
import base64
from dotenv import load_dotenv

load_dotenv()

def decrypt(ciphertext, nonce):

    ciphertext_pad = "=" * ((4 - len(ciphertext) % 4) % 4)
    nonce_pad = "=" * ((4 - len(nonce) % 4) % 4)

    ciphertext = base64.urlsafe_b64decode(ciphertext + ciphertext_pad)
    nonce = base64.urlsafe_b64decode(nonce + nonce_pad)

    aes_key = os.getenv("AES_GCM_KEY")
    decoded_aes_key = base64.urlsafe_b64decode(aes_key)

    aesgcm = AESGCM(decoded_aes_key)

    plaintext_bytes = aesgcm.decrypt(nonce,ciphertext, None)

    return plaintext_bytes.decode('utf-8')