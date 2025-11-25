from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os 
import base64
from dotenv import load_dotenv

load_dotenv()

def _generate_aes_key():
    ###Internal use only: generate a new AES key###
    aes_key = AESGCM.generate_key(bit_length=256) 
    encoded_key = base64.urlsafe_b64encode(aes_key).decode('utf-8') 
    
def generate_nonce():
    return os.urandom(12)

def encrypt(plaintext):

    aes_key = os.getenv("AES_GCM_KEY")
    decoded_aes_key = base64.urlsafe_b64decode(aes_key)

    nonce = generate_nonce()
    plaintext = plaintext.encode('utf-8')

    aesgcm = AESGCM(decoded_aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    encoded_ciphertext = base64.urlsafe_b64encode(ciphertext).decode('utf-8').rstrip("=")
    encoded_nonce = base64.urlsafe_b64encode(nonce).decode('utf-8').rstrip("=")

    return {"ciphertext": encoded_ciphertext, "nonce": encoded_nonce}

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


if __name__ == '__main__':
    plaintext = "Some random texts."
    result = encrypt(plaintext)
    ciphertext = result["ciphertext"]
    nonce = result["nonce"]

    print(f"ciphertext: {ciphertext},  nonce: , {nonce}")
    
    decrypt = decrypt(ciphertext, nonce)
    print(decrypt)









