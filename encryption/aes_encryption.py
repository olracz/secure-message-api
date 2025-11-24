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

    encoded_ciphertext = base64.urlsafe_b64encode(ciphertext).decode('utf-8')
    encoded_nonce = base64.urlsafe_b64encode(nonce).decode('utf-8')

    return {"ciphertext": ciphertext, "nonce": nonce}

def decrypt(ciphertext, nonce):

    ciphertext = base64.urlsafe_b64decode(ciphertext)
    nonce = base64.urlsafe_b64decode(nonce)

    aes_key = os.getenv("AES_GCM_KEY")
    decoded_aes_key = base64.urlsafe_b64decode(aes_key)

    aesgcm = AESGCM(decoded_aes_key)

    plaintext_bytes = aesgcm.decrypt(nonce,ciphertext, None)

    return plaintext_bytes.decode('utf-8')


"""
if __name__ == '__main__':
    plaintext = "hello"
    encrypted_text, nonce = encrypt(plaintext)
    print(encrypted_text, nonce)
    
    decrypt = decrypt(encrypted_text, nonce)
    print(decrypt)
"""








