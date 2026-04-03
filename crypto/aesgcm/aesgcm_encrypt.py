from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from crypto.utils import generate_nonce, b64_encode
import os 
import base64
from dotenv import load_dotenv

load_dotenv()

#def _generate_aes_key():
    ###Internal use only: generate a new AES key###
#    aes_key = AESGCM.generate_key(bit_length=256) 
#    encoded_key = base64.urlsafe_b64encode(aes_key).decode('utf-8') 
    

def encrypt(plaintext: str):

    # Load AES key from env (still base64 encoded)
    aes_key = os.getenv("AES_GCM_KEY")
    decoded_aes_key = base64.urlsafe_b64decode(aes_key)

    # Generate nonce from utils
    nonce = generate_nonce()

    # Convert plaintext to bytes
    plaintext = plaintext.encode('utf-8')

    # Encrypt
    aesgcm = AESGCM(decoded_aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    # Encode using utils
    encoded_ciphertext = b64_encode(ciphertext)
    encoded_nonce = b64_encode(nonce)

    return {"ciphertext": encoded_ciphertext, "nonce": encoded_nonce}


"""
if __name__ == '__main__':
    plaintext = "Some random texts."
    result = encrypt(plaintext)
    ciphertext = result["ciphertext"]
    nonce = result["nonce"]

    print(f"ciphertext: {ciphertext},  nonce: , {nonce}")
    
    decrypt = decrypt(ciphertext, nonce)
    print(decrypt)
"""








