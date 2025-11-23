from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os 
import base64
from dotenv import load_dotenv

load_dotenv()

def generate_aes_key():
    aes_key = AESGCM.generate_key(bit_length=256) #aeskey generation using AESGCM library
    encoded_key = base64.urlsafe_b64encode(aes_key).decode('utf-8') #encode key in base64 to store in .env
    
def generate_nonce():
    return os.urandom(12)

def encrypt(plaintext):
    aes_key = os.getenv("AES_GCM_KEY")
    decoded_aes_key = base64.urlsafe_b64decode(aes_key)




#if __name__ == '__main__':
 #   encrypt()










