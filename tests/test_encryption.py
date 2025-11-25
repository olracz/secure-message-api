from encryption import encrypt, decrypt
import base64

class TestEncryption():
    
    def test_encrypt_decrypt(self):
        message = "Hello World"
        result = encrypt(message)
        ciphertext = result["ciphertext"]
        nonce = result["nonce"]

        
        decrypted = decrypt(ciphertext, nonce)
        assert decrypted == message, "Data does not match."

    