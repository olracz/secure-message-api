from encryption import encrypt, decrypt
import base64

class TestEncryption():
    
    def test_encrypt_decrypt(self):
        message = "Hello World Carlo"
        result = encrypt(message)
        ciphertext = result["ciphertext"]
        nonce = result["nonce"]

        
        decrypted = decrypt(ciphertext, nonce)
        self.assertEqual(decrypted, message)

    