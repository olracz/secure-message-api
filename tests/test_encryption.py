from aesgcm import encrypt, decrypt
import base64

class TestEncryption():
    
    def test_encrypt_decrypt(self):
        message = "Hello World"
        result = encrypt(message)
        ciphertext = result["ciphertext"]
        print(ciphertext)
        nonce = result["nonce"]
        print(nonce)

        
        decrypted = decrypt(ciphertext, nonce)
        print(decrypted)
        assert decrypted == message, "Data does not match."

if __name__ == "__main__":
    t = TestEncryption()
    t.test_encrypt_decrypt()