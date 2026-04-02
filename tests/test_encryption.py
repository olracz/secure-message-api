import pytest
from cryptography.exceptions import InvalidTag
from crypto.aesgcm import encrypt, decrypt
# Import your own custom utilities
from crypto.utils import b64_decode, b64_encode 

class TestAESGCM:
    
    def test_basic_encrypt_decrypt(self):
        message = "Hello World"
        result = encrypt(message)
        decrypted = decrypt(result["ciphertext"], result["nonce"])
        assert decrypted == message

    def test_tampered_ciphertext(self):
        """Uses custom b64_decode to handle the unpadded string."""
        result = encrypt("Top Secret")
        
        # Decode using YOUR utility
        ciphertext_bytes = bytearray(b64_decode(result["ciphertext"]))
        
        # Tamper with the first byte
        ciphertext_bytes[0] ^= 0xFF 
        
        # Re-encode using YOUR utility
        bad_data = b64_encode(bytes(ciphertext_bytes))

        with pytest.raises(InvalidTag):
            decrypt(bad_data, result["nonce"])

    def test_empty_string(self):
        message = ""
        result = encrypt(message)
        assert decrypt(result["ciphertext"], result["nonce"]) == ""