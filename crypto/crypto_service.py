import os

from .ecc.generate_keys import (
    generate_key_pair, 
    private_key_to_pem, 
    public_key_to_pem, 
    pem_to_key, 
    save_key_to_file
)

from .ecc.signatures import sign_data, verify_data
from .aesgcm.aesgcm_encrypt import encrypt
from .aesgcm.aesgcm_decrypt import decrypt


class CryptoService:
    def __init__(self, key_dir="./keys/"):
        self.key_dir = key_dir
        self.private_key = None 
        self.public_key = None
        self.session_key = None

        # Ensure directory exists
        if not os.path.exists(self.key_dir):
            os.makedirs(self.key_dir)

    def initial_client_identity(self, private_path="private.pem", public_path="public.pem"):
        # This function ensures the client has a unique identity, 
        # it checks for an existing private key pem and generate if its missing
        
        private_file = os.path.join(self.key_dir, private_path)
        public_file = os.path.join(self.key_dir, public_path)

        # Check if keys already exist and load them
        if os.path.exists(private_file) and os.path.exists(public_file):

            with open(private_file, "rb") as f:
                priv_pem = f.read()

            with open(public_file, "rb") as f:
                pub_pem = f.read()

            self.private_key, self.public_key = pem_to_key(
                private_pem=priv_pem, 
                public_pem=pub_pem
            )

        # If keys do not exist, generate new ones and save them
        else:
            # Generate new key pair
            self.private_key, self.public_key = generate_key_pair()

            # Save keys to files
            save_key_to_file(private_key_to_pem(self.private_key), private_file)
            save_key_to_file(public_key_to_pem(self.public_key), public_file)
    

    def sign_authentication_proof(self, challenge):
        # This function signs the challenge with the client's private key to prove ownership
        pass


