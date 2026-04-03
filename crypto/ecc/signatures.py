from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils

# ECC P-256 signing and verification
def sign_data(private_key, data_bytes):
    return private_key.sign(
        data_bytes,
        ec.ECDSA(hashes.SHA256())
    )

# Verify the signature of the data using the public key
def verify_data(public_key, signature, data_bytes):
    try:
        public_key.verify(signature, data_bytes, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False