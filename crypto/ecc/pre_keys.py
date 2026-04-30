from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from .key_generation import generate_key_pair
from .storage import save_key_to_file, load_key_from_file
from .serialization import private_key_to_pem, public_key_to_pem, pem_to_key


def generate_signed_pre_key(identity_private_key, pre_key_id):
    # Generate a new ECC key pair for the pre-key
    pre_private_key, pre_public_key = generate_key_pair()

    # Convert the pre-key public key to PEM format
    pre_public_pem = public_key_to_pem(pre_public_key)

    # Sign the pre-key public key with the identity private key
    signature = identity_private_key.sign(
        pre_public_pem,
        ec.ECDSA(hashes.SHA256())
    )

    return {
        "pre_key_id": pre_key_id,
        "pre_public_pem": pre_public_pem,
        "signature": signature
    }

def store_signed_pre_key(signed_pre_key, filename):
    pass

def load_signed_pre_key(filename):
    pass

def generate_one_time_pre_keys():
    pass

def store_one_time_pre_keys(one_time_pre_keys, filename):
    pass

def load_one_time_pre_keys(filename):
    pass

def delete_one_time_pre_key(filename, pre_key_id):
    pass
