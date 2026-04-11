from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def generate_key_pair():
    # Generate an ECC P-256 key pair
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def private_key_to_pem(private_key):
    # Convert private key to PEM format for storage or transmission
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
def public_key_to_pem(public_key):
    # Convert public key to PEM format for storage or transmission
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def pem_to_key(private_pem=None, public_pem=None):
    # Convert PEM back to key objects
    private_key = None
    public_key = None

    if private_pem:
        private_key = serialization.load_pem_private_key(
            private_pem,
            password=None
        )

    if public_pem:
        public_key = serialization.load_pem_public_key(public_pem)

    return private_key, public_key   


def save_key_to_file(pem_data, filename):
    # Save the PEM data to a file
    with open(filename, "wb") as f:
        f.write(pem_data)