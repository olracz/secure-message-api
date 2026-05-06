from cryptography.hazmat.primitives import serialization 

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

def pem_to_key(pem_data, private=True):
    if private:
        return serialization.load_pem_private_key(pem_data, password=None)
    else:
        return serialization.load_pem_public_key(pem_data)