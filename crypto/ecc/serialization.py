from cryptography.hazmat.primitives import serialization 


def private_key_to_pem(private_key) -> bytes:
    # Convert private key object to PEM but in bytes presentation for storage 
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def public_key_to_pem(public_key) -> bytes:
    # Convert public key object to PEM but in bytes presentation for storage 
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def public_key_to_pem_str(public_key) -> str:
    # Convert public key to PEM format and return as a UTF-8 string
    return public_key_to_pem(public_key).decode("utf-8")

def pem_to_key(pem_data, private=True):
    if private:
        return serialization.load_pem_private_key(pem_data, password=None)
    else:
        return serialization.load_pem_public_key(pem_data)
