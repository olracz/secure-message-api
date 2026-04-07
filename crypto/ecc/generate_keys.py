from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# Generate a private key for use in the exchange.
private_key = ec.generate_private_key(ec.SECP256R1())

# Serialize the private key to PEM format and save it to a file.
with open("keys/private_key.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Derive the public key from the private key and save it to a file.
public_key = private_key.public_key()
with open("keys/public_key.pem", "wb") as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))    

print("ECC P-256 keys generated successfully in /keys folder.")