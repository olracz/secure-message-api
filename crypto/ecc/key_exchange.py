from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def derive_shared_aes_key(my_private_key, peer_public_key):
    # Perform ECDH
    shared_secret = my_private_key.exchange(ec.ECDH(), peer_public_key)

    # Derivation (HKDF) to get a clean 256-bit AES key
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'secure-message-api-v1',
    ).derive(shared_secret)