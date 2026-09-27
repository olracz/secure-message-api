from .signatures import sign_data, verify_data

def sign_challenge(private_key, challenge: str) -> bytes:
    """Sign a server challenge to prove identity ownership."""
    return sign_data(private_key, challenge.encode("utf-8"))

def verify_challenge_signature(public_key, signature: bytes, challenge: str) -> bool:
    """Verify a signed challenge against an identity public key."""
    return verify_data(public_key, signature, challenge.encode("utf-8"))