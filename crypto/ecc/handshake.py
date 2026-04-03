import secrets
from .signatures import verify_data, sign_data

def generate_challenge():
    
    # Generate a random challenge string (32 bytes hex)
    return secrets.token_hex(32)

def verify_user_response(public_key, signature, challenge):

    # Verify the user's response by checking the signature against the challenge
    return verify_data(public_key, signature, challenge.encode())