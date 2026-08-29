import base64
import secrets

def generate_nonce() -> bytes:
    return secrets.token_bytes(12)  

def b64_encode(data : bytes) -> str:
    return base64.b64encode(data).decode('utf-8').rstrip("=")

def b64_decode(data: str) -> bytes:
    return base64.b64decode(data + "=" * (-len(data) % 4))