import base64

def b64_encode(data : bytes) -> str:
    # Encode bytes to a URL-safe base64 string without padding
    return base64.urlsafe_b64encode(data).decode('utf-8').strip("=")

def b64_decode(data: str) -> bytes:
    # Add padding if necessary and decode the URL-safe base64 string back to bytes
    pad = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + pad)