import base64

def b64_encode(data):
    return base64.urlsafe_b64encode(data).decode('utf-8').strip("=")

def b64_decode(data):
    pad = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + pad)