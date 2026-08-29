import base64
from .exceptions import InvalidKeyError, InvalidPlaintextError, InvalidCiphertextError

AES_KEY_LENGTH = 32  # AES-256 requires exactly 32 bytes


def validate_key(session_key):
    """Validate AES-GCM session key before any cryptographic operation.

    Args:
        session_key: The key to validate.
    
    Raises:
        InvalidKeyError: If the key is not 32 bytes of type bytes.
    """
    if not isinstance(session_key, bytes):
        raise InvalidKeyError(
            f"Session key must be bytes, got {type(session_key).__name__}."
        )
    if len(session_key) != AES_KEY_LENGTH:
        raise InvalidKeyError(
            f"Session key must be {AES_KEY_LENGTH} bytes, got {len(session_key)}."
        )


def validate_plaintext(plaintext):
    """Validate plaintext before encryption.

    Args:
        plaintext: The plaintext to validate.

    Raises:
        InvalidPlaintextError: If plaintext is not a non-empty string.
    """
    if not isinstance(plaintext, str):
        raise InvalidPlaintextError(
            f"Plaintext must be a string, got {type(plaintext).__name__}."
        )
    if not plaintext:
        raise InvalidPlaintextError("Plaintext must not be empty.")


def validate_ciphertext_and_nonce(ciphertext, nonce):
    """Validate ciphertext and nonce before decryption.

    Args:
        ciphertext: Base64-encoded ciphertext string.
        nonce:      Base64-encoded nonce string.

    Raises:
        InvalidCiphertextError: If either value is missing, not a string,
                                or not valid base64.
    """
    for name, value in [("ciphertext", ciphertext), ("nonce", nonce)]:
        if not isinstance(value, str):
            raise InvalidCiphertextError(
                f"{name} must be a string, got {type(value).__name__}."
            )
        if not value:
            raise InvalidCiphertextError(f"{name} must not be empty.")
        try:
            base64.b64decode(value + "=" * (-len(value) % 4))
        except Exception:
            raise InvalidCiphertextError(
                f"{name} is not valid base64."
            )