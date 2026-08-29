class AESGCMError(Exception):
    """Base exception for all AES-GCM errors."""
    pass


class InvalidKeyError(AESGCMError):
    """Raised when the session key is invalid.
    
    Common causes:
        - Key is not bytes
        - Key length is not 32 bytes (AES-256 requires exactly 32)
        - Key is all zeros or otherwise weak
    """
    pass


class InvalidPlaintextError(AESGCMError):
    """Raised when the plaintext is invalid.

    Common causes:
        - Plaintext is not a string
        - Plaintext is empty
    """
    pass


class InvalidCiphertextError(AESGCMError):
    """Raised when the ciphertext or nonce is invalid.

    Common causes:
        - Ciphertext is not a string
        - Ciphertext is empty
        - Ciphertext is not valid base64
        - Nonce is not a string
        - Nonce is not valid base64
    """
    pass


class DecryptionError(AESGCMError):
    """Raised when AES-GCM decryption fails.

    Wraps cryptography.exceptions.InvalidTag — means the ciphertext
    was tampered with, the wrong key was used, or the nonce was reused.
    Never expose the original exception message to the client — it leaks
    internal state. Log it server-side and return a generic message.
    """
    pass