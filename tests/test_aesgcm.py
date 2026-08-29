import pytest
import secrets
from crypto.aesgcm import encrypt, decrypt
from crypto.aesgcm.exceptions import (
    InvalidKeyError,
    InvalidPlaintextError,
    InvalidCiphertextError,
    DecryptionError
)
from crypto.utils import b64_encode, b64_decode

def make_key():
    """Generate a valid 32-byte AES-GCM session key."""
    return secrets.token_bytes(32)

# ──────────────────────────────────────────────
# ENCRYPT / DECRYPT — HAPPY PATH
# ──────────────────────────────────────────────

def test_basic_encryption_decryption():
    key = make_key()
    plaintext = "Hello, AES-GCM!"

    result = encrypt(key, plaintext)
    decrypted_text = decrypt(key, result["ciphertext"], result["nonce"])
    assert decrypted_text == plaintext

def test_encrypt_returns_ciphertext_and_nonce():
    key = make_key()
    result = encrypt(key, "Hello")
    assert "ciphertext" in result
    assert "nonce" in result
    assert isinstance(result["ciphertext"], str)
    assert isinstance(result["nonce"], str)

def test_encrypt_different_keys_produce_different_ciphertexts():
    key1 = make_key()
    key2 = make_key()
    plaintext = "Same plaintext"

    result1 = encrypt(key1, plaintext)
    result2 = encrypt(key2, plaintext)

    assert result1["ciphertext"] != result2["ciphertext"]
    assert result1["nonce"] != result2["nonce"]

def test_encrypt_message_produces_different_ciphertexts_for_same_key():
    key = make_key()
    plaintext = "Same plaintext"

    result1 = encrypt(key, plaintext)
    result2 = encrypt(key, plaintext)

    assert result1["ciphertext"] != result2["ciphertext"]
    assert result1["nonce"] != result2["nonce"]


# ──────────────────────────────────────────────
# TAMPER DETECTION
# ──────────────────────────────────────────────

def test_tampered_ciphertext_raises_decryption_error():
    key = make_key()
    plaintext = "Hello, AES-GCM!"
    result = encrypt(key, plaintext)

    ciphertext_bytes = bytearray(b64_decode(result["ciphertext"]))
    ciphertext_bytes[0] ^= 0xFF
    bad_data = b64_encode(bytes(ciphertext_bytes))

    with pytest.raises(DecryptionError):
        decrypt(key, bad_data, result["nonce"])

def test_wrong_key_raises_decryption_error():
    key1 = make_key()
    key2 = make_key()
    plaintext = "Hello, AES-GCM!"
    result = encrypt(key1, plaintext)

    with pytest.raises(DecryptionError):
        decrypt(key2, result["ciphertext"], result["nonce"])

# ──────────────────────────────────────────────
# KEY VALIDATION
# ──────────────────────────────────────────────

def test_invalid_key_types_raise_invalid_key_error():
    invalid_keys = [None, "string", 123, 3.14, [], {}, set()]
    for key in invalid_keys:
        with pytest.raises(InvalidKeyError):
            encrypt(key, "Hello")

def test_invalid_key_length_raises_invalid_key_error():
    invalid_keys = [b"short", b"toolong" * 10, b"\x00" * 31, b"\x00" * 33]
    for key in invalid_keys:
        with pytest.raises(InvalidKeyError):
            encrypt(key, "Hello")

# ──────────────────────────────────────────────
# PLAINTEXT VALIDATION
# ──────────────────────────────────────────────

def test_empty_plaintext_raises_invalid_plaintext_error():
    key = make_key()
    with pytest.raises(InvalidPlaintextError):
        encrypt(key, "")

def test_non_string_plaintext_raises_invalid_plaintext_error():
    key = make_key()
    invalid_plaintexts = [None, 123, 3.14, [], {}, set()]
    for plaintext in invalid_plaintexts:
        with pytest.raises(InvalidPlaintextError):
            encrypt(key, plaintext)

# ──────────────────────────────────────────────
# CIPHERTEXT / NONCE VALIDATION
# ──────────────────────────────────────────────

def test_empty_ciphertext_raises_invalid_ciphertext_error():
    key = make_key()
    nonce = b64_encode(secrets.token_bytes(12))
    with pytest.raises(InvalidCiphertextError):
        decrypt(key, "", nonce)


def test_empty_nonce_raises_invalid_ciphertext_error():
    key = make_key()
    ciphertext = b64_encode(secrets.token_bytes(16))
    with pytest.raises(InvalidCiphertextError):
        decrypt(key, ciphertext, "")


def test_invalid_ciphertext_type_raises_invalid_ciphertext_error():
    key = make_key()
    nonce = b64_encode(secrets.token_bytes(12))
    invalid_ciphertexts = [None, 123, 3.14, [], {}, set()]
    for ciphertext in invalid_ciphertexts:
        with pytest.raises(InvalidCiphertextError):
            decrypt(key, ciphertext, nonce)


def test_invalid_nonce_type_raises_invalid_ciphertext_error():
    key = make_key()
    ciphertext = b64_encode(secrets.token_bytes(16))
    invalid_nonces = [None, 123, 3.14, [], {}, set()]
    for nonce in invalid_nonces:
        with pytest.raises(InvalidCiphertextError):
            decrypt(key, ciphertext, nonce)

            