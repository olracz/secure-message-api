import os
import shutil
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

from crypto.crypto_service import CryptoService
from crypto.ecc.serialization import public_key_to_pem

TEST_KEYS_DIR = "./test_keys/"


def setup_function():
    shutil.rmtree(TEST_KEYS_DIR, ignore_errors=True)


def teardown_function():
    shutil.rmtree(TEST_KEYS_DIR, ignore_errors=True)


def _make_crypto_service():
    """Helper — create and initialize a CryptoService instance."""
    cs = CryptoService(key_dir=TEST_KEYS_DIR)
    cs.initialize_identity()
    return cs


# ──────────────────────────────────────────────
# IDENTITY
# ──────────────────────────────────────────────

def test_initialize_identity_generates_keys():
    cs = CryptoService(key_dir=TEST_KEYS_DIR)
    cs.initialize_identity()

    assert cs.private_key is not None
    assert cs.public_key is not None
    assert os.path.exists(os.path.join(TEST_KEYS_DIR, "identity_private.pem"))
    assert os.path.getsize(os.path.join(TEST_KEYS_DIR, "identity_private.pem")) > 0
    assert os.path.exists(os.path.join(TEST_KEYS_DIR, "identity_public.pem"))
    assert os.path.getsize(os.path.join(TEST_KEYS_DIR, "identity_public.pem")) > 0


def test_initialize_identity_loads_existing_keys():
    cs = CryptoService(key_dir=TEST_KEYS_DIR)

    # First run → generate
    cs.initialize_identity()
    first_pub = public_key_to_pem(cs.public_key)

    # Second run → load existing
    cs.initialize_identity()
    second_pub = public_key_to_pem(cs.public_key)

    # Must be the same key — not regenerated
    assert first_pub == second_pub


# ──────────────────────────────────────────────
# PRE-KEYS
# ──────────────────────────────────────────────

def test_initialize_pre_keys_raises_without_identity():
    cs = CryptoService(key_dir=TEST_KEYS_DIR)

    with pytest.raises(RuntimeError):
        cs.initialize_pre_keys()


def test_initialize_pre_keys_generates_spk():
    cs = _make_crypto_service()
    cs.initialize_pre_keys()

    assert cs.spk is not None
    assert cs.spk["pre_key_id"] == cs.spk_id
    assert os.path.exists(os.path.join(TEST_KEYS_DIR, f"spk_{cs.spk_id}_private.pem"))
    assert os.path.exists(os.path.join(TEST_KEYS_DIR, f"spk_{cs.spk_id}_public.pem"))


def test_initialize_pre_keys_generates_otk_batch():
    cs = _make_crypto_service()
    cs.initialize_pre_keys()

    available = cs.get_available_otks()
    assert len(available) == 100


def test_initialize_pre_keys_skips_if_spk_exists():
    cs = _make_crypto_service()
    cs.initialize_pre_keys()

    # Store original SPK public key
    original_spk_pem = public_key_to_pem(cs.spk["pre_public_key"])

    # Second call — should load existing SPK, not regenerate
    cs.initialize_pre_keys()
    second_spk_pem = public_key_to_pem(cs.spk["pre_public_key"])

    assert original_spk_pem == second_spk_pem


def test_initialize_pre_keys_skips_otk_if_pool_exists():
    cs = _make_crypto_service()
    cs.initialize_pre_keys()

    first_otks = cs.get_available_otks()
    first_ids = [otk["otk_id"] for otk in first_otks]

    # Second call — should not generate new OTKs
    cs.initialize_pre_keys()
    second_otks = cs.get_available_otks()
    second_ids = [otk["otk_id"] for otk in second_otks]

    assert first_ids == second_ids


# ──────────────────────────────────────────────
# OTK MANAGEMENT
# ──────────────────────────────────────────────

def test_get_available_otks_returns_full_batch():
    cs = _make_crypto_service()
    cs.initialize_pre_keys()

    available = cs.get_available_otks()
    assert len(available) == 100


def test_consume_otk_removes_it():
    cs = _make_crypto_service()
    cs.initialize_pre_keys()

    first_otk = cs.get_available_otks()[0]
    otk_id = first_otk["otk_id"]

    cs.consume_otk(otk_id)

    remaining = cs.get_available_otks()
    assert all(otk["otk_id"] != otk_id for otk in remaining)


def test_consume_otk_replenishes_when_below_threshold():
    cs = _make_crypto_service()
    cs.initialize_pre_keys()

    # Consume enough OTKs to drop below threshold (20)
    otks = cs.get_available_otks()
    for otk in otks[:81]:  # consume 81, leaving 19 → below threshold of 20
        cs.consume_otk(otk["otk_id"])

    # Pool should have been replenished automatically
    remaining = cs.get_available_otks()
    assert len(remaining) > cs.otk_replenish_threshold


def test_replenish_otks_adds_new_batch():
    cs = _make_crypto_service()
    cs.initialize_pre_keys()

    before = len(cs.get_available_otks())
    cs.replenish_otks()
    after = len(cs.get_available_otks())

    assert after == before + 100


def test_replenish_otks_no_id_collisions():
    cs = _make_crypto_service()
    cs.initialize_pre_keys()

    cs.replenish_otks()

    all_otks = cs.get_available_otks()
    all_ids = [otk["otk_id"] for otk in all_otks]

    # All IDs must be unique
    assert len(all_ids) == len(set(all_ids))


# ──────────────────────────────────────────────
# AUTHENTICATION
# ──────────────────────────────────────────────

def test_sign_authentication_proof_raises_without_identity():
    cs = CryptoService(key_dir=TEST_KEYS_DIR)

    with pytest.raises(RuntimeError):
        cs.sign_authentication_proof("a3f9bc12")


def test_sign_authentication_proof_returns_valid_signature():
    cs = _make_crypto_service()

    challenge = "a3f9bc12"
    signature = cs.sign_authentication_proof(challenge)

    # Verify the signature using the identity public key
    try:
        cs.public_key.verify(
            signature,
            challenge.encode(),
            ec.ECDSA(hashes.SHA256())
        )
    except InvalidSignature:
        pytest.fail("Authentication signature verification failed")


def test_verify_authentication_proof_valid_signature():
    cs = _make_crypto_service()

    challenge = "a3f9bc12"
    signature = cs.sign_authentication_proof(challenge)

    result = cs.verify_authentication_proof(cs.public_key, signature, challenge)
    assert result is True


def test_verify_authentication_proof_tampered_challenge():
    cs = _make_crypto_service()

    challenge = "a3f9bc12"
    signature = cs.sign_authentication_proof(challenge)

    # Verify against a different challenge — should fail
    result = cs.verify_authentication_proof(cs.public_key, signature, "tampered999")
    assert result is False