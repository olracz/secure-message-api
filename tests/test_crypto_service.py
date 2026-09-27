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

def _make_initialized_crypto_service():
    """Helper — create, initialize identity and pre-keys."""
    cs = _make_crypto_service()
    cs.initialize_pre_keys()
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
    assert cs.spk["spk_id"] == cs.spk_id
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

    first_ids = [otk["otk_id"] for otk in cs.get_available_otks()]

    # Second call — should not generate new OTKs
    cs.initialize_pre_keys()
    second_ids = [otk["otk_id"] for otk in cs.get_available_otks()]

    assert first_ids == second_ids


# ──────────────────────────────────────────────
# OTK MANAGEMENT
# ──────────────────────────────────────────────

def test_get_available_otks_returns_full_batch():
    cs = _make_initialized_crypto_service()
    assert len(cs.get_available_otks()) == 100


def test_consume_otk_removes_it():
    cs = _make_initialized_crypto_service()

    first_otk = cs.get_available_otks()[0]
    otk_id = first_otk["otk_id"]
    cs.consume_otk(otk_id)

    remaining = cs.get_available_otks()
    assert all(otk["otk_id"] != otk_id for otk in remaining)


def test_consume_otk_replenishes_when_below_threshold():
    cs = _make_initialized_crypto_service()

    # Consume enough OTKs to drop below threshold (20)
    otks = cs.get_available_otks()
    for otk in otks[:81]:  # consume 81, leaving 19 → below threshold of 20
        cs.consume_otk(otk["otk_id"])

    # Pool should have been replenished automatically
    remaining = cs.get_available_otks()
    assert len(remaining) > cs.otk_replenish_threshold


def test_replenish_otks_adds_new_batch():
    cs = _make_initialized_crypto_service()

    before = len(cs.get_available_otks())
    cs.replenish_otks()
    after = len(cs.get_available_otks())

    assert after == before + 100


def test_replenish_otks_no_id_collisions():
    cs = _make_initialized_crypto_service()
    cs.replenish_otks()

    all_ids = [otk["otk_id"] for otk in cs.get_available_otks()]
    # All IDs must be unique
    assert len(all_ids) == len(set(all_ids))


# ──────────────────────────────────────────────
# PREKEY BUNDLE ASSEMBLY
# ──────────────────────────────────────────────

def test_get_prekey_bundle_raises_without_initialization():
    cs = CryptoService(key_dir=TEST_KEYS_DIR)

    with pytest.raises(RuntimeError):
        cs.get_prekey_bundle()


def test_get_pre_key_bundle_raises_without_pre_keys():
    cs = _make_crypto_service()

    with pytest.raises(RuntimeError):
        cs.get_prekey_bundle()


def test_prekey_bundle_contains_expected_fields():
    cs = _make_initialized_crypto_service()
    bundle = cs.get_prekey_bundle()

    assert "identity_public_key" in bundle
    assert "signed_pre_key_id" in bundle
    assert "signed_pre_key" in bundle
    assert "signed_pre_key_signature" in bundle
    assert "one_time_pre_key_id" in bundle
    assert "one_time_pre_key" in bundle


def test_get_prekey_bundle_consumes_otk():
    cs = _make_initialized_crypto_service()

    before = len(cs.get_available_otks())
    bundle = cs.get_prekey_bundle()
    after = len(cs.get_available_otks())

    # One OTK should have been consumed
    assert after == before - 1
    # Consumed OTK ID should no longer be in pool
    remaining_ids = [otk["otk_id"] for otk in cs.get_available_otks()]
    assert bundle["one_time_pre_key_id"] not in remaining_ids


def test_get_prekey_bundle_without_otk_returns_none_for_otk_fields():
    cs = _make_initialized_crypto_service()

    # Consume all OTKs
    otks = cs.get_available_otks()
    for otk in otks:
        cs.consume_otk(otk["otk_id"])

    # Manually prevent auto-replenishment for this test
    cs.otk_replenish_threshold = 0

    # Consume until truly empty
    remaining = cs.get_available_otks()
    for otk in remaining:
        delete_one_time_pre_key = otk["otk_id"]
        cs.consume_otk(delete_one_time_pre_key)

    bundle = cs.get_prekey_bundle()

    assert bundle["one_time_pre_key_id"] is None
    assert bundle["one_time_pre_key"] is None  


def test_get_prekey_bundle_identity_key_matches_service_public_key():
    cs = _make_initialized_crypto_service()
    bundle = cs.get_prekey_bundle()

    assert bundle["identity_public_key"] == public_key_to_pem(cs.public_key)


def test_get_prekey_bundle_spk_id_matches_service_spk_id():
    cs = _make_initialized_crypto_service()
    bundle = cs.get_prekey_bundle()

    assert bundle["signed_pre_key_id"] == cs.spk_id