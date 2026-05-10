import os
import shutil
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

from crypto.ecc.identity_keys import create_and_store_identity_keys
from crypto.ecc.serialization import public_key_to_pem
from crypto.ecc.pre_keys import (
    generate_signed_pre_key,
    store_signed_pre_key,
    load_signed_pre_key,
    generate_one_time_pre_keys,
    store_one_time_pre_keys,
    load_one_time_pre_keys,
    delete_one_time_pre_key,
)

TEST_KEYS_DIR = "./test_keys/"
PRIVATE_KEY_FILE = os.path.join(TEST_KEYS_DIR, "identity_private.pem")
PUBLIC_KEY_FILE = os.path.join(TEST_KEYS_DIR, "identity_public.pem")


def setup_function():
    shutil.rmtree(TEST_KEYS_DIR, ignore_errors=True)


def teardown_function():
    shutil.rmtree(TEST_KEYS_DIR, ignore_errors=True)


def _make_identity_keys():
    """Helper — create a fresh identity key pair for SPK signing."""
    return create_and_store_identity_keys(PRIVATE_KEY_FILE, PUBLIC_KEY_FILE)


# ──────────────────────────────────────────────
# SIGNED PRE-KEY (SPK)
# ──────────────────────────────────────────────

def test_generate_signed_pre_key_returns_expected_fields():
    private_key, _ = _make_identity_keys()
    spk = generate_signed_pre_key(private_key, pre_key_id=1)

    assert spk["pre_key_id"] == 1
    assert spk["pre_private_key"] is not None
    assert spk["pre_public_key"] is not None
    assert spk["pre_public_pem"] is not None
    assert spk["signature"] is not None


def test_generate_signed_pre_key_signature_is_valid():
    private_key, public_key = _make_identity_keys()
    spk = generate_signed_pre_key(private_key, pre_key_id=1)

    # Signature must verify against the identity public key
    try:
        public_key.verify(
            spk["signature"],
            spk["pre_public_pem"],
            ec.ECDSA(hashes.SHA256())
        )
    except InvalidSignature:
        pytest.fail("SPK signature verification failed")


def test_generate_signed_pre_key_signature_fails_if_tampered():
    private_key, public_key = _make_identity_keys()
    spk = generate_signed_pre_key(private_key, pre_key_id=1)

    # Tamper the public PEM
    tampered_pem = spk["pre_public_pem"][:-4] + b"XXXX"

    with pytest.raises(InvalidSignature):
        public_key.verify(
            spk["signature"],
            tampered_pem,
            ec.ECDSA(hashes.SHA256())
        )


def test_store_signed_pre_key_files_exist_with_content():
    private_key, _ = _make_identity_keys()
    spk = generate_signed_pre_key(private_key, pre_key_id=1)
    store_signed_pre_key(spk, directory=TEST_KEYS_DIR)

    assert os.path.exists(os.path.join(TEST_KEYS_DIR, "spk_1_private.pem"))
    assert os.path.getsize(os.path.join(TEST_KEYS_DIR, "spk_1_private.pem")) > 0

    assert os.path.exists(os.path.join(TEST_KEYS_DIR, "spk_1_public.pem"))
    assert os.path.getsize(os.path.join(TEST_KEYS_DIR, "spk_1_public.pem")) > 0


def test_store_and_load_signed_pre_key_matches_original():
    private_key, _ = _make_identity_keys()
    spk = generate_signed_pre_key(private_key, pre_key_id=1)
    store_signed_pre_key(spk, directory=TEST_KEYS_DIR)

    loaded = load_signed_pre_key(pre_key_id=1, directory=TEST_KEYS_DIR)

    assert loaded["pre_key_id"] == spk["pre_key_id"]
    assert public_key_to_pem(loaded["pre_public_key"]) == spk["pre_public_pem"]


# ──────────────────────────────────────────────
# ONE-TIME PRE-KEYS (OTK)
# ──────────────────────────────────────────────

def test_generate_one_time_pre_keys_default_count():
    otks = generate_one_time_pre_keys()
    assert len(otks) == 100


def test_generate_one_time_pre_keys_sequential_ids():
    otks = generate_one_time_pre_keys(count=5, start_id=100)
    ids = [otk["otk_id"] for otk in otks]
    assert ids == [100, 101, 102, 103, 104]


def test_generate_one_time_pre_keys_custom_start_id():
    otks = generate_one_time_pre_keys(count=5, start_id=200)
    ids = [otk["otk_id"] for otk in otks]
    assert ids == [200, 201, 202, 203, 204]


def test_store_one_time_pre_keys_files_exist_with_content():
    otks = generate_one_time_pre_keys(count=3, start_id=100)
    store_one_time_pre_keys(otks, directory=TEST_KEYS_DIR)

    for i in [100, 101, 102]:
        private_path = os.path.join(TEST_KEYS_DIR, f"otk_{i}_private.pem")
        public_path = os.path.join(TEST_KEYS_DIR, f"otk_{i}_public.pem")

        assert os.path.exists(private_path)
        assert os.path.getsize(private_path) > 0
        assert os.path.exists(public_path)
        assert os.path.getsize(public_path) > 0


def test_store_and_load_one_time_pre_keys_match_original():
    otks = generate_one_time_pre_keys(count=3, start_id=100)
    store_one_time_pre_keys(otks, directory=TEST_KEYS_DIR)

    loaded = load_one_time_pre_keys(directory=TEST_KEYS_DIR)

    assert len(loaded) == 3
    for original, loaded_otk in zip(otks, loaded):
        assert original["otk_id"] == loaded_otk["otk_id"]
        assert original["public_pem"] == public_key_to_pem(loaded_otk["public_key"])


def test_load_one_time_pre_keys_returns_empty_if_no_directory():
    loaded = load_one_time_pre_keys(directory=TEST_KEYS_DIR)
    assert loaded == []


def test_load_one_time_pre_keys_sorted_by_id():
    otks = generate_one_time_pre_keys(count=3, start_id=100)
    store_one_time_pre_keys(otks, directory=TEST_KEYS_DIR)

    loaded = load_one_time_pre_keys(directory=TEST_KEYS_DIR)
    ids = [otk["otk_id"] for otk in loaded]
    assert ids == sorted(ids)


def test_delete_one_time_pre_key_removes_files():
    otks = generate_one_time_pre_keys(count=3, start_id=100)
    store_one_time_pre_keys(otks, directory=TEST_KEYS_DIR)

    delete_one_time_pre_key(pre_key_id=100, directory=TEST_KEYS_DIR)

    assert not os.path.exists(os.path.join(TEST_KEYS_DIR, "otk_100_private.pem"))
    assert not os.path.exists(os.path.join(TEST_KEYS_DIR, "otk_100_public.pem"))

    # Other OTKs must be untouched
    assert os.path.exists(os.path.join(TEST_KEYS_DIR, "otk_101_private.pem"))
    assert os.path.exists(os.path.join(TEST_KEYS_DIR, "otk_102_private.pem"))


def test_delete_one_time_pre_key_reduces_count():
    otks = generate_one_time_pre_keys(count=3, start_id=100)
    store_one_time_pre_keys(otks, directory=TEST_KEYS_DIR)

    delete_one_time_pre_key(pre_key_id=100, directory=TEST_KEYS_DIR)

    remaining = load_one_time_pre_keys(directory=TEST_KEYS_DIR)
    assert len(remaining) == 2
    assert all(otk["otk_id"] != 100 for otk in remaining)


def test_delete_one_time_pre_key_raises_if_not_found():
    with pytest.raises(FileNotFoundError):
        delete_one_time_pre_key(pre_key_id=999, directory=TEST_KEYS_DIR)