import os
import shutil
import pytest

from crypto.ecc.identity_keys import create_and_store_identity_keys, load_identity_keys
from crypto.ecc.serialization import public_key_to_pem

TEST_KEYS_DIR = "./test_keys/"
PRIVATE_KEY_FILE = os.path.join(TEST_KEYS_DIR, "identity_private.pem")
PUBLIC_KEY_FILE = os.path.join(TEST_KEYS_DIR, "identity_public.pem")


def setup_function():
    shutil.rmtree(TEST_KEYS_DIR, ignore_errors=True)


def teardown_function():
    shutil.rmtree(TEST_KEYS_DIR, ignore_errors=True)


def test_create_and_store_identity_keys():
    private_key, public_key = create_and_store_identity_keys(PRIVATE_KEY_FILE, PUBLIC_KEY_FILE)

    assert private_key is not None
    assert public_key is not None

    assert os.path.exists(PRIVATE_KEY_FILE)
    assert os.path.getsize(PRIVATE_KEY_FILE) > 0

    assert os.path.exists(PUBLIC_KEY_FILE)
    assert os.path.getsize(PUBLIC_KEY_FILE) > 0


def test_identity_key_files_already_exist():
    create_and_store_identity_keys(PRIVATE_KEY_FILE, PUBLIC_KEY_FILE)

    assert os.path.exists(PRIVATE_KEY_FILE)
    assert os.path.exists(PUBLIC_KEY_FILE)


def test_create_identity_keys_raises_if_already_exist():
    create_and_store_identity_keys(PRIVATE_KEY_FILE, PUBLIC_KEY_FILE)

    with pytest.raises(FileExistsError):
        create_and_store_identity_keys(PRIVATE_KEY_FILE, PUBLIC_KEY_FILE)


def test_load_identity_keys():
    original_private, original_public = create_and_store_identity_keys(PRIVATE_KEY_FILE, PUBLIC_KEY_FILE)

    loaded_private, loaded_public = load_identity_keys(PRIVATE_KEY_FILE, PUBLIC_KEY_FILE)

    assert loaded_private is not None
    assert loaded_public is not None

    # Implicitly tests serialization/deserialization
    assert public_key_to_pem(original_public) == public_key_to_pem(loaded_public)


def test_load_identity_keys_raises_if_missing():
    with pytest.raises(FileNotFoundError):
        load_identity_keys(PRIVATE_KEY_FILE, PUBLIC_KEY_FILE)


def test_load_identity_keys_raises_if_private_key_missing():
    create_and_store_identity_keys(PRIVATE_KEY_FILE, PUBLIC_KEY_FILE)
    os.remove(PRIVATE_KEY_FILE)

    with pytest.raises(FileNotFoundError):
        load_identity_keys(PRIVATE_KEY_FILE, PUBLIC_KEY_FILE)


def test_load_identity_keys_raises_if_public_key_missing():
    create_and_store_identity_keys(PRIVATE_KEY_FILE, PUBLIC_KEY_FILE)
    os.remove(PUBLIC_KEY_FILE)

    with pytest.raises(FileNotFoundError):
        load_identity_keys(PRIVATE_KEY_FILE, PUBLIC_KEY_FILE)