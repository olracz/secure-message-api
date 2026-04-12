import os
import shutil

from crypto.crypto_service import CryptoService
from crypto.ecc.generate_keys import public_key_to_pem


TEST_KEYS_DIR = "./test_keys/"


def setup_function():
    # Runs before each test
    shutil.rmtree(TEST_KEYS_DIR, ignore_errors=True)


def teardown_function():
    # Runs after each test
    shutil.rmtree(TEST_KEYS_DIR, ignore_errors=True)


def test_generate_keys_when_missing():
    cs = CryptoService(key_dir=TEST_KEYS_DIR)

    cs.initial_client_identity()

    assert cs.private_key is not None
    assert cs.public_key is not None
    assert os.path.exists(os.path.join(TEST_KEYS_DIR, "private.pem"))
    assert os.path.exists(os.path.join(TEST_KEYS_DIR, "public.pem"))


def test_load_existing_keys():
    cs = CryptoService(key_dir=TEST_KEYS_DIR)

    # First run → generate
    cs.initial_client_identity()
    first_pub = public_key_to_pem(cs.public_key)

    # Second run → should load
    cs.initial_client_identity()
    second_pub = public_key_to_pem(cs.public_key)

    assert first_pub == second_pub

def test_dummy():
    assert True 