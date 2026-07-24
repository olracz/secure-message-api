from crypto.ecc.key_exchange import perform_ecdh, derive_x3dh_master_secret
from crypto.ecc.key_generation import generate_key_pair
import pytest

def test_perform_ecdh_rejects_invalid_key_types():
      with pytest.raises(Exception):
          perform_ecdh("Random String", 123)

def test_perform_ecdh_agreement():
    alice_private, alice_public = generate_key_pair()
    bob_private, bob_public = generate_key_pair()

    alice_shared_secret = perform_ecdh(alice_private, bob_public)
    bob_shared_secret = perform_ecdh(bob_private, alice_public)

    assert alice_shared_secret == bob_shared_secret

def test_perform_ecdh_shared_secret_length_and_type():
    alice_private, alice_public = generate_key_pair()
    bob_private, bob_public = generate_key_pair()

    alice_shared_secret = perform_ecdh(alice_private, bob_public)
    bob_shared_secret = perform_ecdh(bob_private, alice_public)

    assert len(alice_shared_secret) == 32
    assert isinstance(alice_shared_secret, bytes)
    assert len(bob_shared_secret) == 32
    assert isinstance(bob_shared_secret, bytes)

def test_derive_x3dh_master_secret_agreement():
    alice_secret_list = [b"fake1", b"fake2", b"fake3", b"fake4"]
    bob_secret_list = [b"fake1", b"fake2", b"fake3", b"fake4"]

    alice_master_secret = derive_x3dh_master_secret(alice_secret_list)
    bob_master_secret = derive_x3dh_master_secret(bob_secret_list)

    assert alice_master_secret == bob_master_secret
    

def test_derive_x3dh_master_secret_different_input():

    alice_secret_list = [b"fake1", b"fake2", b"fake3", b"fake4"]
    bob_secret_list = [b"fake1", b"fake2", b"fake5", b"fake6"]

    alice_master_secret = derive_x3dh_master_secret(alice_secret_list)
    bob_master_secret = derive_x3dh_master_secret(bob_secret_list)

    assert alice_master_secret != bob_master_secret
	

def test_derive_x3dh_master_secret_length_and_type():

    alice_secret_list = [b"fake1", b"fake2", b"fake3", b"fake4"]
    alice_master_secret = derive_x3dh_master_secret(alice_secret_list)

    assert len(alice_master_secret) == 32
    assert isinstance(alice_master_secret, bytes)
	