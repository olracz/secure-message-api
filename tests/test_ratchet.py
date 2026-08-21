from crypto.ecc.key_exchange import perform_ecdh
from crypto.ecc.ratchet import kdf_chain_key, RatchetState, kdf_root_key
from crypto.ecc.key_generation import generate_key_pair
from crypto.ecc.serialization import public_key_to_pem
import secrets
import pytest


def test_kdf_chain_key_returns_different_message_and_chain_keys():

    fake_chain_key = secrets.token_bytes(32)
    message_key, next_chain_key = kdf_chain_key(fake_chain_key)
    assert message_key != next_chain_key


def test_kdf_chain_key_deterministic():
    
    chain_key = secrets.token_bytes(32)

    message_key1, next_chain_key1 = kdf_chain_key(chain_key)
    message_key2, next_chain_key2 = kdf_chain_key(chain_key)

    assert next_chain_key1 == next_chain_key2
    assert message_key1 == message_key2


def test_kdf_chain_key_length_and_type():
    
    chain_key = secrets.token_bytes(32)
    message_key, next_chain_key = kdf_chain_key(chain_key)

    assert type(next_chain_key) == bytes and len(next_chain_key) == 32
    assert type(message_key) == bytes and len(message_key) == 32


def test_kdf_root_key_deterministic():

    fake_root_key = secrets.token_bytes(32) 
    fake_my_private_key, _ = generate_key_pair()
    _, fake_peer_public_key = generate_key_pair()

    ecdh_output = perform_ecdh(fake_my_private_key, fake_peer_public_key)

    root_key1, chain_key1 = kdf_root_key(fake_root_key, ecdh_output)
    root_key2, chain_key2 = kdf_root_key(fake_root_key, ecdh_output)

    assert root_key1 == root_key2
    assert chain_key1 == chain_key2


def test_kdf_root_key_length_and_type():
   
    fake_root_key = secrets.token_bytes(32) 
    fake_my_private_key, _ = generate_key_pair()
    _, fake_peer_public_key = generate_key_pair()

    ecdh_output = perform_ecdh(fake_my_private_key, fake_peer_public_key)

    root_key, chain_key = kdf_root_key(fake_root_key, ecdh_output)

    assert type(chain_key) == bytes and len(chain_key) == 32
    assert type(root_key) == bytes and len(root_key) == 32


def test_ratchet_state_alice_and_bob_agree_on_initial_chain_key():

    master_secret = secrets.token_bytes(32)
    bob_spk_private_key, bob_spk_public_key = generate_key_pair()

    alice = RatchetState.ratchet_state_alice(master_secret, bob_spk_public_key)
    
    bob_dh_output = perform_ecdh(bob_spk_private_key, alice.my_ratchet_public_key)
    bob_root_key, bob_chain_key = kdf_root_key(master_secret, bob_dh_output)

    assert alice.sending_chain_key == bob_chain_key


def test_ratchet_encrypt_decrypt_single_message():
    
    plain_text = "Hello"

    master_secret = secrets.token_bytes(32)
    bob_spk_private_key, bob_spk_public_key = generate_key_pair()

    alice = RatchetState.ratchet_state_alice(master_secret, bob_spk_public_key)
    bob = RatchetState.ratchet_state_bob(master_secret, bob_spk_private_key, bob_spk_public_key)

    encrypted_message = alice.ratchet_encrypt(plain_text)
    decrypted_message = bob.ratchet_decrypt(encrypted_message)

    assert plain_text == decrypted_message


def test_ratchet_multiple_messages_same_direction():

    plain_text_1 = "Hello"
    plain_text_2 = "World"
    
    master_secret = secrets.token_bytes(32)
    bob_spk_private_key, bob_spk_public_key = generate_key_pair()

    alice = RatchetState.ratchet_state_alice(master_secret, bob_spk_public_key)
    bob = RatchetState.ratchet_state_bob(master_secret, bob_spk_private_key, bob_spk_public_key)

    alice_initial_ratchet_key = alice.my_ratchet_public_key

    message_1 = alice.ratchet_encrypt(plain_text_1)
    message_2 = alice.ratchet_encrypt(plain_text_2)

    alice_current_ratchet_key = alice.my_ratchet_public_key

    decrypted_1 = bob.ratchet_decrypt(message_1)
    decrypted_2 = bob.ratchet_decrypt(message_2)

    assert decrypted_1 == plain_text_1
    assert decrypted_2 == plain_text_2
    # Confirms that no DH step happened on alice state since bob didn't send any reply
    assert alice_initial_ratchet_key == alice_current_ratchet_key 


def test_ratchet_triggers_dh_step_on_reply():
   
    plain_text_1 = "Hello"
    plain_text_2 = "World"

    master_secret = secrets.token_bytes(32)
    bob_spk_private_key, bob_spk_public_key = generate_key_pair()

    alice = RatchetState.ratchet_state_alice(master_secret, bob_spk_public_key)
    bob = RatchetState.ratchet_state_bob(master_secret, bob_spk_private_key, bob_spk_public_key)

    alice_initial_ratchet_key = alice.my_ratchet_public_key

    message_a_1 = alice.ratchet_encrypt(plain_text_1)
    decrypted_b_1 = bob.ratchet_decrypt(message_a_1)
    message_b_1 = bob.ratchet_encrypt(plain_text_2)
    decrypted_a_1 = alice.ratchet_decrypt(message_b_1)

    alice_current_ratchet_key = alice.my_ratchet_public_key

    assert alice_initial_ratchet_key != alice_current_ratchet_key


def test_ratchet_full_conversation_round_trip():

    plain_text_1 = "Hello"
    plain_text_2 = "World"
    plain_text_3 = "Secret"

    master_secret = secrets.token_bytes(32)
    bob_spk_private_key, bob_spk_public_key = generate_key_pair()

    alice = RatchetState.ratchet_state_alice(master_secret, bob_spk_public_key)
    bob = RatchetState.ratchet_state_bob(master_secret, bob_spk_private_key, bob_spk_public_key)

    message_a_1 = alice.ratchet_encrypt(plain_text_1)
    message_a_2 = alice.ratchet_encrypt(plain_text_2)

    decrypted_b_1 = bob.ratchet_decrypt(message_a_1)
    decrypted_b_2 = bob.ratchet_decrypt(message_a_2)
    message_b_1 = bob.ratchet_encrypt(plain_text_3)

    decrypted_a_1 = alice.ratchet_decrypt(message_b_1)

    assert decrypted_b_1 == plain_text_1
    assert decrypted_b_2 == plain_text_2  
    assert decrypted_a_1 == plain_text_3
   
def test_ratchet_out_of_order_same_chain():
 
    plain_text_1 = "Hello"
    plain_text_2 = "World"
    plain_text_3 = "Secret"

    master_secret = secrets.token_bytes(32)
    bob_spk_private_key, bob_spk_public_key = generate_key_pair()

    alice = RatchetState.ratchet_state_alice(master_secret, bob_spk_public_key)
    bob = RatchetState.ratchet_state_bob(master_secret, bob_spk_private_key, bob_spk_public_key)    

    message_a_1 = alice.ratchet_encrypt(plain_text_1)
    message_a_2 = alice.ratchet_encrypt(plain_text_2)
    message_a_3 = alice.ratchet_encrypt(plain_text_3)

    decrypted_b2 = bob.ratchet_decrypt(message_a_2)
    decrypted_b1 = bob.ratchet_decrypt(message_a_1)
    decrypted_b3 = bob.ratchet_decrypt(message_a_3)   
    
    assert decrypted_b1 == plain_text_1
    assert decrypted_b2 == plain_text_2
    assert decrypted_b3 == plain_text_3

def test_ratchet_out_of_order_across_dh_boundary():

    plain_text_1 = "Hello"
    plain_text_2 = "World"
    plain_text_3 = "Secret"
    plain_text_4 = "Python"
    plain_text_5 = "Language"

    master_secret = secrets.token_bytes(32)
    bob_spk_private_key, bob_spk_public_key = generate_key_pair()

    alice = RatchetState.ratchet_state_alice(master_secret, bob_spk_public_key)
    bob = RatchetState.ratchet_state_bob(master_secret, bob_spk_private_key, bob_spk_public_key)

    message_a_1 = alice.ratchet_encrypt(plain_text_1)
    message_a_2 = alice.ratchet_encrypt(plain_text_2)

    decrypted_b1 = bob.ratchet_decrypt(message_a_1)
    decrypted_b2 = bob.ratchet_decrypt(message_a_2)
    message_b_1 = bob.ratchet_encrypt(plain_text_3)
    
    decrypted_a1 = alice.ratchet_decrypt(message_b_1)
    message_a_3 = alice.ratchet_encrypt(plain_text_4)
    message_a_4 = alice.ratchet_encrypt(plain_text_5)
     
    decrypted_b3 = bob.ratchet_decrypt(message_a_4)
    decrypted_b4 = bob.ratchet_decrypt(message_a_3)

    assert decrypted_b3 == plain_text_5
    assert decrypted_b4 == plain_text_4
    
    
def test_skip_messsage_keys_raises_when_exceeding_max_skip():

    plain_text_1 = "Hello"

    master_secret = secrets.token_bytes(32)
    bob_spk_private_key, bob_spk_public_key = generate_key_pair()

    alice = RatchetState.ratchet_state_alice(master_secret, bob_spk_public_key)
    bob = RatchetState.ratchet_state_bob(master_secret, bob_spk_private_key, bob_spk_public_key)

    message_a_1 = alice.ratchet_encrypt(plain_text_1)
    decrypted_b1 = bob.ratchet_decrypt(message_a_1)

    with pytest.raises(ValueError):
        bob.skip_message_keys(535)

    
def test_skipped_key_removed_after_use():
    
    plain_text_1 = "Hello"
    plain_text_2 = "World"
    

    master_secret = secrets.token_bytes(32)
    bob_spk_private_key, bob_spk_public_key = generate_key_pair()

    alice = RatchetState.ratchet_state_alice(master_secret, bob_spk_public_key)
    bob = RatchetState.ratchet_state_bob(master_secret, bob_spk_private_key, bob_spk_public_key)

    look_up_key = (public_key_to_pem(alice.my_ratchet_public_key), 0)

    message_a_1 = alice.ratchet_encrypt(plain_text_1)
    message_a_2 = alice.ratchet_encrypt(plain_text_2)
    

    decrypted_b2 = bob.ratchet_decrypt(message_a_2)
    assert look_up_key in bob.skipped_message_keys
    decrypted_b1 = bob.ratchet_decrypt(message_a_1)
    assert look_up_key not in bob.skipped_message_keys
    

   
    