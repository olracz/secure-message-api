from .ecc.handshake import verify_spk_signature, x3dh_sender, x3dh_receiver
from .ecc.key_exchange import derive_x3dh_master_secret
from .ecc.ratchet import RatchetState
from .ecc.serialization import public_key_to_pem


def start_conversation_as_initiator(
    alice_identity_private_key,
    bob_identity_public_key,
    bob_spk_public_key,
    bob_spk_signature,
    bob_otk_public_key=None,
) -> tuple[RatchetState, bytes]:
    
    """ This function is used for user initiating the connection. 
    It starts the handshake, master secret derivation, 
    and ratchet state initiation. Runs once per conversation. 

    Args: alice identity private key, bob_identity_public_key, 
          bob_spk_public_key, bob_spk_signature, bob_otk_public_key

    Returns: Initiator's ratchet state and x3dh eph public key

    Raises: ValueError if verify signature function fails. 
    """

    if not verify_spk_signature(
        bob_identity_public_key, 
        public_key_to_pem(bob_spk_public_key), 
        bob_spk_signature):
        raise ValueError("SPK signature verification failed.")
     
    secret_list, x3dh_eph_public_key = x3dh_sender(alice_identity_private_key, bob_identity_public_key, 
                                                   bob_spk_public_key, bob_otk_public_key)
 
    master_secret = derive_x3dh_master_secret(secret_list)
    ratchet_state = RatchetState.ratchet_state_alice(master_secret, bob_spk_public_key)

    return ratchet_state, x3dh_eph_public_key
  

def start_conversation_as_receiver(
    alice_identity_public_key,
    alice_x3dh_eph_public_key,
    bob_identity_private_key,
    bob_spk_private_key,
    bob_spk_public_key,
    bob_otk_private_key=None
    ) -> RatchetState:

    """ This function is used by the receiver side. Performs operations to derive the 
    master secret using alice's eph public key and identity public key.

    Args: Alice's identity public key, Alice eph public key, bob identity private key, 
    bob spk private key, bob otk private key, bob spk public key

    Returns: Bob's Ratchet State
    """

    secret_list = x3dh_receiver(bob_spk_private_key, bob_identity_private_key, alice_identity_public_key,                    
                                 alice_x3dh_eph_public_key, bob_otk_private_key) 

    master_secret = derive_x3dh_master_secret(secret_list)

    ratchet_state = RatchetState.ratchet_state_bob(master_secret, bob_spk_private_key, bob_spk_public_key)

    return ratchet_state
  