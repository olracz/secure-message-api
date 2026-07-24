from crypto.ecc.key_generation import generate_key_pair
from crypto.ecc.signatures import sign_data
from crypto.ecc.handshake import verify_spk_signature, x3dh_sender, x3dh_receiver
from crypto.ecc.key_exchange import derive_x3dh_master_secret
from crypto.ecc.serialization import public_key_to_pem


def test_x3dh_sender_receiver_agree_with_otk():
    
    a_priv_identity_key,a_pub_identity_key = generate_key_pair()
    b_priv_identity_key,b_pub_identity_key = generate_key_pair()
    b_spk_priv_key,b_spk_pub_key = generate_key_pair()
    b_otk_priv_key,b_otk_pub_key = generate_key_pair()

    a_secret_list, a_eph_pub_key = x3dh_sender(a_priv_identity_key, b_pub_identity_key, b_spk_pub_key, b_otk_pub_key)

    b_secret_list = x3dh_receiver(b_spk_priv_key, b_priv_identity_key, a_pub_identity_key, a_eph_pub_key, b_otk_priv_key)

    a_master_secret = derive_x3dh_master_secret(a_secret_list)
    b_master_secret = derive_x3dh_master_secret(b_secret_list)

    assert a_master_secret == b_master_secret


def test_x3dh_sender_receiver_agree_without_otk():
    
    a_priv_identity_key,a_pub_identity_key = generate_key_pair()
    b_priv_identity_key,b_pub_identity_key = generate_key_pair()
    b_spk_priv_key,b_spk_pub_key = generate_key_pair()

    a_secret_list, a_eph_pub_key = x3dh_sender(a_priv_identity_key, b_pub_identity_key, b_spk_pub_key)

    b_secret_list = x3dh_receiver(b_spk_priv_key, b_priv_identity_key, a_pub_identity_key, a_eph_pub_key)

    a_master_secret = derive_x3dh_master_secret(a_secret_list)
    b_master_secret = derive_x3dh_master_secret(b_secret_list)

    assert a_master_secret == b_master_secret

def test_verify_spk_signature_valid():
    a_priv_identity_key, a_pub_identity_key = generate_key_pair()
    a_priv_spk_key, a_pub_spk_key = generate_key_pair()

    spk_pem_key = public_key_to_pem(a_pub_spk_key)
    signature = sign_data(a_priv_identity_key, spk_pem_key)

    assert verify_spk_signature(a_pub_identity_key, spk_pem_key, signature)


def test_verify_spk_signature_rejects_tampered():
    a_priv_identity_key, a_pub_identity_key = generate_key_pair()
    a_priv_spk_key, a_pub_spk_key = generate_key_pair()
    
    spk_pem_key = public_key_to_pem(a_pub_spk_key)
    signature = sign_data(a_priv_identity_key, spk_pem_key + b"x")

    assert verify_spk_signature(a_pub_identity_key, spk_pem_key, signature) == False



