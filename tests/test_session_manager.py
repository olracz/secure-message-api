import pytest
import secrets
from crypto.ecc.key_generation import generate_key_pair
from crypto.ecc.serialization import public_key_to_pem
from crypto.ecc.signatures import sign_data
from crypto.session_manager import (
    start_conversation_as_initiator,
    start_conversation_as_receiver,
)
from crypto.ecc.ratchet import RatchetState


def _make_bob_bundle(with_otk=True):
    """Helper — generate a full Bob pre-key bundle."""
    bob_identity_private, bob_identity_public = generate_key_pair()
    bob_spk_private, bob_spk_public = generate_key_pair()
    bob_spk_signature = sign_data(bob_identity_private, public_key_to_pem(bob_spk_public))

    otk_private, otk_public = (generate_key_pair() if with_otk else (None, None))

    return {
        "bob_identity_private": bob_identity_private,
        "bob_identity_public": bob_identity_public,
        "bob_spk_private": bob_spk_private,
        "bob_spk_public": bob_spk_public,
        "bob_spk_signature": bob_spk_signature,
        "bob_otk_private": otk_private,
        "bob_otk_public": otk_public,
    }


def _make_alice():
    """Helper — generate Alice's identity key pair."""
    alice_private, alice_public = generate_key_pair()
    return alice_private, alice_public


# ──────────────────────────────────────────────
# INITIATOR SIDE
# ──────────────────────────────────────────────

def test_initiator_returns_ratchet_state_and_eph_key_with_otk():
    alice_private, alice_public = _make_alice()
    bundle = _make_bob_bundle(with_otk=True)

    ratchet_state, eph_public_key = start_conversation_as_initiator(
        alice_private,
        bundle["bob_identity_public"],
        bundle["bob_spk_public"],
        bundle["bob_spk_signature"],
        bundle["bob_otk_public"],
    )

    assert isinstance(ratchet_state, RatchetState)
    assert eph_public_key is not None


def test_initiator_returns_ratchet_state_and_eph_key_without_otk():
    alice_private, alice_public = _make_alice()
    bundle = _make_bob_bundle(with_otk=False)

    ratchet_state, eph_public_key = start_conversation_as_initiator(
        alice_private,
        bundle["bob_identity_public"],
        bundle["bob_spk_public"],
        bundle["bob_spk_signature"],
    )

    assert isinstance(ratchet_state, RatchetState)
    assert eph_public_key is not None


def test_initiator_raises_if_spk_signature_invalid():
    alice_private, alice_public = _make_alice()
    bundle = _make_bob_bundle(with_otk=True)

    # Tamper the signature
    tampered_signature = bytes([b ^ 0xFF for b in bundle["bob_spk_signature"]])

    with pytest.raises(ValueError):
        start_conversation_as_initiator(
            alice_private,
            bundle["bob_identity_public"],
            bundle["bob_spk_public"],
            tampered_signature,
            bundle["bob_otk_public"],
        )


# ──────────────────────────────────────────────
# RECEIVER SIDE
# ──────────────────────────────────────────────

def test_receiver_returns_ratchet_state_with_otk():
    alice_private, alice_public = _make_alice()
    bundle = _make_bob_bundle(with_otk=True)

    _, eph_public_key = start_conversation_as_initiator(
        alice_private,
        bundle["bob_identity_public"],
        bundle["bob_spk_public"],
        bundle["bob_spk_signature"],
        bundle["bob_otk_public"],
    )

    ratchet_state = start_conversation_as_receiver(
        alice_public,
        eph_public_key,
        bundle["bob_identity_private"],
        bundle["bob_spk_private"],
        bundle["bob_spk_public"],
        bundle["bob_otk_private"],
    )

    assert isinstance(ratchet_state, RatchetState)


def test_receiver_returns_ratchet_state_without_otk():
    alice_private, alice_public = _make_alice()
    bundle = _make_bob_bundle(with_otk=False)

    _, eph_public_key = start_conversation_as_initiator(
        alice_private,
        bundle["bob_identity_public"],
        bundle["bob_spk_public"],
        bundle["bob_spk_signature"],
    )

    ratchet_state = start_conversation_as_receiver(
        alice_public,
        eph_public_key,
        bundle["bob_identity_private"],
        bundle["bob_spk_private"],
        bundle["bob_spk_public"],
    )

    assert isinstance(ratchet_state, RatchetState)


# ──────────────────────────────────────────────
# END TO END — INITIATOR AND RECEIVER AGREE
# ──────────────────────────────────────────────

def test_initiator_and_receiver_agree_with_otk():
    alice_private, alice_public = _make_alice()
    bundle = _make_bob_bundle(with_otk=True)

    alice_ratchet, eph_public_key = start_conversation_as_initiator(
        alice_private,
        bundle["bob_identity_public"],
        bundle["bob_spk_public"],
        bundle["bob_spk_signature"],
        bundle["bob_otk_public"],
    )

    bob_ratchet = start_conversation_as_receiver(
        alice_public,
        eph_public_key,
        bundle["bob_identity_private"],
        bundle["bob_spk_private"],
        bundle["bob_spk_public"],
        bundle["bob_otk_private"],
    )

    # Verify both sides agree by encrypting and decrypting
    plaintext = "Hello Bob!"
    envelope = alice_ratchet.ratchet_encrypt(plaintext)
    decrypted = bob_ratchet.ratchet_decrypt(envelope)

    assert decrypted == plaintext


def test_initiator_and_receiver_agree_without_otk():
    alice_private, alice_public = _make_alice()
    bundle = _make_bob_bundle(with_otk=False)

    alice_ratchet, eph_public_key = start_conversation_as_initiator(
        alice_private,
        bundle["bob_identity_public"],
        bundle["bob_spk_public"],
        bundle["bob_spk_signature"],
    )

    bob_ratchet = start_conversation_as_receiver(
        alice_public,
        eph_public_key,
        bundle["bob_identity_private"],
        bundle["bob_spk_private"],
        bundle["bob_spk_public"],
    )

    plaintext = "Hello Bob without OTK!"
    envelope = alice_ratchet.ratchet_encrypt(plaintext)
    decrypted = bob_ratchet.ratchet_decrypt(envelope)

    assert decrypted == plaintext


def test_full_conversation_round_trip():
    alice_private, alice_public = _make_alice()
    bundle = _make_bob_bundle(with_otk=True)

    alice_ratchet, eph_public_key = start_conversation_as_initiator(
        alice_private,
        bundle["bob_identity_public"],
        bundle["bob_spk_public"],
        bundle["bob_spk_signature"],
        bundle["bob_otk_public"],
    )

    bob_ratchet = start_conversation_as_receiver(
        alice_public,
        eph_public_key,
        bundle["bob_identity_private"],
        bundle["bob_spk_private"],
        bundle["bob_spk_public"],
        bundle["bob_otk_private"],
    )

    # Alice sends two messages
    msg_1 = alice_ratchet.ratchet_encrypt("Hello Bob!")
    msg_2 = alice_ratchet.ratchet_encrypt("How are you?")

    decrypted_1 = bob_ratchet.ratchet_decrypt(msg_1)
    decrypted_2 = bob_ratchet.ratchet_decrypt(msg_2)

    # Bob replies — triggers DH ratchet on Alice
    bob_reply = bob_ratchet.ratchet_encrypt("Hello Alice!")
    decrypted_reply = alice_ratchet.ratchet_decrypt(bob_reply)

    assert decrypted_1 == "Hello Bob!"
    assert decrypted_2 == "How are you?"
    assert decrypted_reply == "Hello Alice!"