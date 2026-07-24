from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def perform_ecdh(my_private_key:bytes, peer_public_key:bytes) -> bytes:
	"""
   	Perform a single raw Elliptic Curve Diffie-Hellman computation.

    Takes one private key and one peer's public key, returns the raw
    shared-secret bytes. This is a low-level primitive only -- it does
    NOT run HKDF. X3DH needs 3-4 separate raw outputs from this function
    (combined with different key pairs each time) before HKDF runs once,
    at the end, on all of them together. Keeping HKDF out of this
    function is what makes it safely reusable for every DH1-DH4 call.
    """

	shared_secret = my_private_key.exchange(ec.ECDH(), peer_public_key)

	return shared_secret

def derive_x3dh_master_secret(secret_list: list[bytes]) -> bytes:
	"""
    Concatenate 3-4 raw ECDH outputs and derive a single 32-byte
    X3DH master secret via HKDF-SHA256.

    This is the ONE place HKDF derivation happens for X3DH -- both
    x3dh_sender() and x3dh_receiver() call this same function on their
    own independently-computed secret_list, guaranteeing they agree
    as long as their underlying DH math was correct.

    Salt is a fixed constant (not random) -- both parties must derive
    this independently and reach the SAME output, which is impossible
    if each side picks its own random salt.

    Output becomes the initial root key for the Double Ratchet (Phase 5).
    it is NOT used directly as an AES session key -- per-message keys
    are derived later via the ratchet's symmetric-key chain.
    """
	
	joined_secret = b"".join(secret_list)
	
	KEY_LENGTH = 32
	salt = b"\x00" * KEY_LENGTH

	master_secret = HKDF(
		algorithm=hashes.SHA256(),
		length=KEY_LENGTH,
		salt=salt,
		info=b'x3dh-master-secret',
		).derive(joined_secret)

	return master_secret