from .key_exchange import perform_ecdh
from .key_generation import generate_key_pair
from .signatures import verify_data

def x3dh_sender(my_private_key, peer_identity_public_key, peer_spk_public_key, 
		peer_otk_public_key =None) -> tuple[list[bytes], object]:
	"""
    Perform the INITIATOR side of an X3DH handshake.

    Generates a fresh, one-time-use ephemeral key pair, then performs
   	3 DH computations (4 if the peer's pre-key bundle included an OTK)
   	against the peer's published identity key, signed pre-key, and
    optional one-time pre-key.

    Returns (secret_list, ephemeral_public_key). The ephemeral public
    key MUST be transmitted to the peer -- without it, the peer (running
    x3dh_receiver) has no way to compute the matching DH2/DH3/DH4 and
    the two sides will derive different, incompatible secrets.

    Call derive_x3dh_master_secret(secret_list) on the returned list
    to get the final master secret -- this function only builds the
    raw ingredients, it does not derive the key itself.
    """
	
	secret_list = []

	eph_private_key, eph_public_key	= generate_key_pair()

	dh1 = perform_ecdh(my_private_key, peer_spk_public_key)
	dh2 = perform_ecdh(eph_private_key, peer_identity_public_key)
	dh3 = perform_ecdh(eph_private_key, peer_spk_public_key)

	if peer_otk_public_key is not None:
		dh4 = perform_ecdh(eph_private_key, peer_otk_public_key)
		secret_list.extend([dh1,dh2,dh3,dh4])

	else:
		dh4 = None
		secret_list.extend([dh1,dh2,dh3])

	return secret_list, eph_public_key


def x3dh_receiver(my_spk_private_key, my_identity_private_key, peer_identity_public_key,
                   peer_ephemeral_public_key, my_otk_private_key=None) -> list[bytes]:

	"""
    Perform the RESPONDER side of an X3DH handshake -- the mirror image
    of x3dh_sender().

    Unlike the sender, the receiver does NOT generate a fresh ephemeral
    key; instead it uses its own already-published SPK/identity/OTK
    private keys against the sender's ephemeral PUBLIC key (received
    over the network). Private/public roles for DH1 and DH2 are swapped
    relative to the sender's version -- this asymmetry is what makes
    both sides land on the same shared secret.

   	my_otk_private_key should be None if this OTK was never issued to
   	this particular sender, or has already been consumed/deleted
   	(Phase 2 hard-deletes OTKs after use) -- must match whether the
   	sender's peer_otk_public_key was provided, or the secret_list
    lengths (and thus the derived secrets) won't agree.
	
    Returns secret_list only -- no ephemeral key to send back, since
   	the receiver never generates one. Call derive_x3dh_master_secret()
   	on the result to get the final master secret.
   	"""
	
	secret_list = []
	dh1 = perform_ecdh(my_spk_private_key, peer_identity_public_key)
	dh2 = perform_ecdh(my_identity_private_key, peer_ephemeral_public_key)
	dh3 = perform_ecdh(my_spk_private_key, peer_ephemeral_public_key)
	
	if my_otk_private_key is not None:
		dh4 = perform_ecdh(my_otk_private_key, peer_ephemeral_public_key)
		secret_list.extend([dh1,dh2,dh3,dh4])
	else:
		dh4 = None
		secret_list.extend([dh1,dh2,dh3])
	
	return secret_list


def verify_spk_signature(identity_public_key, spk_public_pem, signature) -> bool:
    """
    Verify that spk_public_pem was actually signed by the holder of
    identity_public_key's matching private key.

    spk_public_pem must be the EXACT PEM bytes that were originally
    signed in generate_signed_pre_key() -- re-serializing the key
    or passing the raw key object instead of PEM bytes will cause
    verification to fail even for a legitimate SPK.
    """
    return verify_data(identity_public_key, signature, spk_public_pem)