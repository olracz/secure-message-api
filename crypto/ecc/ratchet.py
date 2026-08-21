from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from ..aesgcm import encrypt, decrypt
from .serialization import public_key_to_pem, pem_to_key
from .key_exchange import perform_ecdh
from .key_generation import generate_key_pair
import hmac

CHAIN_KEY_LABEL = b"DoubleRatchetChainKey"
MESSAGE_KEY_LABEL = b"DoubleRatchetMessageKey"
MAX_SKIP = 100

def kdf_chain_key(chain_key: bytes) -> tuple[bytes, bytes]:
    """Advance the symmetric ratchet by one step using HMAC-SHA256.

    Args:
        chain_key: Current 32-byte chain key.

    Returns:
        Tuple of (message_key, next_chain_key), each 32 bytes.
    """  

    message_key = hmac.digest(chain_key, MESSAGE_KEY_LABEL, "sha256")
    next_chain_key = hmac.digest(chain_key, CHAIN_KEY_LABEL, "sha256")

    return message_key, next_chain_key



def kdf_root_key(root_key: bytes, fresh_dh_output: bytes) -> tuple[bytes, bytes]:
    """Advance the DH ratchet, deriving a new root key and chain key.

    Args:
        root_key: Current 32-byte root key, used as HKDF salt.
        fresh_dh_output: Raw ECDH output from perform_ecdh().

    Returns:
        Tuple of (new_root_key, new_chain_key), each 32 bytes.
    """

    kdf_output = HKDF(
	                algorithm=hashes.SHA256(),
	                length=64,
 	                salt=root_key,
	                info=b'double-ratchet-hkdf',
	                ).derive(fresh_dh_output)

    next_root_key = kdf_output[:32]
    next_chain_key = kdf_output[32:]

    return next_root_key, next_chain_key


class RatchetState:
    def __init__(self, root_key, sending_chain_key=None, receiving_chain_key=None,   
                 my_ratchet_private_key=None, my_ratchet_public_key=None, 
                 their_ratchet_public_key=None, skipped_message_keys=None):

        """Double Ratchet session state for one party in a conversation.

        Args:
            root_key: 32-byte root key (from X3DH master_secret or a prior
                DH ratchet step).
            sending_chain_key: Current sending chain key, if established.
            receiving_chain_key: Current receiving chain key, if established.
            my_ratchet_private_key: This party's current ratchet private key.
            my_ratchet_public_key: This party's current ratchet public key.
            their_ratchet_public_key: Peer's last-known ratchet public key.
            skipped_message_keys: Optional pre-populated skip cache; defaults
                to an empty dict.
        """

        self.root_key = root_key
        self.sending_chain_key = sending_chain_key
        self.receiving_chain_key = receiving_chain_key
        self.my_ratchet_private_key = my_ratchet_private_key
        self.my_ratchet_public_key = my_ratchet_public_key
        self.their_ratchet_public_key = their_ratchet_public_key
        self.skipped_message_keys = skipped_message_keys
        if self.skipped_message_keys is None:
            self.skipped_message_keys = {}

        # NOT parameters -- every new ratchet always starts at 0 for these three, 
        # so they're set directly here rather than exposed for the caller to set. 
        self.sending_message_number = 0 
        self.receiving_message_number = 0 
        self.previous_sending_chain_length = 0


    @classmethod
    def ratchet_state_alice(cls, master_secret, bob_spk_public_key):
        """Construct the initiator's ratchet state.

        Generates a new ratchet key pair and performs one DH ratchet step
        against the peer's signed pre-key, establishing an initial sending
        chain.

        Args:
            master_secret: 32-byte X3DH output.
            bob_spk_public_key: Peer's signed pre-key public key.

        Returns:
            A new RatchetState instance.
        """

        ratchet_priv_key, ratchet_pub_key = generate_key_pair()
        dh_output = perform_ecdh(ratchet_priv_key, bob_spk_public_key)
        root_key, sending_chain_key = kdf_root_key(master_secret, dh_output)

        return cls(root_key=root_key, sending_chain_key=sending_chain_key, 
        receiving_chain_key=None, my_ratchet_private_key=ratchet_priv_key,
        my_ratchet_public_key=ratchet_pub_key, their_ratchet_public_key=bob_spk_public_key)


    @classmethod
    def ratchet_state_bob(cls, master_secret, bob_spk_private_key, bob_spk_public_key):
        """Construct the responder's ratchet state.

        No DH step is performed; root_key is set directly from
        master_secret and the existing signed pre-key pair is reused as
        the initial ratchet key pair.

        Args:
            master_secret: 32-byte X3DH output.
            bob_spk_private_key: This party's signed pre-key private key.
            bob_spk_public_key: This party's signed pre-key public key.

        Returns:
            A new RatchetState instance.
        """

        return cls(
        root_key=master_secret,
        sending_chain_key=None,
        receiving_chain_key=None,
        my_ratchet_private_key=bob_spk_private_key,
        my_ratchet_public_key=bob_spk_public_key,
        their_ratchet_public_key=None,
        )

    
    def skip_message_keys(self, until: int):
        """ Raises value error if the gap between receiving message number + max skip and until is too far. Stores skipped       
        message keys while receiving message number is less than until.

        Args: until = sending message number of the sender 

        Returns: None, only stores skipped message keys as value with the 
             self.their_ratchet_public_key and self.receiving_message_number as keys

        """
        if self.receiving_message_number + MAX_SKIP < until:
            raise ValueError(f"Cannot skip {until - self.receiving_message_number} messages, exceeds MAX_SKIP")

        if self.receiving_chain_key is not None:
            while self.receiving_message_number < until:
               message_key, self.receiving_chain_key = kdf_chain_key(self.receiving_chain_key)
               self.skipped_message_keys[public_key_to_pem(self.their_ratchet_public_key), 
                                         self.receiving_message_number] = message_key
               self.receiving_message_number += 1

 
    def try_skipped_message_keys(self, envelope: dict) -> str | None:
        """ Checks if look_up_key in dictionary and fetch it to be used in decryption and then deletes it from the dictionary
     
        Args: envelope

        Returns: decrypted message if look up key in skipped message keys dictionary, else none.
        """
        look_up_key = (envelope["ratchet_public_key"], envelope["message_number"])

        if look_up_key in self.skipped_message_keys:
           message_key = self.skipped_message_keys[look_up_key]
           self.skipped_message_keys.pop(look_up_key)
           return decrypt(message_key, envelope["ciphertext"], envelope["nonce"])

        return None

    def ratchet_encrypt(self, plaintext: str) -> dict:
        """Encrypt one outgoing message.

        Args:
            plaintext: Message text to encrypt.

        Returns:
            Envelope dict containing ratchet_public_key, previous_chain_key_length,
            message_number, ciphertext, and nonce.
        """

        message_key, self.sending_chain_key = kdf_chain_key(self.sending_chain_key)

        header = {
            "ratchet_public_key": public_key_to_pem(self.my_ratchet_public_key),
            "previous_chain_key_length": self.previous_sending_chain_length,
            "message_number": self.sending_message_number,
        }

        self.sending_message_number += 1

        encrypted = encrypt(message_key, plaintext)
    
        encrypt_envelope = header | encrypted

        return encrypt_envelope

    def ratchet_decrypt(self, envelope: dict) -> str:
        """Decrypt one incoming message, performing a DH ratchet step first
        if the envelope's ratchet key differs from the last-known peer key.

        Args:
            envelope: Dict as produced by ratchet_encrypt().

        Returns:
            Decrypted plaintext string.

        Raises:
            cryptography.exceptions.InvalidTag: If authentication fails.
        """
       
        skipped_result = self.try_skipped_message_keys(envelope)
        if skipped_result is not None:
                return skipped_result


        incoming_key_obj = pem_to_key(envelope["ratchet_public_key"], private=False)
 
        is_new = (self.their_ratchet_public_key is None or
                 public_key_to_pem(incoming_key_obj) != public_key_to_pem(self.their_ratchet_public_key))

        if is_new:
           self.skip_message_keys(envelope["previous_chain_key_length"])

           self.their_ratchet_public_key = incoming_key_obj
           shared_key = perform_ecdh(self.my_ratchet_private_key, self.their_ratchet_public_key)
           self.root_key, self.receiving_chain_key = kdf_root_key(self.root_key, shared_key)
           self.receiving_message_number = 0 
           self.skip_message_keys(envelope["message_number"])
           decrypt_message_key, self.receiving_chain_key = kdf_chain_key(self.receiving_chain_key)
           self.receiving_message_number += 1
           self.my_ratchet_private_key, self.my_ratchet_public_key = generate_key_pair()
           shared_key = perform_ecdh(self.my_ratchet_private_key, self.their_ratchet_public_key)
           self.root_key, self.sending_chain_key = kdf_root_key(self.root_key, shared_key)
           self.previous_sending_chain_length = self.sending_message_number
           self.sending_message_number = 0 

        else:
           self.skip_message_keys(envelope["message_number"])
           decrypt_message_key, self.receiving_chain_key = kdf_chain_key(self.receiving_chain_key)
           self.receiving_message_number += 1

        decrypted_text = decrypt(decrypt_message_key, envelope["ciphertext"], envelope["nonce"])

        return decrypted_text

