import os

from .ecc.identity_keys import create_and_store_identity_keys, load_identity_keys
from .ecc.pre_keys import (
    generate_signed_pre_key,
    store_signed_pre_key,
    load_signed_pre_key,
    generate_one_time_pre_keys,
    store_one_time_pre_keys,
    load_one_time_pre_keys,
    delete_one_time_pre_key,
)
from .ecc.signatures import sign_data, verify_data
from .aesgcm.aesgcm_encrypt import encrypt
from .aesgcm.aesgcm_decrypt import decrypt


class CryptoService:
    def __init__(self, key_dir="./keys/"):
        self.key_dir = key_dir
        self.private_key = None
        self.public_key = None

        # SPK state
        self.spk = None
        self.spk_id = 1

        # OTK state
        self.otk_start_id = 100
        self.otk_replenish_threshold = 20  # replenish when pool drops below this

    # ──────────────────────────────────────────────
    # IDENTITY
    # ──────────────────────────────────────────────

    def initialize_identity(self):
        """
        Load existing identity keys or create new ones if missing.
        Sets self.private_key and self.public_key.
        """
        private_file = os.path.join(self.key_dir, "identity_private.pem")
        public_file = os.path.join(self.key_dir, "identity_public.pem")

        if os.path.exists(private_file) and os.path.exists(public_file):
            self.private_key, self.public_key = load_identity_keys(
                private_file, public_file
            )
        else:
            self.private_key, self.public_key = create_and_store_identity_keys(
                private_file, public_file
            )

    # ──────────────────────────────────────────────
    # PRE-KEYS
    # ──────────────────────────────────────────────

    def initialize_pre_keys(self):
        """
        Generate, sign, and store SPK + OTK batch on first run.
        Skips if SPK already exists for current spk_id.
        """
        if self.private_key is None:
            raise RuntimeError(
                "Identity keys not initialized. Call initialize_identity() first."
            )

        # SPK — only generate if not already stored
        spk_private_file = os.path.join(self.key_dir, f"spk_{self.spk_id}_private.pem")
        if not os.path.exists(spk_private_file):
            self.spk = generate_signed_pre_key(self.private_key, self.spk_id)
            store_signed_pre_key(self.spk, directory=self.key_dir)
        else:
            self.spk = load_signed_pre_key(self.spk_id, directory=self.key_dir)

        # OTK — only generate if pool is empty
        available = load_one_time_pre_keys(directory=self.key_dir)
        if not available:
            self._generate_and_store_otk_batch()

    def _generate_and_store_otk_batch(self):
        """Internal — generate a fresh OTK batch starting from otk_start_id."""
        otks = generate_one_time_pre_keys(count=100, start_id=self.otk_start_id)
        store_one_time_pre_keys(otks, directory=self.key_dir)

        # Advance start_id for next batch to avoid ID collisions
        self.otk_start_id += 100

    # ──────────────────────────────────────────────
    # OTK MANAGEMENT
    # ──────────────────────────────────────────────

    def get_available_otks(self):
        """Return list of all remaining OTKs sorted by ID."""
        return load_one_time_pre_keys(directory=self.key_dir)

    def consume_otk(self, otk_id):
        """
        Hard delete an OTK after it has been used in a session.
        Automatically replenishes the pool if it drops below threshold.
        """
        delete_one_time_pre_key(otk_id, directory=self.key_dir)

        # Check if pool needs replenishing
        remaining = self.get_available_otks()
        if len(remaining) < self.otk_replenish_threshold:
            self._generate_and_store_otk_batch()

    def replenish_otks(self):
        """Manually trigger OTK pool replenishment."""
        self._generate_and_store_otk_batch()

    # ──────────────────────────────────────────────
    # AUTHENTICATION
    # ──────────────────────────────────────────────

    def sign_authentication_proof(self, challenge):
        """Sign a challenge with the identity private key to prove ownership."""
        if self.private_key is None:
            raise RuntimeError(
                "Identity keys not initialized. Call initialize_identity() first."
            )
        return sign_data(self.private_key, challenge.encode())

    def verify_authentication_proof(self, public_key, signature, challenge):
        """Verify a challenge signature against a given public key."""
        return verify_data(public_key, signature, challenge.encode())