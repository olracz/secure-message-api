import os
from .ecc.serialization import public_key_to_pem
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
    # PREKEY BUNDLE ASSEMBLY
    # ──────────────────────────────────────────────

    def get_prekey_bundle(self):
        """
        Assemble a publishable pre-key bundle for upload to the server.
        Contains identity key, signed pre-key, its signature, and one OTK.
        The OTK is hard-deleted immediately on issue — single use only.

        Returns:
            dict with PEM bytes for all public keys, ready for JSON serialization.

        Raises:
            RuntimeError: If identity or pre-keys are not initialized.
        """
        if self.private_key is None or self.spk is None:
            raise RuntimeError(
                "Identity and pre-keys not initialized. "
                "Call initialize_identity() and initialize_pre_keys() first."
            )

        available_otks = self.get_available_otks()
        otk = available_otks[0] if available_otks else None

        if otk:
            self.consume_otk(otk["otk_id"]) 

        return {
            "identity_public_key":      public_key_to_pem(self.public_key),
            "signed_pre_key_id":        self.spk["spk_id"],
            "signed_pre_key":           self.spk["pre_public_pem"],
            "signed_pre_key_signature": self.spk["signature"],
            "one_time_pre_key_id":      otk["otk_id"] if otk else None,
            "one_time_pre_key":         otk["public_pem"] if otk else None,
        }