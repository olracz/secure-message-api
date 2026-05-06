import os
from .key_generation import generate_key_pair
from .storage import save_key_to_file, load_key_from_file
from .serialization import private_key_to_pem, public_key_to_pem, pem_to_key


def create_and_store_identity_keys(private_key_file, public_key_file):
    """
    Generate a new long-term ECC identity key pair and persist to PEM files.
    Raises FileExistsError if keys already exist — never silently overwrites.
    Returns the (private_key, public_key) objects for immediate use.
    """
    if os.path.exists(private_key_file) or os.path.exists(public_key_file):
        raise FileExistsError(
            f"Identity keys already exist at '{private_key_file}' / '{public_key_file}'. "
            "Delete them manually if you intend to rotate your identity."
        )

    private_key, public_key = generate_key_pair()

    private_pem = private_key_to_pem(private_key)
    public_pem = public_key_to_pem(public_key)

    save_key_to_file(private_pem, private_key_file)
    save_key_to_file(public_pem, public_key_file)

    return private_key, public_key


def load_identity_keys(private_key_file, public_key_file):
    """
    Load existing long-term identity keys from PEM files.
    Raises FileNotFoundError if either file is missing.
    Returns (private_key, public_key) objects.
    """
    if not os.path.exists(private_key_file):
        raise FileNotFoundError(f"Identity private key not found: '{private_key_file}'")
    if not os.path.exists(public_key_file):
        raise FileNotFoundError(f"Identity public key not found: '{public_key_file}'")

    private_pem = load_key_from_file(private_key_file)
    public_pem = load_key_from_file(public_key_file)

    private_key = pem_to_key(private_pem, private=True)
    public_key = pem_to_key(public_pem, private=False)

    return private_key, public_key