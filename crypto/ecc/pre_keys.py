from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from .key_generation import generate_key_pair
from .storage import save_key_to_file, load_key_from_file
from .serialization import private_key_to_pem, public_key_to_pem, pem_to_key
import os


def generate_signed_pre_key(identity_private_key, pre_key_id):
    """Generate a new ECC key-pair and sign the pair with the identity key."""
    pre_private_key, pre_public_key = generate_key_pair()
    pre_public_pem = public_key_to_pem(pre_public_key)

    signature = identity_private_key.sign(
        pre_public_pem,
        ec.ECDSA(hashes.SHA256())
    )

    return {
        "pre_key_id": pre_key_id,
        "pre_private_key": pre_private_key,
        "pre_public_key": pre_public_key,
        "pre_public_pem": pre_public_pem,
        "signature": signature
    }


def store_signed_pre_key(signed_pre_key, directory="keys"):
    """
    Store SPK private and public keys as separate PEM files.
    Filenames: spk_<id>_private.pem / spk_<id>_public.pem
    """
    os.makedirs(directory, exist_ok=True)
    key_id = signed_pre_key["pre_key_id"]   

    private_pem = private_key_to_pem(signed_pre_key["pre_private_key"])
    public_pem = signed_pre_key["pre_public_pem"]

    save_key_to_file(private_pem, os.path.join(directory, f"spk_{key_id}_private.pem"))
    save_key_to_file(public_pem, os.path.join(directory, f"spk_{key_id}_public.pem"))
    

def load_signed_pre_key(pre_key_id, directory="keys"):
    """
    Load SPK private and public keys by ID.
    Returns a dict with the loaded key objects.
    """
    private_pem = load_key_from_file(os.path.join(directory, f"spk_{pre_key_id}_private.pem"))
    public_pem = load_key_from_file(os.path.join(directory, f"spk_{pre_key_id}_public.pem"))

    return {
        "pre_key_id": pre_key_id,
        "pre_private_key": pem_to_key(private_pem, private=True),
        "pre_public_key": pem_to_key(public_pem, private=False),
        "pre_public_pem": public_pem,
    }
    

def generate_one_time_pre_keys(count=100, start_id=100):
    """
    Generate `count` OTK key pairs with sequential IDs starting from start_id.
    Returns a list of dicts: { otk_id, private_key, public_key, public_pem }
    """
    otks = []
    for i in range(count):
        private_key, public_key = generate_key_pair()
        otks.append({
            "otk_id": start_id + i,
            "private_key": private_key,
            "public_key": public_key,
            "public_pem": public_key_to_pem(public_key),
        })
    return otks


def store_one_time_pre_keys(one_time_pre_keys, directory="keys"):
    """
    Store each OTK as a pair of PEM files.
    Filenames: otk_<id>_private.pem / otk_<id>_public.pem
    """
    os.makedirs(directory, exist_ok=True)
    for otk in one_time_pre_keys:
        key_id = otk["otk_id"]
        private_pem = private_key_to_pem(otk["private_key"])
        public_pem = otk["public_pem"]

        save_key_to_file(private_pem, os.path.join(directory, f"otk_{key_id}_private.pem"))
        save_key_to_file(public_pem, os.path.join(directory, f"otk_{key_id}_public.pem"))


def load_one_time_pre_keys(directory="keys"):
    """
    Load all available OTKs from the directory.
    Returns a list of dicts with loaded key objects, sorted by ID.
    """
    if not os.path.exists(directory):
        return []

    # Discover all OTK IDs by scanning for private key files
    otk_ids = []
    for filename in os.listdir(directory):
        if filename.startswith("otk_") and filename.endswith("_private.pem"):
            try:
                key_id = int(filename.split("_")[1])
                otk_ids.append(key_id)
            except ValueError:
                continue

    otks = []
    for key_id in sorted(otk_ids):
        private_pem = load_key_from_file(os.path.join(directory, f"otk_{key_id}_private.pem"))
        public_pem = load_key_from_file(os.path.join(directory, f"otk_{key_id}_public.pem"))
        otks.append({
            "otk_id": key_id,
            "private_key": pem_to_key(private_pem, private=True),
            "public_key": pem_to_key(public_pem, private=False),
            "public_pem": public_pem,
        })

    return otks


def delete_one_time_pre_key(pre_key_id, directory="keys"):
    """
    Hard-delete a consumed OTK (both private and public PEM files).
    This enforces forward secrecy — the key is gone after use.
    """
    private_path = os.path.join(directory, f"otk_{pre_key_id}_private.pem")
    public_path = os.path.join(directory, f"otk_{pre_key_id}_public.pem")

    deleted = False
    for path in (private_path, public_path):
        if os.path.exists(path):
            os.remove(path)
            deleted = True

    if not deleted:
        raise FileNotFoundError(f"OTK with ID {pre_key_id} not found in '{directory}'")