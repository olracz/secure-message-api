from .key_generation import generate_key_pair
from .storage import save_key_to_file, load_key_from_file
from .serialization import private_key_to_pem, public_key_to_pem, pem_to_key

def create_and_store_identity_keys(private_key_file, public_key_file):
    # Generate a new ECC key pair
    private_key, public_key = generate_key_pair()

    # Convert keys to PEM format
    private_pem = private_key_to_pem(private_key)
    public_pem = public_key_to_pem(public_key)

    # Save PEM data to files
    save_key_to_file(private_pem, private_key_file)
    save_key_to_file(public_pem, public_key_file)

def load_identity_keys(private_key_file, public_key_file):
    # Load PEM data from files
    private_pem = load_key_from_file(private_key_file)
    public_pem = load_key_from_file(public_key_file)

    # Convert PEM back to key objects
    private_key, public_key = pem_to_key(private_pem, public_pem)

    return private_key, public_key