import os

def save_key_to_file(pem_data, filename):
    # Ensure the directory exists and create it if necessary
    os.makedirs(os.path.dirname(filename), exist_ok=True)

    # Save the PEM data to a file
    with open(filename, "wb") as f:
        f.write(pem_data)

def load_key_from_file(filename):
    # Load PEM data from a file
    with open(filename, "rb") as f:
        return f.read()