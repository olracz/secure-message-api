def save_key_to_file(pem_data, filename):
    # Save the PEM data to a file
    with open(filename, "wb") as f:
        f.write(pem_data)

def load_key_from_file(filename):
    # Load PEM data from a file
    with open(filename, "rb") as f:
        return f.read()
    
    