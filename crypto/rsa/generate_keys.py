from crypto.rsa.key_pair import generate_rsa_keypair, save_private_key, save_public_key

private_key, public_key = generate_rsa_keypair()

# Run this code only when rotating RSA public and private keys

save_private_key(private_key, "private_key.pem")
save_public_key(public_key, "public_key.pem")

print("Keys generated successfully!")