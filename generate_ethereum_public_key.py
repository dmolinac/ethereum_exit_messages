
"""
This script generates an Ethereum public key from a private key using the 
eth_keys library. It also demonstrates how to compress the public key for 
efficient representation.
"""

from eth_keys import keys
import hashlib

# Define the private key in hexadecimal format
private_key_hex = "0x5c012c558a5f1e76bf6addef45dc6549ae3baf514ebc465c07a8cf92454b102d"

# Convert the private key from hex to an eth_keys PrivateKey object
private_key = keys.PrivateKey(bytes.fromhex(private_key_hex[2:]))

# Generate the uncompressed public key
public_key_uncompressed = private_key.public_key

# Compress the public key by hashing it with SHA-384 for compact representation
# This reduces the length to 96 characters (48 bytes)
public_key_compressed = hashlib.sha384(public_key_uncompressed.to_bytes()).hexdigest()

# Output the compressed public key
print("Public Key (96 chars):", public_key_compressed)
