
"""
This script derives Ethereum private keys from a mnemonic following the 
BLS12-381 cryptographic standard. It supports hierarchical key derivation 
using a specified path.
"""

import hashlib
import hmac
from math import ceil
from eth_utils import big_endian_to_int

# BLS12-381 specific constants
ORDER_R = int("52435875175126190479447740508185965837690552500527637822603658699938581184512")

def sha256(data):
    """Compute the SHA-256 hash of the given data."""
    return hashlib.sha256(data).digest()

def i2osp(value, length):
    """
    Convert an integer to an octet string of a specified length.

    Args:
        value (int): Integer value to convert.
        length (int): Desired length of the octet string.

    Returns:
        bytes: Octet string.
    """
    return value.to_bytes(length, byteorder="big")

def os2ip(data):
    """
    Convert an octet string to an integer.

    Args:
        data (bytes): Octet string.

    Returns:
        int: Integer value.
    """
    return int.from_bytes(data, byteorder="big")

def hkdf_extract(salt, input_key_material):
    """
    Perform the HKDF extract step to derive a pseudo-random key (PRK).

    Args:
        salt (bytes): Salt value.
        input_key_material (bytes): Input key material.

    Returns:
        bytes: Pseudo-random key.
    """
    return hmac.new(salt, input_key_material, hashlib.sha256).digest()

def hkdf_expand(prk, info, length):
    """
    Perform the HKDF expand step to derive key material of the desired length.

    Args:
        prk (bytes): Pseudo-random key.
        info (bytes): Context-specific information.
        length (int): Desired length of output key material.

    Returns:
        bytes: Output key material.
    """
    output = b""
    t = b""
    for i in range(1, ceil(length / 32) + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        output += t
    return output[:length]

def hkdf_mod_r(ikm, key_info):
    """
    Map random bytes to the BLS12-381 subgroup using HKDF.

    Args:
        ikm (bytes): Input key material.
        key_info (str): Context-specific information.

    Returns:
        int: Derived private key.
    """
    salt = b"BLS-SIG-KEYGEN-SALT-"
    sk = 0
    while sk == 0:
        salt = sha256(salt)
        prk = hkdf_extract(salt, ikm + i2osp(0, 1))
        okm = hkdf_expand(prk, key_info.encode() + i2osp(48, 2), 48)
        sk_candidate = os2ip(okm)
        sk = sk_candidate % ORDER_R
    return sk

def xor_bytes(data):
    """
    XOR all bytes in the input data with 0xFF.

    Args:
        data (bytes): Input byte array.

    Returns:
        bytes: Result of XOR operation.
    """
    return bytes([b ^ 0xFF for b in data])

def ikm_to_lamport_sk(ikm, salt):
    """
    Generate a Lamport secret key from input key material and a salt.

    Args:
        ikm (bytes): Input key material.
        salt (bytes): Salt value.

    Returns:
        list: List of 32-byte chunks representing the Lamport secret key.
    """
    prk = hkdf_extract(salt, ikm)
    okm = hkdf_expand(prk, b"", 255 * 32)
    return [okm[i * 32 : (i + 1) * 32] for i in range(255)]

def parent_sk_to_lamport_pk(parent_sk, index):
    """
    Derive the Lamport public key from a parent secret key and an index.

    Args:
        parent_sk (int): Parent secret key.
        index (int): Index for derivation.

    Returns:
        bytes: Compressed Lamport public key.
    """
    salt = i2osp(index, 4)
    ikm = i2osp(parent_sk, 32)
    lamport0 = ikm_to_lamport_sk(ikm, salt)
    lamport1 = ikm_to_lamport_sk(xor_bytes(ikm), salt)
    lamport_pk = b"".join(sha256(chunk) for chunk in lamport0 + lamport1)
    return sha256(lamport_pk)

def derive_child_sk(parent_sk, index):
    """
    Derive a child secret key from a parent secret key and an index.

    Args:
        parent_sk (int): Parent secret key.
        index (int): Index for derivation.

    Returns:
        int: Child secret key.
    """
    lamport_pk = parent_sk_to_lamport_pk(parent_sk, index)
    return hkdf_mod_r(lamport_pk, "")

def private_key_from_seed_and_path(seed, path):
    """
    Derive an Ethereum private key from a seed and derivation path.

    Args:
        seed (bytes): Seed value.
        path (str): Derivation path (e.g., "m/12381/3600/0/0/0").

    Returns:
        bytes: Derived private key.
    """
    if not path or len(seed) < 16:
        raise ValueError("Invalid seed or path")
    path_bits = path.split("/")
    if path_bits[0] != "m":
        raise ValueError("Path must start with 'm'")
    sk = hkdf_mod_r(seed, "")
    for bit in path_bits[1:]:
        if not bit.isdigit():
            raise ValueError(f"Invalid path component: {bit}")
        sk = derive_child_sk(sk, int(bit))
    return sk.to_bytes(32, "big")

if __name__ == "__main__":
    mnemonic = "poet hurdle cousin either average visual pipe crowd reform alcohol music afraid fee pizza copy divide fish work pipe scout oppose amount creek canoe"
    seed = hashlib.pbkdf2_hmac("sha512", mnemonic.encode("utf-8"), b"mnemonic", 2048, 64)
    path = "m/12381/3600/0/0/0"
    private_key = private_key_from_seed_and_path(seed, path)
    print(f"Mnemonic: {mnemonic}")
    print(f"Private Key (Hex): {private_key.hex()}")
