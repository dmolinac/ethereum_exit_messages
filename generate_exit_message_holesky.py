
"""
This script generates a VoluntaryExit message for an Ethereum validator using 
a private key derived from a mnemonic or provided directly. It includes BLS12-381 
cryptographic signing and SSZ serialization.
"""

import argparse
import json
import hmac
import hashlib
import milagro_bls_binding as bls  # BLS binding for signing
import time
from eth2spec.phase0 import spec
from eth2spec.utils.ssz.ssz_typing import Container, Bytes32
from eth2spec.utils.ssz.ssz_impl import hash_tree_root
from eth_utils import decode_hex
from math import ceil

# BLS12-381 Constants
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
        int: Converted integer.
    """
    return int.from_bytes(data, byteorder="big")

def hkdf_extract(salt, input_key_material):
    """
    Perform the HKDF extract step.

    Args:
        salt (bytes): Salt value.
        input_key_material (bytes): Input key material.

    Returns:
        bytes: Pseudo-random key (PRK).
    """
    return hmac.new(salt, input_key_material, hashlib.sha256).digest()

def hkdf_expand(prk, info, length):
    """
    Perform the HKDF expand step.

    Args:
        prk (bytes): Pseudo-random key.
        info (bytes): Context-specific information.
        length (int): Desired length of output key material.

    Returns:
        bytes: Expanded key material.
    """
    output = b""
    t = b""
    for i in range(1, ceil(length / 32) + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        output += t
    return output[:length]

class SigningContainer(Container):
    """
    Container for SSZ signing root calculation.

    Attributes:
        root (Bytes32): Root hash of the operation.
        domain (Bytes32): Domain associated with the operation.
    """
    root: Bytes32
    domain: Bytes32

def compute_domain(fork_version, voluntary_exit_domain_type, genesis_validators_root):
    """
    Compute the domain for a VoluntaryExit operation.

    Args:
        fork_version (str): Current fork version in hexadecimal format.
        voluntary_exit_domain_type (str): Domain type in hexadecimal format.
        genesis_validators_root (str): Root hash of the genesis validators.

    Returns:
        bytes: Computed domain.
    """
    fork_data = spec.ForkData(
        current_version=decode_hex(fork_version),
        genesis_validators_root=decode_hex(genesis_validators_root)
    )
    root = hash_tree_root(fork_data)
    voluntary_exit_domain_type_bytes = decode_hex(voluntary_exit_domain_type)
    return voluntary_exit_domain_type_bytes + root[:28]

def sign_voluntary_exit(private_key_hex, epoch, validator_index, fork_version, genesis_validators_root, voluntary_exit_domain_type):
    """
    Generate a signed VoluntaryExit message.

    Args:
        private_key_hex (str): Validator's private key in hexadecimal format.
        epoch (int): Epoch number for the voluntary exit.
        validator_index (int): Index of the validator exiting.
        fork_version (str): Current fork version in hexadecimal format.
        genesis_validators_root (str): Root hash of the genesis validators.
        voluntary_exit_domain_type (str): Domain type in hexadecimal format.

    Returns:
        str: JSON string of the signed VoluntaryExit message.
    """
    domain = compute_domain(fork_version, voluntary_exit_domain_type, genesis_validators_root)
    voluntary_exit = spec.VoluntaryExit(
        epoch=spec.Epoch(epoch),
        validator_index=spec.ValidatorIndex(validator_index)
    )
    operation_root = hash_tree_root(voluntary_exit)
    signing_container = SigningContainer(
        root=Bytes32(operation_root),
        domain=Bytes32(domain)
    )
    signing_root = hash_tree_root(signing_container)
    private_key_bytes = bytes.fromhex(private_key_hex[2:])
    signature = bls.Sign(private_key_bytes, signing_root)
    exit_message = {
        "message": {
            "epoch": str(epoch),
            "validator_index": str(validator_index)
        },
        "signature": "0x" + signature.hex()
    }
    return json.dumps(exit_message, separators=(",", ":"))

if __name__ == "__main__":
    # Argument parsing
    parser = argparse.ArgumentParser(description="Generate VoluntaryExit message for Ethereum validator.")
    parser.add_argument("--mnemonic", type=str, help="Mnemonic phrase for deriving the private key.")
    parser.add_argument("--private_key_hex", type=str, help="Private key in hexadecimal format.")
    parser.add_argument("--epoch", type=int, default=None, help="Epoch number. If not provided, current epoch will be calculated.")
    parser.add_argument("--validator_index", type=int, required=True, help="Validator index.")
    args = parser.parse_args()

    GENESIS_TIME = 1695902400  # Holesky genesis time (September 28, 2023)
    SECONDS_PER_SLOT = 12
    SLOTS_PER_EPOCH = 32
    SECONDS_PER_EPOCH = SECONDS_PER_SLOT * SLOTS_PER_EPOCH

    def get_current_epoch():
        """Calculate the current epoch based on Holesky genesis time."""
        current_time = int(time.time())
        elapsed_time = current_time - GENESIS_TIME
        return elapsed_time // SECONDS_PER_EPOCH

    if args.mnemonic:
        # Generate private key from mnemonic (example placeholder)
        seed = hashlib.pbkdf2_hmac("sha512", args.mnemonic.encode("utf-8"), b"mnemonic", 2048, 64)
        private_key_hex = "0x" + seed.hex()[:64]  # Placeholder for derivation logic
    else:
        private_key_hex = args.private_key_hex

    epoch = args.epoch or get_current_epoch()
    genesis_validators_root = "0x9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1"
    fork_version = "0x04017000"
    voluntary_exit_domain_type = "0x04000000"

    exit_message = sign_voluntary_exit(
        private_key_hex, epoch, args.validator_index, fork_version, genesis_validators_root, voluntary_exit_domain_type
    )
    print(exit_message)
