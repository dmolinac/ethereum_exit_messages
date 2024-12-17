
"""
This script validates Ethereum VoluntaryExit messages by verifying their 
signatures against the provided public key and domain parameters.
"""

import json
import argparse
from eth2spec.phase0 import spec
from eth2spec.utils.ssz.ssz_typing import Container, Bytes32
from eth2spec.utils.ssz.ssz_impl import hash_tree_root
import milagro_bls_binding as bls  # BLS binding for signature verification
from eth_utils import decode_hex

class SigningContainer(Container):
    """
    Represents a container for signing in Ethereum's VoluntaryExit process.

    Attributes:
        root (Bytes32): The operation root.
        domain (Bytes32): The domain associated with the operation.
    """
    root: Bytes32
    domain: Bytes32

def compute_domain(fork_version, voluntary_exit_domain_type, genesis_validators_root):
    """
    Computes the domain for a VoluntaryExit operation.

    Args:
        fork_version (str): The current fork version in hexadecimal format.
        voluntary_exit_domain_type (str): The domain type in hexadecimal format.
        genesis_validators_root (str): The genesis validators root in hexadecimal format.

    Returns:
        bytes: The computed domain.
    """
    fork_data = spec.ForkData(
        current_version=decode_hex(fork_version),
        genesis_validators_root=decode_hex(genesis_validators_root)
    )
    root = hash_tree_root(fork_data)
    voluntary_exit_domain_type_bytes = decode_hex(voluntary_exit_domain_type)
    domain = voluntary_exit_domain_type_bytes + root[:28]
    return domain

def calculate_signing_root(exit_message, fork_version, genesis_validators_root, voluntary_exit_domain_type):
    """
    Calculates the signing root for a VoluntaryExit operation.

    Args:
        exit_message (dict): The exit message as a dictionary.
        fork_version (str): The current fork version in hexadecimal format.
        genesis_validators_root (str): The genesis validators root in hexadecimal format.
        voluntary_exit_domain_type (str): The domain type in hexadecimal format.

    Returns:
        bytes: The signing root.
    """
    epoch = int(exit_message["message"]["epoch"])
    validator_index = int(exit_message["message"]["validator_index"])
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
    return hash_tree_root(signing_container)

def verify_exit_message(exit_message, public_key_hex, fork_version, genesis_validators_root, voluntary_exit_domain_type):
    """
    Verifies the signature of a VoluntaryExit message.

    Args:
        exit_message (dict): The exit message as a dictionary.
        public_key_hex (str): The public key in hexadecimal format.
        fork_version (str): The current fork version in hexadecimal format.
        genesis_validators_root (str): The genesis validators root in hexadecimal format.
        voluntary_exit_domain_type (str): The domain type in hexadecimal format.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    signing_root = calculate_signing_root(exit_message, fork_version, genesis_validators_root, voluntary_exit_domain_type)
    public_key = bytes.fromhex(public_key_hex[2:])
    signature = bytes.fromhex(exit_message["signature"][2:])
    return bls.Verify(public_key, signing_root, signature)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verify Ethereum VoluntaryExit message signatures.")
    parser.add_argument("--exit_message", type=str, help="Path to a JSON file or a JSON string containing the exit message.")
    parser.add_argument("--public_key_hex", type=str, required=True, help="Validator's public key in hexadecimal format.")
    parser.add_argument("--fork_version", type=str, default="0x04017000", help="Fork version in hexadecimal format.")
    parser.add_argument("--genesis_validators_root", type=str, default="0x9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1", help="Genesis validators root in hexadecimal format.")
    parser.add_argument("--voluntary_exit_domain_type", type=str, default="0x04000000", help="Voluntary exit domain type in hexadecimal format.")

    args = parser.parse_args()

    if args.exit_message.endswith(".json"):
        with open(args.exit_message, "r") as f:
            exit_message = json.load(f)
    else:
        exit_message = json.loads(args.exit_message)

    public_key_hex = args.public_key_hex
    fork_version = args.fork_version
    genesis_validators_root = args.genesis_validators_root
    voluntary_exit_domain_type = args.voluntary_exit_domain_type

    is_valid = verify_exit_message(exit_message, public_key_hex, fork_version, genesis_validators_root, voluntary_exit_domain_type)
    print("Exit message is valid:", is_valid)
