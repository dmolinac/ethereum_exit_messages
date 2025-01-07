# Ethereum Validator Exit Message Toolkit

This repository provides a set of Python scripts to generate and validate `VoluntaryExit` messages for Ethereum validators.

The scripts have been developed as part of a research project within the [Department of Information and Communications Engineering](https://deic.uab.cat/) of the [Universitat Autònoma de Barcelona](https://www.uab.cat/).

## Scripts

### 1. `generate_exit_message_holesky.py`

This script generates a signed `VoluntaryExit` message for a specified validator in Holesky.

#### Usage
```bash
python generate_exit_message_holesky.py --mnemonic <mnemonic> --validator_index <validator_index> [--epoch <epoch>] [--private_key_hex <private_key_hex>] [--fork_version <fork_version>] [--genesis_validators_root <genesis_validators_root>]
```

**Parameters**

- `--mnemonic`: The BIP-39 mnemonic for the validator. Either this or `--private_key_hex` must be provided.
- `--private_key_hex`: The validator's private key in hexadecimal format. Either this or `--mnemonic` must be provided.
- `--validator_index`: The index of the validator. This parameter is mandatory.
- `--epoch`: The epoch at which the exit message is to be generated. If not provided, the script calculates the current epoch.
- `--fork_version`: The fork version of the network. Defaults to `0x04017000` (Holesky).
- `--genesis_validators_root`: The genesis validators root of the network. Defaults to the value for Holesky.

#### Example

To generate an exit message for a validator using its mnemonic:

```bash
python generate_exit_message.py --mnemonic "average visual pipe crowd reform alcohol music afraid fee pizza copy divide fish poet hurdle cousin either work pipe scout oppose amount creek canoe" --validator_index 1845650
```

### 2. `validate_exit_message_holesky.py`

This script validates a `VoluntaryExit` message against the provided parameters.

#### Usage
```bash
python validate_exit_message_holesky.py --message <message_json> --validator_index <validator_index> --epoch <epoch> [--fork_version <fork_version>] [--genesis_validators_root <genesis_validators_root>]
```

**Parameters**

- `--exit_message` (Mandatory): Path to a JSON file or a JSON string containing the `VoluntaryExit` message to validate.
- `--public_key_hex` (Mandatory): Validator's public key in hexadecimal format.
- `--fork_version` (Optional): The fork version of the network. Defaults to `0x04017000` (Holesky).
- `--genesis_validators_root` (Optional): The genesis validators root of the network. Defaults to the value "0x9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1" for Holesky.
- `--voluntary_exit_domain_type` (Optional): Voluntary exit domain type in hexadecimal format. Defaults to the value "0x04000000" for Holesky.

#### Example

To validate an exit message:

```bash
python validate_exit_message.py --exit_message '{"message":{"epoch":"95362","validator_index":"1845650"},"signature":"0xa4b2c3d4..."}' --public_key_hex 0x1234...
```

### 3. `calculate_current_epoch_holesky.py`
This script calculates the current epoch for the Ethereum **Holesky testnet** based on the genesis time and the slot duration.

#### Usage
```bash
python calculate_current_epoch_holesky.py
```

**Output**
Displays the current epoch number on the Holesky testnet.

#### Example
```bash
python calculate_current_epoch_holesky.py
```
Output:
```
Current epoch on Holesky: 95362
```


### 4.  `generate_ethereum_public_key_from_private_key.py`
This script generates an Ethereum **public key** from a given private key. It also compresses the public key using the **SHA-384** hashing algorithm for a compact representation.

#### Usage
The private key is defined directly in the script:
```python
private_key_hex = "0x5c012ef45dc6549ae3baf514ebc465c07c558a5f1e76bf6adda8cf92454b102d"
```

Run the script:
```bash
python generate_ethereum_public_key_from_private_key.py
```

**Output**
Displays the compressed public key (96 characters):
```
Public Key (96 chars): <compressed_public_key>
```

### 5.  `derive_ethereum_private_key_from_mnemonic.py`
This script derives an Ethereum **private key** from a given **mnemonic phrase** using the **BLS12-381** key derivation standard and a hierarchical derivation path.

#### Usage
The mnemonic and derivation path are defined directly in the script:
```python
mnemonic = "poet hurdle cousin either average visual pipe crowd reform alcohol music afraid fee ..."
path = "m/12381/3600/0/0/0"
```

Run the script:
```bash
python derive_ethereum_private_key_from_mnemonic.py
```

**Output**
Displays the derived private key in hexadecimal format:
```
Private Key (Hex): <derived_private_key>
```


### Network Defaults

This repository includes default values for the most common Ethereum networks:

- **Holesky**:
  - Fork version: `0x04017000`
  - Genesis validators root: `0x9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1`

- **Mainnet (work in progress)**:
  - Fork version: `0x00000000`
  - Genesis validators root: `0x22c1f297e2614b3eefc721e389d2f29ec82d6c8b3fa09f88da21d9a3eab82eac`

### Installation

To install the required Python dependencies for the scripts, ensure you have `pip` installed. Then, run the following command:

```bash
pip install -r requirements.txt
```

This will install all the necessary libraries, including:

- `eth2spec`: For simulating and working with the Ethereum 2.0 specification, including SSZ serialization and validation processes.
- `eth-keys`: For working with Ethereum keys.
- `milagro-bls-binding`: For BLS cryptographic operations.
- `mnemonic`: For generating and validating BIP-39 mnemonics.
- `setuptools`: For packaging and distributing Python projects, ensuring dependencies are properly handled and installed.

Make sure you are using a Python version compatible with these dependencies (recommended: Python 3.8 or higher).

### Contributing

Contributions are welcome! If you encounter any issues, feel free to open an issue or submit a pull request. Ensure your code follows the style guidelines and includes appropriate tests.

### License

This project is licensed under the MIT License.

---
