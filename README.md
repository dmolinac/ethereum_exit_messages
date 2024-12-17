# Ethereum Validator Exit Message Toolkit

This repository provides a set of Python scripts to generate and validate `VoluntaryExit` messages for Ethereum validators.

## Scripts

### 1. `generate_exit_message.py`

This script generates a signed `VoluntaryExit` message for a specified validator.

#### Usage
```bash
python generate_exit_message.py --mnemonic <mnemonic> --validator_index <validator_index> [--epoch <epoch>] [--private_key_hex <private_key_hex>] [--fork_version <fork_version>] [--genesis_validators_root <genesis_validators_root>]
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
python generate_exit_message.py --mnemonic "poet hurdle cousin either average visual pipe crowd reform alcohol music afraid fee pizza copy divide fish work pipe scout oppose amount creek canoe" --validator_index 1887870
```

### 2. `validate_exit_message.py`

This script validates a `VoluntaryExit` message against the provided parameters.

#### Usage
```bash
python validate_exit_message.py --message <message_json> --validator_index <validator_index> --epoch <epoch> [--fork_version <fork_version>] [--genesis_validators_root <genesis_validators_root>]
```

**Parameters**

- `--message`: The JSON string containing the `VoluntaryExit` message to validate.
- `--validator_index`: The index of the validator. This parameter is mandatory.
- `--epoch`: The epoch at which the exit message is to be validated.
- `--fork_version`: The fork version of the network. Defaults to `0x04017000` (Holesky).
- `--genesis_validators_root`: The genesis validators root of the network. Defaults to the value for Holesky.

#### Example

To validate an exit message:

```bash
python validate_exit_message.py --message '{"message":{"epoch":"95962","validator_index":"1887870"},"signature":"0xa4b2c3d4..."}' --validator_index 1887870 --epoch 95962
```

### Network Defaults

This repository includes default values for the most common Ethereum networks:

- **Holesky**:
  - Fork version: `0x04017000`
  - Genesis validators root: `0x9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1`

- **Mainnet**:
  - Fork version: `0x00000000`
  - Genesis validators root: `0x22c1f297e2614b3eefc721e389d2f29ec82d6c8b3fa09f88da21d9a3eab82eac`

### Contributing

Contributions are welcome! If you encounter any issues, feel free to open an issue or submit a pull request. Ensure your code follows the style guidelines and includes appropriate tests.

### License

This project is licensed under the MIT License.

---
