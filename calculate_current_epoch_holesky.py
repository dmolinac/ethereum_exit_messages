
"""
This script calculates the current Ethereum epoch for the Holesky testnet based 
on its genesis time and slot/epoch parameters.
"""

import time

# Holesky testnet parameters
GENESIS_TIME = 1695902400  # September 28, 2023, 12:00 UTC
SECONDS_PER_SLOT = 12  # Duration of a slot in seconds
SLOTS_PER_EPOCH = 32  # Number of slots per epoch
SECONDS_PER_EPOCH = SECONDS_PER_SLOT * SLOTS_PER_EPOCH  # Duration of an epoch in seconds

def get_current_epoch():
    """
    Calculate the current epoch for the Holesky testnet.

    Returns:
        int: The current epoch number.
    """
    current_time = int(time.time())  # Get the current time in seconds since epoch
    elapsed_time = current_time - GENESIS_TIME  # Time elapsed since the genesis time
    current_epoch = elapsed_time // SECONDS_PER_EPOCH  # Calculate the current epoch
    return current_epoch

if __name__ == "__main__":
    # Calculate and display the current epoch
    epoch = get_current_epoch()
    print(f"Current epoch on Holesky: {epoch}")
