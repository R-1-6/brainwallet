# BrainWallet

BrainWallet is a Python script that generates private keys and addresses for Bitcoin and Solana wallets using two user-defined keyphrases. By remembering these keyphrases, you can regenerate your wallet keys anytime without storing seed phrases or private keys externally. Designed for simplicity and memory-based access, it also supports Solana private keys in a format compatible with Phantom Wallet.

It can be run offline, it's just as safe as tradtional wallet generation methods as long as your rememberable keyphrases are secure (lengthy) enough.

## Features
- **Bitcoin Wallet**: Generates a private key (secp256k1) and legacy P2PKH address.
- **Solana Wallet**: Generates a private key (ed25519) and address, with dual outputs:
  - 32-byte seed in hex.
  - 64-byte Phantom Wallet-compatible key (base58 and byte array formats).
- **Deterministic**: Same keyphrases always produce the same wallet keys.
- **Custom Derivation**: Uses PBKDF2 and HMAC-SHA256 with keyphrases as salt and HMAC keys for enhanced uniqueness.

## Installation

### Prerequisites
- Python 3.6+
- Required libraries: `ecdsa`, `cryptography`, `base58`

### Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/R-1-6/BrainWallet.git
   cd BrainWallet
   python brainwallet.py
