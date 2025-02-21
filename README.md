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
- base58==2.1.1
- ecdsa==0.19.0
- cryptography==44.0.1
- ^ Versions used and confirmed working at time of upload

### Setup
1. Clone the repository:
   git clone https://github.com/R-1-6/BrainWallet.git
   cd BrainWallet
2. Install dependencies:
   pip install ecdsa cryptography base58

## Usage
1. Run the script:
   python brainwallet.py
2. Enter your keyphrases when prompted:
   Enter your keyphrases to generate Bitcoin and Solana wallet keys.
   Enter keyphrase 1: my secret phrase one
   Enter keyphrase 2: another secret phrase two
3. View the generated wallet information:
   Generated Wallet Information:
   ==============================
   Bitcoin Wallet:
   Private Key (hex): a1b2c3d4e5f67890...
   Address: 1ABCxyz...
   Solana Wallet:
   Private Key Seed (hex, 32 bytes): 1234567890abcdef...
   Address: 5tR0nGpUbLiC...
   Phantom Wallet Compatible Private Key (64 bytes):
   Base58: 2a3b4c5d6e7f8g9h...
   Byte Array: [18, 52, 86, 120, ...]
4. To regenerate, run again with the same keyphrases.

### Importing into Wallets
- Bitcoin: Import the private key (hex) into wallets like Electrum (convert to WIF format if needed).
- Solana:
  - Use the 32-byte seed hex for programmatic access.
  - Use the Phantom-compatible base58 or byte array to import into Phantom Wallet:
    - Go to "Add / Connect Wallet" -> "Import Private Key".
    - Paste the base58 string or byte array as prompted.

## How It Works
1. Master Seed: Combines `keyphrase1 + " " + keyphrase2` and derives a 64-byte seed via PBKDF2, using `keyphrase1 + keyphrase2` as the salt.
2. Bitcoin Seed: Derived via HMAC-SHA256 with `keyphrase1` as the key, producing a 32-byte private key.
3. Solana Seed: Derived via HMAC-SHA256 with `keyphrase2` as the key, producing a 32-byte seed for ed25519.
4. Outputs: Generates wallet addresses and private keys, with Solana keys in multiple formats.

## Security Considerations
- Keyphrase Strength: Security depends on the entropy of your keyphrases. Use long, unique phrases (e.g., 20+ random words) for 128+ bits of entropy.
- No Randomness: Unlike BIP39, this is fully deterministic with no added entropy—great for memory, but ensure keyphrases are unguessable.
- Private Key Safety: Never share or expose private keys. Run on a trusted, offline system to avoid leaks.
- Custom Derivation: Uses keyphrases as salt and HMAC keys for uniqueness, deviating from standards but secure if inputs are strong.

## Limitations
- Bitcoin: Generates legacy (P2PKH) addresses only. No SegWit or Taproot support yet.
- Solana: Single keypair, no derivation paths (unlike BIP44).
- Not BIP39: Doesn’t follow standard mnemonic protocols—designed for custom, memory-based use.

## Contributing
Feel free to fork, submit PRs, or open issues for improvements (e.g., SegWit support, additional wallet formats).

## Disclaimer
This is a proof-of-concept tool. Use at your own risk, especially with real funds. Always test with small amounts first and secure your keyphrases.

---
Created with ❤️ by R-1-6
