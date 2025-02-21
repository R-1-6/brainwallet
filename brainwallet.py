import hashlib
import hmac
from ecdsa import SigningKey, SECP256k1
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import base58

def generate_bitcoin_address(private_key_bytes):
    """
    Generate a Bitcoin address from a private key.
    Uses compressed public key and base58check encoding.
    """
    sk = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    vk = sk.get_verifying_key()
    pubkey_bytes = vk.to_string("compressed")
    sha256_hash = hashlib.sha256(pubkey_bytes).digest()
    hash160 = hashlib.new('ripemd160', sha256_hash).digest()
    address_bytes = b'\x00' + hash160
    checksum = hashlib.sha256(hashlib.sha256(address_bytes).digest()).digest()[:4]
    address_bytes += checksum
    bitcoin_address = base58.b58encode(address_bytes).decode('utf-8')
    return bitcoin_address

def main():
    # Prompt for keyphrases
    print("Enter your keyphrases to generate Bitcoin and Solana wallet keys.")
    keyphrase1 = input("Enter keyphrase 1: ")
    keyphrase2 = input("Enter keyphrase 2: ")

    # Concatenate keyphrases with a space for the password
    password = keyphrase1 + " " + keyphrase2
    # Use keyphrase1 + keyphrase2 as the salt
    salt = (keyphrase1 + keyphrase2).encode('utf-8')

    # Generate master seed using PBKDF2 with dynamic salt
    master_seed = hashlib.pbkdf2_hmac(
        'sha512',
        password.encode('utf-8'),
        salt,
        2048,
        64
    )

    # Derive Bitcoin seed using HMAC-SHA256 with keyphrase1 as the key
    bitcoin_hmac = hmac.new(
        keyphrase1.encode('utf-8'),
        master_seed,
        hashlib.sha256
    ).digest()
    bitcoin_private_key = bitcoin_hmac[:32]  # 32 bytes for secp256k1

    # Derive Solana seed using HMAC-SHA256 with keyphrase2 as the key
    solana_hmac = hmac.new(
        keyphrase2.encode('utf-8'),
        master_seed,
        hashlib.sha256
    ).digest()
    solana_seed = solana_hmac[:32]  # 32 bytes for ed25519

    # Generate Bitcoin wallet
    bitcoin_address = generate_bitcoin_address(bitcoin_private_key)

    # Generate Solana wallet
    solana_private_key = Ed25519PrivateKey.from_private_bytes(solana_seed)
    solana_public_key = solana_private_key.public_key()
    solana_pubkey_bytes = solana_public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    solana_address = base58.b58encode(solana_pubkey_bytes).decode('utf-8')

    # Generate Phantom-compatible private key (64 bytes: seed + public key)
    phantom_private_key_bytes = solana_seed + solana_pubkey_bytes
    phantom_private_key_base58 = base58.b58encode(phantom_private_key_bytes).decode('utf-8')
    phantom_private_key_array = [int(byte) for byte in phantom_private_key_bytes]

    # Display results
    print("\nGenerated Wallet Information:")
    print("==============================")
    print("Bitcoin Wallet:")
    print(f"Private Key (hex): {bitcoin_private_key.hex()}")
    print(f"Address: {bitcoin_address}")
    print("\nSolana Wallet:")
    print(f"Private Key Seed (hex, 32 bytes): {solana_seed.hex()}")
    print(f"Address: {solana_address}")
    print("\nPhantom Wallet Compatible Private Key (64 bytes):")
    print(f"Base58: {phantom_private_key_base58}")
    print(f"Byte Array: {phantom_private_key_array}")
    print("\nWARNING: Keep your private keys secure and never share them.")
    print("You can regenerate these wallets using the same keyphrases.")

if __name__ == "__main__":
    main()