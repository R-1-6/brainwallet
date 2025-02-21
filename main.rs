use base58::ToBase58;              // For converting bytes to base58 strings
use console::Term;                 // For reading input and writing output
use digest::Digest;                // Trait for hash functions like SHA-256 and RIPEMD-160
use ed25519_dalek::SigningKey as Ed25519SecretKey;  // Ed25519 private key
use hex;                           // For encoding bytes as hex strings
use hmac::{Hmac, Mac};             // For HMAC-SHA256
use pbkdf2::pbkdf2_hmac;           // For PBKDF2 with HMAC-SHA512
use ripemd::Ripemd160;             // RIPEMD-160 hash function
use secp256k1::{PublicKey, Secp256k1, SecretKey};  // SECP256k1 key generation
use sha2::{Sha256, Sha512};        // SHA-256 and SHA-512 hash functions
use std::error::Error;             // For error handling

/// Generates a Bitcoin address from a private key using compressed public key and base58check encoding.
fn generate_bitcoin_address(private_key: &[u8]) -> String {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(private_key).expect("Invalid private key");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let compressed_pubkey = public_key.serialize();  // Compressed public key (33 bytes)

    let mut sha256 = Sha256::new();
    sha256.update(&compressed_pubkey);
    let sha256_result = sha256.finalize();

    let mut ripemd = Ripemd160::new();
    ripemd.update(&sha256_result);
    let hash160 = ripemd.finalize();

    let mut address_bytes = vec![0x00];  // Version byte for mainnet
    address_bytes.extend_from_slice(&hash160);

    let mut sha256_1 = Sha256::new();
    sha256_1.update(&address_bytes);
    let sha256_1_result = sha256_1.finalize();
    let mut sha256_2 = Sha256::new();
    sha256_2.update(&sha256_1_result);
    let checksum = &sha256_2.finalize()[..4];  // First 4 bytes of double SHA-256

    address_bytes.extend_from_slice(checksum);
    address_bytes.to_base58()  // Convert to base58 string
}

fn main() -> Result<(), Box<dyn Error>> {
    let term = Term::stdout();
    term.write_line("Enter your keyphrases to generate Bitcoin and Solana wallet keys.")?;

    term.write_line("Enter keyphrase 1: ")?;
    let keyphrase1 = term.read_line()?;
    term.write_line("Enter keyphrase 2: ")?;
    let keyphrase2 = term.read_line()?;

    // Concatenate keyphrases with a space for the password
    let password = format!("{} {}", keyphrase1, keyphrase2);
    // Use keyphrase1 + keyphrase2 as the salt
    let salt = format!("{}{}", keyphrase1, keyphrase2);

    // Generate master seed using PBKDF2 with SHA-512
    let mut master_seed = [0u8; 64];
    pbkdf2_hmac::<Sha512>(password.as_bytes(), salt.as_bytes(), 2048, &mut master_seed);

    // Derive Bitcoin seed using HMAC-SHA256 with keyphrase1 as the key
    let mut bitcoin_hmac = Hmac::<Sha256>::new_from_slice(keyphrase1.as_bytes())?;
    bitcoin_hmac.update(&master_seed);
    let bitcoin_seed = bitcoin_hmac.finalize().into_bytes();
    let bitcoin_private_key = &bitcoin_seed[..32];  // 32 bytes for secp256k1

    // Derive Solana seed using HMAC-SHA256 with keyphrase2 as the key
    let mut solana_hmac = Hmac::<Sha256>::new_from_slice(keyphrase2.as_bytes())?;
    solana_hmac.update(&master_seed);
    let solana_seed = solana_hmac.finalize().into_bytes();
    let mut solana_private_key = [0u8; 32];
    solana_private_key.copy_from_slice(&solana_seed[..32]);  // 32 bytes for ed25519

    // Generate Bitcoin wallet
    let bitcoin_address = generate_bitcoin_address(bitcoin_private_key);

    // Generate Solana wallet
    let ed25519_secret = Ed25519SecretKey::from_bytes(&solana_private_key); // No `?` needed
    let ed25519_public = ed25519_secret.verifying_key();
    let solana_address = ed25519_public.to_bytes().to_base58();

    // Generate Phantom-compatible private key (64 bytes: seed + public key)
    let mut phantom_private_key_bytes = Vec::with_capacity(64);
    phantom_private_key_bytes.extend_from_slice(&solana_private_key);
    phantom_private_key_bytes.extend_from_slice(&ed25519_public.to_bytes());
    let phantom_private_key_base58 = phantom_private_key_bytes.to_base58();
    let phantom_private_key_array: Vec<u8> = phantom_private_key_bytes;

    // Display results
    term.write_line("\nGenerated Wallet Information:")?;
    term.write_line("==============================")?;
    term.write_line("Bitcoin Wallet:")?;
    term.write_line(&format!("Private Key (hex): {}", hex::encode(bitcoin_private_key)))?;
    term.write_line(&format!("Address: {}", bitcoin_address))?;
    term.write_line("\nSolana Wallet:")?;
    term.write_line(&format!("Private Key Seed (hex, 32 bytes): {}", hex::encode(solana_private_key)))?;
    term.write_line(&format!("Address: {}", solana_address))?;
    term.write_line("\nPhantom Wallet Compatible Private Key (64 bytes):")?;
    term.write_line(&format!("Base58: {}", phantom_private_key_base58))?;
    term.write_line(&format!("Byte Array: {:?}", phantom_private_key_array))?;
    term.write_line("\nWARNING: Keep your private keys secure and never share them.")?;
    term.write_line("You can regenerate these wallets using the same keyphrases.")?;

    Ok(())
}