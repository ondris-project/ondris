//! Encrypted on-disk keystore: the Ed25519 seed (32 bytes) is encrypted
//! with AES-256-GCM, whose key is derived from the password via Argon2id.
//! Nothing is ever written in plaintext except the public key and address
//! (not sensitive).

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use ondris_primitives::KeyPair;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Serialize, Deserialize)]
pub struct Keystore {
    pub public_key: String,
    pub address: String,
    salt: String,
    nonce: String,
    ciphertext: String,
}

fn derive_key(password: &str, salt: &[u8]) -> anyhow::Result<[u8; 32]> {
    let mut key = [0u8; 32];
    argon2::Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("key derivation failed: {e:?}"))?;
    Ok(key)
}

pub fn create(password: &str) -> anyhow::Result<(Keystore, KeyPair)> {
    let keypair = KeyPair::generate();
    let seed = keypair.seed_bytes();

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let key = derive_key(password, &salt)?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| anyhow::anyhow!("invalid key: {e:?}"))?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), seed.as_ref())
        .map_err(|e| anyhow::anyhow!("encryption failed: {e:?}"))?;

    let ks = Keystore {
        public_key: keypair.public().to_hex(),
        address: keypair.address().to_string(),
        salt: hex::encode(salt),
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
    };
    Ok((ks, keypair))
}

pub fn unlock(ks: &Keystore, password: &str) -> anyhow::Result<KeyPair> {
    let salt = hex::decode(&ks.salt)?;
    let key = derive_key(password, &salt)?;
    let nonce_bytes = hex::decode(&ks.nonce)?;
    let ciphertext = hex::decode(&ks.ciphertext)?;

    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| anyhow::anyhow!("invalid key: {e:?}"))?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref())
        .map_err(|_| anyhow::anyhow!("incorrect password or corrupted wallet file"))?;

    anyhow::ensure!(plaintext.len() == 32, "decrypted seed has unexpected size");
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&plaintext);
    Ok(KeyPair::from_seed(seed))
}

pub fn load(path: &Path) -> anyhow::Result<Keystore> {
    let data = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&data)?)
}

pub fn save(path: &Path, ks: &Keystore) -> anyhow::Result<()> {
    std::fs::write(path, serde_json::to_string_pretty(ks)?)?;
    Ok(())
}
