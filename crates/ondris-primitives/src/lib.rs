//! Base types shared across the whole Ondris project: 256-bit hashes,
//! addresses, key pairs and signatures. No homemade cryptographic
//! primitive here: BLAKE3 for hashing, Ed25519 for signatures.

use ed25519_dalek::{Signature as DalekSignature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;

pub const ADDRESS_PREFIX: &str = "ondr";

/// 256-bit hash (BLAKE3 output), used for block hashes, transaction
/// hashes, Merkle roots, etc. Serialized as hex (not as a number array) so
/// the JSON-RPC API stays readable/usable.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash256(pub [u8; 32]);

impl Serialize for Hash256 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Hash256 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Hash256::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

impl Hash256 {
    pub const ZERO: Hash256 = Hash256([0u8; 32]);

    pub fn hash(data: &[u8]) -> Self {
        Hash256(*blake3::hash(data).as_bytes())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Interprets the hash as a big-endian 256-bit integer, for comparison
    /// against the difficulty target.
    pub fn to_u256_be(&self) -> [u8; 32] {
        self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        let mut arr = [0u8; 32];
        if bytes.len() == 32 {
            arr.copy_from_slice(&bytes);
        }
        Ok(Hash256(arr))
    }
}

impl fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash256({})", self.to_hex())
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Ed25519 public key. Serialized as hex, like `Hash256`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(pub [u8; 32]);

impl Serialize for PublicKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        PublicKey::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

impl PublicKey {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> anyhow::Result<Self> {
        let bytes = hex::decode(s)?;
        anyhow::ensure!(bytes.len() == 32, "invalid public key: incorrect length");
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(PublicKey(arr))
    }

    fn verifying_key(&self) -> anyhow::Result<VerifyingKey> {
        Ok(VerifyingKey::from_bytes(&self.0)?)
    }

    /// Derives the address (20 bytes = BLAKE3(pubkey)[..20]) associated with this key.
    pub fn to_address(&self) -> Address {
        let h = blake3::hash(&self.0);
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&h.as_bytes()[..20]);
        Address(addr)
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        match (
            self.verifying_key(),
            DalekSignature::from_slice(&signature.0),
        ) {
            (Ok(vk), Ok(sig)) => vk.verify(message, &sig).is_ok(),
            _ => false,
        }
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.to_hex())
    }
}

/// Ed25519 signature (64 bytes). Serialized by hand as hex: `serde` only
/// derives `Serialize`/`Deserialize` natively for arrays up to 32
/// elements, so [u8; 64] needs a dedicated implementation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature(pub [u8; 64]);

impl Signature {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl serde::Serialize for Signature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> serde::Deserialize<'de> for Signature {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom(
                "invalid signature length (expected 64 bytes)",
            ));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(Signature(arr))
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({}...)", &self.to_hex()[..16])
    }
}

/// Account address: 20 bytes derived from the public key, displayed with
/// the `ondr` prefix + hex (no bech32, to keep things simple and avoid an
/// extra external dependency at this stage).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Address(pub [u8; 20]);

impl Serialize for Address {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl Address {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> anyhow::Result<Self> {
        let bytes = hex::decode(s)?;
        anyhow::ensure!(bytes.len() == 20, "invalid address: incorrect length");
        let mut arr = [0u8; 20];
        arr.copy_from_slice(&bytes);
        Ok(Address(arr))
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", ADDRESS_PREFIX, self.to_hex())
    }
}

impl std::str::FromStr for Address {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let stripped = s.strip_prefix(ADDRESS_PREFIX).unwrap_or(s);
        Address::from_hex(stripped)
    }
}

/// Ed25519 key pair held in memory (unencrypted). Encrypted on-disk
/// storage is handled by `ondris-wallet`, not here.
pub struct KeyPair {
    signing_key: SigningKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let mut seed = [0u8; 32];
        csprng.fill_bytes(&mut seed);
        Self {
            signing_key: SigningKey::from_bytes(&seed),
        }
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&seed),
        }
    }

    pub fn seed_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(self.signing_key.verifying_key().to_bytes())
    }

    pub fn address(&self) -> Address {
        self.public().to_address()
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        let sig = self.signing_key.sign(message);
        Signature(sig.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_deterministic() {
        let a = Hash256::hash(b"ondris");
        let b = Hash256::hash(b"ondris");
        assert_eq!(a, b);
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let kp = KeyPair::generate();
        let msg = b"transfer 10 ONDR";
        let sig = kp.sign(msg);
        assert!(kp.public().verify(msg, &sig));
        assert!(!kp.public().verify(b"transfer 11 ONDR", &sig));
    }

    #[test]
    fn address_roundtrip_through_string() {
        let kp = KeyPair::generate();
        let addr = kp.address();
        let s = addr.to_string();
        let parsed: Address = s.parse().unwrap();
        assert_eq!(addr, parsed);
    }
}
