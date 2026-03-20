//! Key generation and management for signing ledger entries.
//!
//! Uses Ed25519 for compact, fast digital signatures. The server generates
//! a keypair during setup and uses it to sign every verdict written to ledgers.

use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

use crate::error::LedgerError;

/// A server signing identity backed by an Ed25519 keypair.
#[derive(Debug)]
pub struct ServerKeyPair {
    signing_key: SigningKey,
}

impl ServerKeyPair {
    /// Generate a new random Ed25519 keypair.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Load a keypair from raw 32-byte seed stored on disk.
    pub fn from_seed_file(path: &Path) -> Result<Self, LedgerError> {
        let bytes = std::fs::read(path).map_err(|e| {
            LedgerError::KeyGeneration(format!("failed to read key file {}: {e}", path.display()))
        })?;
        if bytes.len() != 32 {
            return Err(LedgerError::KeyGeneration(format!(
                "key file must be exactly 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        let signing_key = SigningKey::from_bytes(&seed);
        Ok(Self { signing_key })
    }

    /// Save the 32-byte seed to disk for later reloading.
    pub fn save_seed(&self, path: &Path) -> Result<(), LedgerError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, self.signing_key.to_bytes())?;
        Ok(())
    }

    /// Load or generate a keypair. If the file exists, loads from it;
    /// otherwise generates a new keypair and saves it.
    pub fn load_or_generate(path: &Path) -> Result<Self, LedgerError> {
        if path.exists() {
            tracing::info!("Loading server signing key from {}", path.display());
            Self::from_seed_file(path)
        } else {
            tracing::info!("Generating new server signing key at {}", path.display());
            let kp = Self::generate();
            kp.save_seed(path)?;
            Ok(kp)
        }
    }

    /// Sign arbitrary bytes and return the signature.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let sig: Signature = self.signing_key.sign(message);
        sig.to_bytes().to_vec()
    }

    /// Sign bytes and return hex-encoded signature string.
    pub fn sign_hex(&self, message: &[u8]) -> String {
        hex::encode(self.sign(message))
    }

    /// Return the public verifying key as hex.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    /// Return the raw public verifying key bytes.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Verify a signature against this keypair's public key.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), LedgerError> {
        Self::verify_with_public_key(&self.signing_key.verifying_key(), message, signature)
    }

    /// Verify a signature given a public key.
    pub fn verify_with_public_key(
        public_key: &VerifyingKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), LedgerError> {
        let sig_bytes: [u8; 64] = signature.try_into().map_err(|_| {
            LedgerError::Verification("signature must be 64 bytes".into())
        })?;
        let sig = Signature::from_bytes(&sig_bytes);
        public_key
            .verify(message, &sig)
            .map_err(|e| LedgerError::Verification(e.to_string()))
    }

    /// Parse a hex-encoded public key into a VerifyingKey.
    pub fn parse_public_key_hex(hex_str: &str) -> Result<VerifyingKey, LedgerError> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| LedgerError::Verification(format!("invalid hex: {e}")))?;
        let key_bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            LedgerError::Verification("public key must be 32 bytes".into())
        })?;
        VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| LedgerError::Verification(format!("invalid public key: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_sign_verify() {
        let kp = ServerKeyPair::generate();
        let msg = b"verdict: DENY";
        let sig = kp.sign(msg);
        assert!(kp.verify(msg, &sig).is_ok());
    }

    #[test]
    fn tampered_message_fails_verification() {
        let kp = ServerKeyPair::generate();
        let sig = kp.sign(b"original");
        assert!(kp.verify(b"tampered", &sig).is_err());
    }

    #[test]
    fn hex_roundtrip() {
        let kp = ServerKeyPair::generate();
        let msg = b"test message";
        let sig_hex = kp.sign_hex(msg);
        let sig_bytes = hex::decode(&sig_hex).unwrap();
        assert!(kp.verify(msg, &sig_bytes).is_ok());
    }

    #[test]
    fn public_key_hex_roundtrip() {
        let kp = ServerKeyPair::generate();
        let pk_hex = kp.public_key_hex();
        let pk = ServerKeyPair::parse_public_key_hex(&pk_hex).unwrap();
        assert_eq!(pk.to_bytes(), kp.public_key_bytes());
    }

    #[test]
    fn save_and_load_seed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.key");

        let kp1 = ServerKeyPair::generate();
        kp1.save_seed(&path).unwrap();

        let kp2 = ServerKeyPair::from_seed_file(&path).unwrap();
        assert_eq!(kp1.public_key_hex(), kp2.public_key_hex());

        // Signatures from loaded key should verify with original
        let msg = b"persistence test";
        let sig = kp2.sign(msg);
        assert!(kp1.verify(msg, &sig).is_ok());
    }

    #[test]
    fn load_or_generate_creates_new() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys/server.key");

        let kp = ServerKeyPair::load_or_generate(&path).unwrap();
        assert!(path.exists());
        assert!(!kp.public_key_hex().is_empty());
    }

    #[test]
    fn load_or_generate_reuses_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.key");

        let kp1 = ServerKeyPair::load_or_generate(&path).unwrap();
        let kp2 = ServerKeyPair::load_or_generate(&path).unwrap();
        assert_eq!(kp1.public_key_hex(), kp2.public_key_hex());
    }

    #[test]
    fn invalid_seed_file_length() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.key");
        std::fs::write(&path, b"too short").unwrap();
        assert!(ServerKeyPair::from_seed_file(&path).is_err());
    }
}
