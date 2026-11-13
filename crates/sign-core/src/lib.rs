//! Private, in-process cryptographic boundary for NEXUS-Q Sign.
//!
//! This crate uses the pinned NEXUS-Q Core cryptographic implementation.
//! It deliberately does not expose Vault sessions, identity records, storage,
//! or any cross-application communication.

mod encrypted_seed;
mod history;
mod identity_service;
mod identity_store;
mod key_store;
mod nqsig;

use nexusq_core::crypto::pq_sign::{MlDsa65KeyPair, MlDsa65VerifyingKey, PqSignError};

pub use encrypted_seed::{EncryptedSeedError, decrypt_seed, encrypt_seed};
pub use history::{HistoryEntry, HistoryError, HistoryStore};
pub use identity_service::{IdentityService, IdentityServiceError};
pub use identity_store::{IdentityRecord, IdentityStore, IdentityStoreError};
pub use key_store::{KeyStore, KeyStoreError};
pub use nqsig::{
    NQSIG_DIGEST_LEN, NQSIG_DOMAIN, NQSIG_HEADER_LEN, NQSIG_ID_LEN, NQSIG_MAGIC,
    NQSIG_MANIFEST_VERSION, NQSIG_MAX_FILE_LEN, NQSIG_ML_DSA_65, NQSIG_PUBLIC_KEY_LEN,
    NQSIG_SHA_256, NQSIG_SIGNATURE_LEN, NQSIG_VERSION, NqsigEnvelope, NqsigError, NqsigManifest,
};

/// Public sizes for the ML-DSA-65 encoding used by NEXUS-Q Core.
pub const ML_DSA_65_PUBLIC_KEY_LEN: usize = 1952;
pub const ML_DSA_65_SECRET_SEED_LEN: usize = 32;
pub const ML_DSA_65_SIGNATURE_LEN: usize = 3309;

/// Errors returned by Sign's narrow crypto adapter.
#[derive(Debug, thiserror::Error)]
pub enum SignCoreError {
    #[error("ML-DSA-65 key generation failed")]
    KeyGeneration(#[source] PqSignError),
    #[error("invalid ML-DSA-65 secret seed")]
    InvalidSecretSeed(#[source] PqSignError),
    #[error("ML-DSA-65 signing failed")]
    Signing(#[source] PqSignError),
    #[error("invalid ML-DSA-65 public key")]
    InvalidPublicKey(#[source] PqSignError),
    #[error("ML-DSA-65 signature verification failed")]
    Verification(#[source] PqSignError),
    #[error("protecting the private signing seed failed")]
    SeedProtection(#[from] EncryptedSeedError),
}

/// In-memory ML-DSA-65 signer. Secret seed export is intentionally not
/// exposed; persistence is available only as authenticated ciphertext.
pub struct DocumentSigner {
    keypair: MlDsa65KeyPair,
}

impl DocumentSigner {
    /// Generate a fresh keypair using the operating-system CSPRNG.
    pub fn generate() -> Result<Self, SignCoreError> {
        let keypair = MlDsa65KeyPair::try_generate().map_err(SignCoreError::KeyGeneration)?;
        Ok(Self { keypair })
    }

    /// Reconstitute a signer from a 32-byte FIPS 204 signing seed.
    /// The caller must supply bytes obtained from Sign's protected store.
    pub fn from_secret_seed(seed: &[u8]) -> Result<Self, SignCoreError> {
        let keypair =
            MlDsa65KeyPair::from_secret_key(seed).map_err(SignCoreError::InvalidSecretSeed)?;
        Ok(Self { keypair })
    }

    /// Return the encoded public key (1952 bytes).
    pub fn public_key(&self) -> Vec<u8> {
        self.keypair.public_key()
    }

    /// Sign the exact message bytes.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignCoreError> {
        self.keypair
            .try_sign(message)
            .map_err(SignCoreError::Signing)
    }

    /// Export the private seed only in an authenticated encrypted envelope.
    /// The plaintext seed is zeroized when this method returns.
    pub fn encrypt_private_seed(&self, password: &[u8]) -> Result<Vec<u8>, SignCoreError> {
        let seed = self.keypair.secret_key();
        Ok(encrypt_seed(&seed, password)?)
    }

    /// Unlock a signer from Sign's encrypted seed envelope.
    pub fn unlock(envelope: &[u8], password: &[u8]) -> Result<Self, SignCoreError> {
        let seed = decrypt_seed(envelope, password)?;
        Self::from_secret_seed(&seed)
    }
}

/// Verify exact message bytes using an encoded ML-DSA-65 public key.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), SignCoreError> {
    let verifier = MlDsa65VerifyingKey::from_public_key(public_key)
        .map_err(SignCoreError::InvalidPublicKey)?;
    verifier
        .verify(message, signature)
        .map_err(SignCoreError::Verification)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_key_signs_and_verifies_exact_message() {
        let signer = DocumentSigner::generate().expect("key generation");
        let public_key = signer.public_key();
        let message = b"NEXUS-Q Sign detached document test vector";
        let signature = signer.sign(message).expect("signing");

        assert_eq!(public_key.len(), ML_DSA_65_PUBLIC_KEY_LEN);
        assert_eq!(signature.len(), ML_DSA_65_SIGNATURE_LEN);
        verify(&public_key, message, &signature).expect("verification");
        assert!(verify(&public_key, b"modified message", &signature).is_err());
    }

    #[test]
    fn nqsig_sidecar_signs_and_verifies_the_canonical_manifest() {
        let signer = DocumentSigner::generate().expect("key generation");
        let manifest = NqsigManifest {
            signature_algorithm: NQSIG_ML_DSA_65,
            digest_algorithm: NQSIG_SHA_256,
            document_digest: [0xA5; NQSIG_DIGEST_LEN],
            identity_id: [0x11; NQSIG_ID_LEN],
            key_id: [0x22; NQSIG_ID_LEN],
            created_at: 1_800_000_000,
        };
        let message = manifest.signing_message().expect("canonical message");
        let signature = signer.sign(&message).expect("sidecar signature");
        let sidecar = NqsigEnvelope {
            manifest,
            public_key: signer.public_key(),
            signature,
        };
        let encoded = sidecar.encode().expect("encode sidecar");
        let decoded = NqsigEnvelope::decode(&encoded).expect("decode sidecar");
        assert_eq!(decoded, sidecar);
        assert_eq!(decoded.encode().expect("re-encode sidecar"), encoded);

        let decoded_message = decoded.manifest.signing_message().expect("decoded message");
        verify(&decoded.public_key, &decoded_message, &decoded.signature)
            .expect("verify sidecar signature");

        // The detached signature authenticates the manifest, including the document digest.
        let mut altered_manifest = decoded.manifest.clone();
        altered_manifest.document_digest[0] ^= 1;
        let altered_message = altered_manifest
            .signing_message()
            .expect("altered manifest remains structurally valid");
        assert!(verify(&decoded.public_key, &altered_message, &decoded.signature).is_err());

        let mut tampered_signature = decoded.signature.clone();
        tampered_signature[0] ^= 1;
        assert!(verify(&decoded.public_key, &decoded_message, &tampered_signature).is_err());
    }

    #[test]
    fn rejects_invalid_key_and_signature_lengths() {
        assert!(verify(&[], b"message", &[]).is_err());

        let signer = DocumentSigner::generate().expect("key generation");
        assert!(verify(&signer.public_key(), b"message", &[]).is_err());
    }

    #[test]
    fn encrypted_seed_roundtrip_restores_same_signing_identity() {
        let original = DocumentSigner::generate().expect("key generation");
        let original_public_key = original.public_key();
        let password = b"correct horse battery staple";
        let envelope = original
            .encrypt_private_seed(password)
            .expect("encrypt seed");
        let restored = DocumentSigner::unlock(&envelope, password).expect("unlock seed");

        assert_eq!(restored.public_key(), original_public_key);
        let message = b"sign after unlocking";
        let signature = restored.sign(message).expect("sign restored key");
        verify(&original_public_key, message, &signature).expect("verify restored signature");
    }

    #[test]
    fn wrong_password_and_tampering_fail_closed() {
        let signer = DocumentSigner::generate().expect("key generation");
        let envelope = signer
            .encrypt_private_seed(b"correct horse battery staple")
            .unwrap();

        assert!(DocumentSigner::unlock(&envelope, b"incorrect password").is_err());

        let mut tampered = envelope;
        let last = tampered.len() - 1;
        tampered[last] ^= 0x80;
        assert!(DocumentSigner::unlock(&tampered, b"correct horse battery staple").is_err());
    }
}
