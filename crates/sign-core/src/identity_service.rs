//! Coordinates public identity metadata and encrypted private-key envelopes.
use std::path::Path;

use crate::{
    DocumentSigner, IdentityRecord, IdentityStore, IdentityStoreError, KeyStore, KeyStoreError,
    SignCoreError,
};

#[derive(Debug, thiserror::Error)]
pub enum IdentityServiceError {
    #[error("identity metadata operation failed")]
    Metadata(#[from] IdentityStoreError),
    #[error("encrypted key operation failed")]
    KeyStorage(#[from] KeyStoreError),
    #[error("identity key material does not match its public record")]
    KeyMismatch,
    #[error("identity creation could not allocate unique identifiers")]
    IdentifierCollision,
    #[error("identity cryptographic operation failed")]
    Crypto(#[from] SignCoreError),
}

/// Owns the two Sign stores and coordinates their lifecycle.
pub struct IdentityService {
    identities: IdentityStore,
    keys: KeyStore,
}

impl IdentityService {
    /// Open stores beneath a trusted, Rust-selected application-data directory.
    /// Callers must never accept this path from the webview.
    pub fn open(app_data_dir: impl AsRef<Path>) -> Result<Self, IdentityServiceError> {
        let root = app_data_dir.as_ref();
        let identities = IdentityStore::open(root.join("identities"))?;
        let keys = KeyStore::open(root.join("keys"))?;
        Ok(Self { identities, keys })
    }

    /// Generate, encrypt and persist one independent ML-DSA-65 identity.
    /// The password is consumed only in Rust and is never persisted.
    pub fn create(
        &self,
        display_name: String,
        password: &[u8],
    ) -> Result<IdentityRecord, IdentityServiceError> {
        let signer = DocumentSigner::generate()?;
        let envelope = signer.encrypt_private_seed(password)?;
        let public_key = signer.public_key();

        for _ in 0..4 {
            let (identity_id, key_id) = IdentityRecord::generate_ids()?;
            let record = IdentityRecord::now_untrusted(
                identity_id,
                key_id,
                display_name.clone(),
                public_key.clone(),
            )?;

            match self.keys.store(&key_id, &envelope) {
                Ok(()) => {}
                Err(KeyStoreError::AlreadyExists) => continue,
                Err(error) => return Err(error.into()),
            }

            match self.identities.store(&record) {
                Ok(()) => return Ok(record),
                Err(error) => {
                    // A directory-sync error can occur after the atomic no-replace
                    // commit. Keep the key if the public record is already visible.
                    let committed = self.identities.load(&identity_id).is_ok();
                    if !committed {
                        let _ = self.keys.delete(&key_id);
                    }
                    return Err(error.into());
                }
            }
        }
        Err(IdentityServiceError::IdentifierCollision)
    }

    /// List public records and fail closed if any referenced key envelope is absent.
    pub fn list(&self) -> Result<Vec<IdentityRecord>, IdentityServiceError> {
        let records = self.identities.list()?;
        for record in &records {
            self.keys.load(&record.key_id)?;
        }
        Ok(records)
    }

    /// Unlock only after checking that the decrypted key matches the stored public key.
    pub fn unlock(
        &self,
        identity_id: &[u8; 16],
        password: &[u8],
    ) -> Result<DocumentSigner, IdentityServiceError> {
        let record = self.identities.load(identity_id)?;
        let envelope = self.keys.load(&record.key_id)?;
        let signer = DocumentSigner::unlock(&envelope, password)?;
        if signer.public_key() != record.public_key {
            return Err(IdentityServiceError::KeyMismatch);
        }
        Ok(signer)
    }

    /// Remove the public record first, then its encrypted key envelope.
    /// A failure deleting the key leaves an orphan ciphertext, never a visible
    /// identity that silently points to a missing key.
    pub fn delete(&self, identity_id: &[u8; 16]) -> Result<(), IdentityServiceError> {
        let record = self.identities.load(identity_id)?;
        self.identities.delete(identity_id)?;
        match self.keys.delete(&record.key_id) {
            Ok(()) | Err(KeyStoreError::NotFound) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn temp() -> PathBuf {
        std::env::temp_dir().join(format!(
            "nqs-identity-service-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn creates_lists_unlocks_and_deletes_an_independent_identity() {
        let dir = temp();
        let service = IdentityService::open(&dir).unwrap();
        let password = b"a sufficiently long password";
        let record = service.create("Personal".into(), password).unwrap();
        assert_eq!(service.list().unwrap(), vec![record.clone()]);

        let signer = service.unlock(&record.identity_id, password).unwrap();
        let message = b"identity service integration";
        let signature = signer.sign(message).unwrap();
        crate::verify(&record.public_key, message, &signature).unwrap();

        assert!(
            service
                .unlock(&record.identity_id, b"wrong password")
                .is_err()
        );
        service.delete(&record.identity_id).unwrap();
        assert!(matches!(
            service.identities.load(&record.identity_id),
            Err(IdentityStoreError::NotFound)
        ));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn invalid_password_policy_does_not_leave_partial_identity() {
        let dir = temp();
        let service = IdentityService::open(&dir).unwrap();
        assert!(service.create("Personal".into(), b"short").is_err());
        assert!(service.list().unwrap().is_empty());
        fs::remove_dir_all(dir).unwrap();
    }
}
