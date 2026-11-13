//! Password-based authenticated encryption for a single ML-DSA-65 seed.
//! This module does not perform filesystem I/O; atomic persistence is a
//! separate storage concern and must never write plaintext key material.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"NQSK";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const HEADER_LEN: usize = 4 + 1 + SALT_LEN + NONCE_LEN;
const SEED_LEN: usize = 32;
const TAG_LEN: usize = 16;
const ENVELOPE_LEN: usize = HEADER_LEN + SEED_LEN + TAG_LEN;
const MIN_PASSWORD_LEN: usize = 12;
const MAX_PASSWORD_LEN: usize = 1024;
const ARGON2_MEMORY_KIB: u32 = 19 * 1024;
const ARGON2_ITERATIONS: u32 = 2;
const ARGON2_LANES: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum EncryptedSeedError {
    #[error("password must contain at least 12 bytes")]
    PasswordTooShort,
    #[error("password exceeds the 1024-byte input limit")]
    PasswordTooLong,
    #[error("ML-DSA-65 seed must contain exactly 32 bytes")]
    InvalidSeedLength,
    #[error("invalid or unsupported encrypted key envelope")]
    InvalidEnvelope,
    #[error("key could not be unlocked; password may be incorrect or data altered")]
    UnlockFailed,
    #[error("secure random number generation failed")]
    Randomness,
    #[error("key derivation failed")]
    KeyDerivation,
}

fn validate_password(password: &[u8]) -> Result<(), EncryptedSeedError> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err(EncryptedSeedError::PasswordTooShort);
    }
    if password.len() > MAX_PASSWORD_LEN {
        return Err(EncryptedSeedError::PasswordTooLong);
    }
    Ok(())
}

fn derive_key(
    password: &[u8],
    salt: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>, EncryptedSeedError> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_LANES,
        Some(KEY_LEN),
    )
    .map_err(|_| EncryptedSeedError::KeyDerivation)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|_| EncryptedSeedError::KeyDerivation)?;
    Ok(key)
}

/// Encrypt exactly one 32-byte ML-DSA-65 FIPS 204 signing seed.
/// Envelope: magic | version | salt | XChaCha20 nonce | ciphertext+tag.
pub fn encrypt_seed(seed: &[u8], password: &[u8]) -> Result<Vec<u8>, EncryptedSeedError> {
    validate_password(password)?;
    if seed.len() != SEED_LEN {
        return Err(EncryptedSeedError::InvalidSeedLength);
    }

    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut salt).map_err(|_| EncryptedSeedError::Randomness)?;
    getrandom::fill(&mut nonce).map_err(|_| EncryptedSeedError::Randomness)?;

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);

    let key = derive_key(password, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| EncryptedSeedError::KeyDerivation)?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: seed,
                aad: &header,
            },
        )
        .map_err(|_| EncryptedSeedError::UnlockFailed)?;

    let mut envelope = header;
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

/// Decrypt an envelope and return plaintext in a zeroizing container.
pub fn decrypt_seed(
    envelope: &[u8],
    password: &[u8],
) -> Result<Zeroizing<Vec<u8>>, EncryptedSeedError> {
    validate_password(password)?;
    if envelope.len() != ENVELOPE_LEN || &envelope[..4] != MAGIC || envelope[4] != VERSION {
        return Err(EncryptedSeedError::InvalidEnvelope);
    }

    let salt = &envelope[5..5 + SALT_LEN];
    let nonce_start = 5 + SALT_LEN;
    let nonce_end = nonce_start + NONCE_LEN;
    let nonce = &envelope[nonce_start..nonce_end];
    let header = &envelope[..HEADER_LEN];
    let ciphertext = &envelope[HEADER_LEN..];

    let key = derive_key(password, salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| EncryptedSeedError::KeyDerivation)?;
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: header,
            },
        )
        .map_err(|_| EncryptedSeedError::UnlockFailed)?;

    if plaintext.len() != SEED_LEN {
        return Err(EncryptedSeedError::InvalidEnvelope);
    }
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_encrypts_and_decrypts_seed() {
        let seed = [0x42u8; SEED_LEN];
        let password = b"correct horse battery staple";
        let envelope = encrypt_seed(&seed, password).expect("encrypt");
        assert_eq!(envelope.len(), ENVELOPE_LEN);
        assert_ne!(&envelope[HEADER_LEN..], &seed);
        let recovered = decrypt_seed(&envelope, password).expect("decrypt");
        assert_eq!(&recovered[..], &seed);
    }

    #[test]
    fn fresh_envelopes_use_distinct_salts_and_nonces() {
        let seed = [0x24u8; SEED_LEN];
        let password = b"correct horse battery staple";
        let first = encrypt_seed(&seed, password).expect("first");
        let second = encrypt_seed(&seed, password).expect("second");
        assert_ne!(first, second);
    }

    #[test]
    fn rejects_short_password_bad_seed_and_malformed_envelope() {
        assert!(matches!(
            encrypt_seed(&[0u8; SEED_LEN], b"short"),
            Err(EncryptedSeedError::PasswordTooShort)
        ));
        assert!(matches!(
            encrypt_seed(&[0u8; 31], b"correct horse battery staple"),
            Err(EncryptedSeedError::InvalidSeedLength)
        ));
        assert!(matches!(
            encrypt_seed(&[0u8; SEED_LEN], &[b'x'; MAX_PASSWORD_LEN + 1]),
            Err(EncryptedSeedError::PasswordTooLong)
        ));
        assert!(decrypt_seed(b"broken", b"correct horse battery staple").is_err());
    }

    #[test]
    fn wrong_password_fails_authentication() {
        let envelope =
            encrypt_seed(&[0x55; SEED_LEN], b"correct horse battery staple").expect("encrypt");
        assert!(decrypt_seed(&envelope, b"wrong password here").is_err());
    }
}
