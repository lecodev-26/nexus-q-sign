//! Private filesystem store for encrypted Sign key envelopes.
//!
//! This module persists ciphertext only. It never receives a password or
//! plaintext seed. The caller supplies Sign's application-data directory.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

const ENVELOPE_LEN: u64 = 93;
const MAGIC: &[u8; 4] = b"NQSK";
const VERSION: u8 = 1;
const MAX_TEMP_ATTEMPTS: usize = 8;

#[derive(Debug, thiserror::Error)]
pub enum KeyStoreError {
    #[error("key store directory is unavailable or unsafe")]
    UnsafeDirectory,
    #[error("invalid key identifier")]
    InvalidKeyId,
    #[error("invalid encrypted key envelope")]
    InvalidEnvelope,
    #[error("encrypted key already exists")]
    AlreadyExists,
    #[error("encrypted key was not found")]
    NotFound,
    #[error("encrypted key file is unsafe or malformed")]
    UnsafeFile,
    #[error("secure random number generation failed")]
    Randomness,
    #[error("key storage operation failed")]
    Io(#[source] std::io::Error),
}

/// Stores one authenticated encrypted key envelope per 16-byte key ID.
pub struct KeyStore {
    root: PathBuf,
}

impl KeyStore {
    /// Open/create the store directory. The final directory itself must not
    /// be a symlink and is restricted to owner-only permissions on Unix.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, KeyStoreError> {
        let root = root.as_ref();
        match fs::symlink_metadata(root) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(KeyStoreError::UnsafeDirectory);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(root).map_err(KeyStoreError::Io)?;
            }
            Err(error) => return Err(KeyStoreError::Io(error)),
        }

        let metadata = fs::symlink_metadata(root).map_err(KeyStoreError::Io)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(KeyStoreError::UnsafeDirectory);
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root, fs::Permissions::from_mode(0o700))
                .map_err(KeyStoreError::Io)?;
        }

        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    /// Persist an already encrypted NQSK v1 envelope without replacing data.
    /// A platform no-replace rename gives atomic no-clobber semantics.
    pub fn store(&self, key_id: &[u8; 16], envelope: &[u8]) -> Result<(), KeyStoreError> {
        validate_envelope(envelope)?;
        let destination = self.key_path(key_id);
        match fs::symlink_metadata(&destination) {
            Ok(_) => return Err(KeyStoreError::AlreadyExists),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(KeyStoreError::Io(error)),
        }

        let mut last_error = None;
        for _ in 0..MAX_TEMP_ATTEMPTS {
            let mut random = [0u8; 16];
            getrandom::fill(&mut random).map_err(|_| KeyStoreError::Randomness)?;
            let temp_path =
                self.root
                    .join(format!(".{}.{}.tmp", hex_id(key_id), hex_bytes(&random)));

            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }

            let mut file = match options.open(&temp_path) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(KeyStoreError::Io(error)),
            };

            let write_result = (|| {
                file.write_all(envelope)?;
                file.sync_all()?;
                drop(file);
                commit_noreplace(&temp_path, &destination)?;
                sync_directory(&self.root)?;
                Ok::<(), std::io::Error>(())
            })();

            if let Err(error) = write_result {
                let _ = fs::remove_file(&temp_path);
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    return Err(KeyStoreError::AlreadyExists);
                }
                last_error = Some(error);
                break;
            }
            return Ok(());
        }

        Err(KeyStoreError::Io(last_error.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "temporary filename collision",
            )
        })))
    }

    /// Load ciphertext only. The caller must authenticate/decrypt it separately.
    pub fn load(&self, key_id: &[u8; 16]) -> Result<Vec<u8>, KeyStoreError> {
        let path = self.key_path(key_id);
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                KeyStoreError::NotFound
            } else {
                KeyStoreError::Io(error)
            }
        })?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() != ENVELOPE_LEN
        {
            return Err(KeyStoreError::UnsafeFile);
        }

        let mut file = File::open(&path).map_err(KeyStoreError::Io)?;
        let mut bytes = Vec::with_capacity(ENVELOPE_LEN as usize);
        file.read_to_end(&mut bytes).map_err(KeyStoreError::Io)?;
        validate_envelope(&bytes).map_err(|_| KeyStoreError::UnsafeFile)?;
        Ok(bytes)
    }

    /// Delete an encrypted key file. No recursive or directory deletion occurs.
    pub fn delete(&self, key_id: &[u8; 16]) -> Result<(), KeyStoreError> {
        let path = self.key_path(key_id);
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                KeyStoreError::NotFound
            } else {
                KeyStoreError::Io(error)
            }
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(KeyStoreError::UnsafeFile);
        }
        fs::remove_file(path).map_err(KeyStoreError::Io)?;
        sync_directory(&self.root).map_err(KeyStoreError::Io)
    }

    fn key_path(&self, key_id: &[u8; 16]) -> PathBuf {
        self.root.join(format!("{}.nqsk", hex_id(key_id)))
    }
}

fn validate_envelope(envelope: &[u8]) -> Result<(), KeyStoreError> {
    if envelope.len() as u64 != ENVELOPE_LEN || &envelope[..4] != MAGIC || envelope[4] != VERSION {
        return Err(KeyStoreError::InvalidEnvelope);
    }
    Ok(())
}

fn hex_id(bytes: &[u8; 16]) -> String {
    hex_bytes(bytes)
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

/// Atomically publish a file without replacing an existing destination.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn commit_noreplace(source: &Path, destination: &Path) -> std::io::Result<()> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        source,
        rustix::fs::CWD,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(std::io::Error::from)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn commit_noreplace(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::hard_link(source, destination)?;
    fs::remove_file(source)
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypt_seed;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn test_dir() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "nexus-q-sign-keystore-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn stores_loads_and_deletes_ciphertext() {
        let dir = test_dir();
        let store = KeyStore::open(&dir).expect("open store");
        let key_id = [0x11u8; 16];
        let envelope = encrypt_seed(&[0x22u8; 32], b"correct horse battery staple").unwrap();

        store.store(&key_id, &envelope).expect("store");
        assert_eq!(store.load(&key_id).unwrap(), envelope);
        assert!(matches!(
            store.store(&key_id, &envelope),
            Err(KeyStoreError::AlreadyExists)
        ));
        store.delete(&key_id).expect("delete");
        assert!(matches!(store.load(&key_id), Err(KeyStoreError::NotFound)));

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_symlink_store_directory() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let real = test_dir();
            let alias = test_dir().with_extension("link");
            fs::create_dir_all(&real).unwrap();
            symlink(&real, &alias).unwrap();
            assert!(matches!(
                KeyStore::open(&alias),
                Err(KeyStoreError::UnsafeDirectory)
            ));
            fs::remove_file(alias).unwrap();
            fs::remove_dir_all(real).unwrap();
        }
    }

    #[test]
    fn rejects_invalid_envelope_and_duplicate_key_id() {
        let dir = test_dir();
        let store = KeyStore::open(&dir).unwrap();
        let key_id = [0x33u8; 16];
        assert!(matches!(
            store.store(&key_id, b"not an envelope"),
            Err(KeyStoreError::InvalidEnvelope)
        ));
        let envelope = encrypt_seed(&[0x44u8; 32], b"correct horse battery staple").unwrap();
        store.store(&key_id, &envelope).unwrap();
        assert!(matches!(
            store.store(&key_id, &envelope),
            Err(KeyStoreError::AlreadyExists)
        ));
        fs::remove_dir_all(dir).unwrap();
    }
}
