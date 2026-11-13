//! Versioned, public-only identity metadata storage for NEXUS-Q Sign.
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::ML_DSA_65_PUBLIC_KEY_LEN;

const MAGIC: &[u8; 4] = b"NQID";
const VERSION: u8 = 1;
const FIXED_LEN: usize = 4 + 1 + 16 + 16 + 8 + 2 + ML_DSA_65_PUBLIC_KEY_LEN;
const MAX_NAME_LEN: usize = 128;
const MAX_TEMP_ATTEMPTS: usize = 8;

#[derive(Debug, thiserror::Error)]
pub enum IdentityStoreError {
    #[error("identity store directory is unavailable or unsafe")]
    UnsafeDirectory,
    #[error("identity metadata is invalid or unsupported")]
    InvalidRecord,
    #[error("identity already exists")]
    AlreadyExists,
    #[error("identity was not found")]
    NotFound,
    #[error("identity metadata file is unsafe or malformed")]
    UnsafeFile,
    #[error("secure random number generation failed")]
    Randomness,
    #[error("identity storage operation failed")]
    Io(#[source] std::io::Error),
}

/// Public metadata only. The private key is held in a separate encrypted file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityRecord {
    pub identity_id: [u8; 16],
    pub key_id: [u8; 16],
    pub display_name: String,
    pub public_key: Vec<u8>,
    /// Informational Unix seconds from the local system clock, not trusted time.
    pub created_at: u64,
}

impl IdentityRecord {
    pub fn new(
        identity_id: [u8; 16],
        key_id: [u8; 16],
        display_name: String,
        public_key: Vec<u8>,
        created_at: u64,
    ) -> Result<Self, IdentityStoreError> {
        let record = Self {
            identity_id,
            key_id,
            display_name,
            public_key,
            created_at,
        };
        validate_record(&record)?;
        Ok(record)
    }

    /// Create random, independent identity and key identifiers.
    pub fn generate_ids() -> Result<([u8; 16], [u8; 16]), IdentityStoreError> {
        let mut identity_id = [0u8; 16];
        let mut key_id = [0u8; 16];
        getrandom::fill(&mut identity_id).map_err(|_| IdentityStoreError::Randomness)?;
        getrandom::fill(&mut key_id).map_err(|_| IdentityStoreError::Randomness)?;
        Ok((identity_id, key_id))
    }

    pub fn now_untrusted(
        identity_id: [u8; 16],
        key_id: [u8; 16],
        display_name: String,
        public_key: Vec<u8>,
    ) -> Result<Self, IdentityStoreError> {
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| IdentityStoreError::InvalidRecord)?
            .as_secs();
        Self::new(identity_id, key_id, display_name, public_key, created_at)
    }
}

/// Stores versioned public metadata records as individual .nqi files.
pub struct IdentityStore {
    root: PathBuf,
}

impl IdentityStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, IdentityStoreError> {
        let root = root.as_ref();
        match fs::symlink_metadata(root) {
            Ok(m) if m.file_type().is_symlink() || !m.is_dir() => {
                return Err(IdentityStoreError::UnsafeDirectory);
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(root).map_err(IdentityStoreError::Io)?
            }
            Err(e) => return Err(IdentityStoreError::Io(e)),
        }
        let m = fs::symlink_metadata(root).map_err(IdentityStoreError::Io)?;
        if m.file_type().is_symlink() || !m.is_dir() {
            return Err(IdentityStoreError::UnsafeDirectory);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root, fs::Permissions::from_mode(0o700))
                .map_err(IdentityStoreError::Io)?;
        }
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    /// Add a new record without replacing an existing identity ID.
    pub fn store(&self, record: &IdentityRecord) -> Result<(), IdentityStoreError> {
        validate_record(record)?;
        let bytes = encode(record)?;
        let destination = self.path(&record.identity_id);
        match fs::symlink_metadata(&destination) {
            Ok(_) => return Err(IdentityStoreError::AlreadyExists),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(IdentityStoreError::Io(e)),
        }
        for _ in 0..MAX_TEMP_ATTEMPTS {
            let mut random = [0u8; 8];
            getrandom::fill(&mut random).map_err(|_| IdentityStoreError::Randomness)?;
            let temp = self.root.join(format!(
                ".{}.{}.tmp",
                hex(&record.identity_id),
                hex(&random)
            ));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = match options.open(&temp) {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(IdentityStoreError::Io(e)),
            };
            let result = (|| {
                file.write_all(&bytes)?;
                file.sync_all()?;
                drop(file);
                commit_noreplace(&temp, &destination)?;
                sync_dir(&self.root)?;
                Ok::<(), std::io::Error>(())
            })();
            if let Err(e) = result {
                let _ = fs::remove_file(&temp);
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    return Err(IdentityStoreError::AlreadyExists);
                }
                return Err(IdentityStoreError::Io(e));
            }
            return Ok(());
        }
        Err(IdentityStoreError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "temporary filename collision",
        )))
    }

    pub fn load(&self, identity_id: &[u8; 16]) -> Result<IdentityRecord, IdentityStoreError> {
        let path = self.path(identity_id);
        let meta = fs::symlink_metadata(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                IdentityStoreError::NotFound
            } else {
                IdentityStoreError::Io(e)
            }
        })?;
        if meta.file_type().is_symlink()
            || !meta.is_file()
            || meta.len() as usize > FIXED_LEN + MAX_NAME_LEN
        {
            return Err(IdentityStoreError::UnsafeFile);
        }
        let mut file = File::open(path).map_err(IdentityStoreError::Io)?;
        let mut bytes = Vec::with_capacity(meta.len() as usize);
        file.read_to_end(&mut bytes)
            .map_err(IdentityStoreError::Io)?;
        decode(&bytes).map_err(|_| IdentityStoreError::UnsafeFile)
    }

    /// Delete one public identity record without touching key material.
    pub fn delete(&self, identity_id: &[u8; 16]) -> Result<(), IdentityStoreError> {
        let path = self.path(identity_id);
        let meta = fs::symlink_metadata(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                IdentityStoreError::NotFound
            } else {
                IdentityStoreError::Io(e)
            }
        })?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err(IdentityStoreError::UnsafeFile);
        }
        fs::remove_file(path).map_err(IdentityStoreError::Io)?;
        sync_dir(&self.root).map_err(IdentityStoreError::Io)
    }

    pub fn list(&self) -> Result<Vec<IdentityRecord>, IdentityStoreError> {
        let mut records = Vec::new();
        for entry in fs::read_dir(&self.root).map_err(IdentityStoreError::Io)? {
            let entry = entry.map_err(IdentityStoreError::Io)?;
            let path = entry.path();
            if path.extension().and_then(|x| x.to_str()) != Some("nqi") {
                continue;
            }
            let meta = fs::symlink_metadata(&path).map_err(IdentityStoreError::Io)?;
            if meta.file_type().is_symlink() || !meta.is_file() {
                return Err(IdentityStoreError::UnsafeFile);
            }
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .ok_or(IdentityStoreError::UnsafeFile)?;
            if stem.len() != 32 {
                return Err(IdentityStoreError::UnsafeFile);
            }
            let id = parse_hex_id(stem).ok_or(IdentityStoreError::UnsafeFile)?;
            let record = self.load(&id)?;
            if record.identity_id != id {
                return Err(IdentityStoreError::UnsafeFile);
            }
            records.push(record);
        }
        records.sort_by_key(|r| r.identity_id);
        Ok(records)
    }

    fn path(&self, id: &[u8; 16]) -> PathBuf {
        self.root.join(format!("{}.nqi", hex(id)))
    }
}

fn validate_record(r: &IdentityRecord) -> Result<(), IdentityStoreError> {
    let name = r.display_name.trim();
    if name.is_empty()
        || r.display_name.len() > MAX_NAME_LEN
        || r.display_name.chars().any(char::is_control)
        || r.public_key.len() != ML_DSA_65_PUBLIC_KEY_LEN
    {
        return Err(IdentityStoreError::InvalidRecord);
    }
    Ok(())
}

fn encode(r: &IdentityRecord) -> Result<Vec<u8>, IdentityStoreError> {
    validate_record(r)?;
    let name = r.display_name.as_bytes();
    let mut out = Vec::with_capacity(FIXED_LEN + name.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&r.identity_id);
    out.extend_from_slice(&r.key_id);
    out.extend_from_slice(&r.created_at.to_be_bytes());
    out.extend_from_slice(&(name.len() as u16).to_be_bytes());
    out.extend_from_slice(&r.public_key);
    out.extend_from_slice(name);
    Ok(out)
}

fn decode(bytes: &[u8]) -> Result<IdentityRecord, IdentityStoreError> {
    if bytes.len() < FIXED_LEN
        || bytes.len() > FIXED_LEN + MAX_NAME_LEN
        || &bytes[..4] != MAGIC
        || bytes[4] != VERSION
    {
        return Err(IdentityStoreError::InvalidRecord);
    }
    let mut p = 5;
    let mut identity_id = [0u8; 16];
    identity_id.copy_from_slice(&bytes[p..p + 16]);
    p += 16;
    let mut key_id = [0u8; 16];
    key_id.copy_from_slice(&bytes[p..p + 16]);
    p += 16;
    let created_at = u64::from_be_bytes(
        bytes[p..p + 8]
            .try_into()
            .map_err(|_| IdentityStoreError::InvalidRecord)?,
    );
    p += 8;
    let name_len = u16::from_be_bytes(
        bytes[p..p + 2]
            .try_into()
            .map_err(|_| IdentityStoreError::InvalidRecord)?,
    ) as usize;
    p += 2;
    if name_len == 0 || name_len > MAX_NAME_LEN || bytes.len() != FIXED_LEN + name_len {
        return Err(IdentityStoreError::InvalidRecord);
    }
    let public_key = bytes[p..p + ML_DSA_65_PUBLIC_KEY_LEN].to_vec();
    p += ML_DSA_65_PUBLIC_KEY_LEN;
    let display_name = std::str::from_utf8(&bytes[p..])
        .map_err(|_| IdentityStoreError::InvalidRecord)?
        .to_owned();
    IdentityRecord::new(identity_id, key_id, display_name, public_key, created_at)
}

fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char);
    }
    s
}
fn parse_hex_id(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, pair) in s.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let digit = |b: u8| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        };
        out[i] = (digit(pair[0])? << 4) | digit(pair[1])?;
    }
    Some(out)
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

fn sync_dir(path: &Path) -> std::io::Result<()> {
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
    use std::time::{SystemTime, UNIX_EPOCH};
    fn temp() -> PathBuf {
        std::env::temp_dir().join(format!(
            "nqs-identities-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }
    fn record() -> IdentityRecord {
        IdentityRecord::new(
            [1; 16],
            [2; 16],
            "Personal signing key".into(),
            vec![7; ML_DSA_65_PUBLIC_KEY_LEN],
            1_800_000_000,
        )
        .unwrap()
    }
    #[test]
    fn persists_and_lists_public_metadata_only() {
        let dir = temp();
        let store = IdentityStore::open(&dir).unwrap();
        let r = record();
        store.store(&r).unwrap();
        assert_eq!(store.load(&r.identity_id).unwrap(), r);
        assert_eq!(store.list().unwrap(), vec![r.clone()]);
        assert!(matches!(
            store.store(&r),
            Err(IdentityStoreError::AlreadyExists)
        ));
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn rejects_bad_names_and_public_key_lengths() {
        assert!(
            IdentityRecord::new(
                [1; 16],
                [2; 16],
                "  ".into(),
                vec![0; ML_DSA_65_PUBLIC_KEY_LEN],
                1
            )
            .is_err()
        );
        assert!(IdentityRecord::new([1; 16], [2; 16], "valid".into(), vec![0; 3], 1).is_err());
    }
    #[test]
    fn rejects_corrupt_and_noncanonical_metadata() {
        let mut bytes = encode(&record()).unwrap();
        bytes[4] = 9;
        assert!(decode(&bytes).is_err());
        let mut bytes = encode(&record()).unwrap();
        bytes.push(0);
        assert!(decode(&bytes).is_err());
    }
}
