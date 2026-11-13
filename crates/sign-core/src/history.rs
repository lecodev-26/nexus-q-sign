//! Local SQLite operation history. Stores metadata only; never document bytes or secrets.
use rusqlite::{Connection, OpenFlags, params};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_ENTRIES: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    pub id: i64,
    pub created_at: u64,
    pub operation: String,
    pub document_name: String,
    pub document_sha256: Option<[u8; 32]>,
    pub identity_id: Option<[u8; 16]>,
    pub status: String,
}

#[derive(Debug, thiserror::Error)]
pub enum HistoryError {
    #[error("history database error")]
    Database(#[from] rusqlite::Error),
    #[error("invalid history entry")]
    InvalidEntry,
    #[error("system clock is before Unix epoch")]
    Clock,
}

/// SQLite-backed history owned exclusively by NEXUS-Q Sign.
pub struct HistoryStore {
    connection: Connection,
}

impl HistoryStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, HistoryError> {
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "secure_delete", "ON")?;
        connection.execute_batch(
            "PRAGMA foreign_keys=ON;
             CREATE TABLE IF NOT EXISTS sign_history (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               created_at INTEGER NOT NULL,
               operation TEXT NOT NULL CHECK(operation IN ('sign','verify')),
               document_name TEXT NOT NULL,
               document_sha256 BLOB,
               identity_id BLOB,
               status TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS sign_history_created_at
               ON sign_history(created_at DESC, id DESC);",
        )?;
        Ok(Self { connection })
    }

    /// Record only a basename and cryptographic metadata, never a full path.
    pub fn record(
        &mut self,
        operation: &str,
        document_name: &str,
        document_sha256: Option<[u8; 32]>,
        identity_id: Option<[u8; 16]>,
        status: &str,
    ) -> Result<i64, HistoryError> {
        if !matches!(operation, "sign" | "verify")
            || document_name.is_empty()
            || document_name.len() > 255
            || document_name == "."
            || document_name == ".."
            || document_name.contains('/')
            || document_name.contains('\\')
            || document_name.chars().any(char::is_control)
            || status.is_empty()
            || status.len() > 64
            || status.chars().any(char::is_control)
        {
            return Err(HistoryError::InvalidEntry);
        }
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| HistoryError::Clock)?
            .as_secs();
        self.connection.execute(
            "INSERT INTO sign_history
             (created_at, operation, document_name, document_sha256, identity_id, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                created_at,
                operation,
                document_name,
                document_sha256.map(|v| v.to_vec()),
                identity_id.map(|v| v.to_vec()),
                status
            ],
        )?;
        self.connection.execute(
            "DELETE FROM sign_history WHERE id NOT IN
             (SELECT id FROM sign_history ORDER BY created_at DESC, id DESC LIMIT ?1)",
            [MAX_ENTRIES as i64],
        )?;
        Ok(self.connection.last_insert_rowid())
    }

    pub fn list(&self, limit: usize) -> Result<Vec<HistoryEntry>, HistoryError> {
        if limit == 0 || limit > MAX_ENTRIES {
            return Err(HistoryError::InvalidEntry);
        }
        let mut statement = self.connection.prepare(
            "SELECT id, created_at, operation, document_name,
                    document_sha256, identity_id, status
             FROM sign_history ORDER BY created_at DESC, id DESC LIMIT ?1",
        )?;
        let rows = statement.query_map([limit as i64], |row| {
            let digest: Option<Vec<u8>> = row.get(4)?;
            let identity: Option<Vec<u8>> = row.get(5)?;
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, u64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                digest,
                identity,
                row.get::<_, String>(6)?,
            ))
        })?;
        let mut entries = Vec::new();
        for row in rows {
            let (id, created_at, operation, document_name, digest, identity, status) = row?;
            let document_sha256 = digest
                .map(|v| v.try_into().map_err(|_| rusqlite::Error::InvalidQuery))
                .transpose()?;
            let identity_id = identity
                .map(|v| v.try_into().map_err(|_| rusqlite::Error::InvalidQuery))
                .transpose()?;
            entries.push(HistoryEntry {
                id,
                created_at,
                operation,
                document_name,
                document_sha256,
                identity_id,
                status,
            });
        }
        Ok(entries)
    }

    pub fn clear(&mut self) -> Result<(), HistoryError> {
        self.connection.execute("DELETE FROM sign_history", [])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persists_metadata_and_rejects_invalid_entries() {
        let path = std::env::temp_dir().join(format!(
            "nqs-history-{}-{}.sqlite",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        {
            let mut store = HistoryStore::open(&path).unwrap();
            let id = store
                .record(
                    "sign",
                    "contract.pdf",
                    Some([7; 32]),
                    Some([9; 16]),
                    "signed",
                )
                .unwrap();
            assert!(id > 0);
            assert!(store.record("delete", "x", None, None, "ok").is_err());
            assert!(
                store
                    .record("verify", "../private/path", None, None, "ok")
                    .is_err()
            );
            assert_eq!(store.list(10).unwrap().len(), 1);
        }
        {
            let store = HistoryStore::open(&path).unwrap();
            let entries = store.list(10).unwrap();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].document_name, "contract.pdf");
            assert_eq!(entries[0].document_sha256, Some([7; 32]));
        }
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = std::fs::remove_file(path.with_extension("sqlite-shm"));
    }
}
