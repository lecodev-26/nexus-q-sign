#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use nexus_q_sign_core::{
    DocumentSigner, HistoryEntry, HistoryStore, IdentityRecord, IdentityService, NQSIG_ML_DSA_65,
    NQSIG_SHA_256, NqsigEnvelope, NqsigError, NqsigManifest, verify,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};
use tauri::{Manager, State};
use zeroize::Zeroizing;

const MAX_DOCUMENT_BYTES: u64 = 1_073_741_824;

struct UnlockedIdentity {
    identity_id: [u8; 16],
    key_id: [u8; 16],
    _signer: DocumentSigner,
}

struct SignState {
    identities: Mutex<IdentityService>,
    // Private signer material is Rust-only and is dropped (zeroized by Core) on lock/exit.
    unlocked: Mutex<Option<UnlockedIdentity>>,
    history: Mutex<HistoryStore>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AppInfo {
    name: &'static str,
    version: &'static str,
    release_channel: &'static str,
    crypto_ready: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DocumentInfo {
    file_name: String,
    size_bytes: u64,
    sha256: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignedDocumentInfo {
    sidecar_file_name: String,
    sha256: String,
    history_recorded: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VerificationInfo {
    status: String,
    document_sha256: String,
    signer_fingerprint: String,
    recognized_identity: Option<String>,
    history_recorded: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HistoryView {
    id: i64,
    created_at: u64,
    operation: String,
    document_name: String,
    document_sha256: Option<String>,
    identity_id: Option<String>,
    status: String,
}

impl From<HistoryEntry> for HistoryView {
    fn from(entry: HistoryEntry) -> Self {
        Self {
            id: entry.id,
            created_at: entry.created_at,
            operation: entry.operation,
            document_name: entry.document_name,
            document_sha256: entry.document_sha256.map(|v| hex(&v)),
            identity_id: entry.identity_id.map(|v| hex(&v)),
            status: entry.status,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct IdentityView {
    identity_id: String,
    display_name: String,
    created_at: u64,
    public_key_fingerprint: String,
}

impl From<IdentityRecord> for IdentityView {
    fn from(record: IdentityRecord) -> Self {
        let digest = Sha256::digest(&record.public_key);
        let fingerprint = digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        Self {
            identity_id: hex(&record.identity_id),
            display_name: record.display_name,
            created_at: record.created_at,
            public_key_fingerprint: fingerprint,
        }
    }
}

#[tauri::command]
fn list_history(limit: usize, state: State<'_, SignState>) -> Result<Vec<HistoryView>, String> {
    let history = state
        .history
        .lock()
        .map_err(|_| "El historial no está disponible.".to_string())?;
    history
        .list(limit)
        .map(|rows| rows.into_iter().map(HistoryView::from).collect())
        .map_err(|_| "No se pudo cargar el historial local.".to_string())
}

#[tauri::command]
fn clear_history(state: State<'_, SignState>) -> Result<(), String> {
    let mut history = state
        .history
        .lock()
        .map_err(|_| "El historial no está disponible.".to_string())?;
    history
        .clear()
        .map_err(|_| "No se pudo vaciar el historial local.".to_string())
}

#[tauri::command]
fn app_info() -> AppInfo {
    AppInfo {
        name: "NEXUS-Q Sign",
        version: env!("CARGO_PKG_VERSION"),
        release_channel: "development",
        crypto_ready: false,
    }
}

#[tauri::command]
fn list_identities(state: State<'_, SignState>) -> Result<Vec<IdentityView>, String> {
    let service = state
        .identities
        .lock()
        .map_err(|_| "El almacén de identidades no está disponible.".to_string())?;
    service
        .list()
        .map(|records| records.into_iter().map(IdentityView::from).collect())
        .map_err(|_| {
            "No se pudieron cargar las identidades. Comprueba el almacenamiento local.".to_string()
        })
}

#[tauri::command]
fn create_identity(
    display_name: String,
    password: String,
    state: State<'_, SignState>,
) -> Result<IdentityView, String> {
    let name = display_name.trim().to_string();
    if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
        return Err(
            "El nombre debe contener entre 1 y 128 bytes y no incluir caracteres de control."
                .into(),
        );
    }
    let password = Zeroizing::new(password.into_bytes());
    if password.len() < 12 || password.len() > 1024 {
        return Err("La contraseña debe tener entre 12 y 1024 bytes.".into());
    }
    let service = state
        .identities
        .lock()
        .map_err(|_| "El almacén de identidades no está disponible.".to_string())?;
    service
        .create(name, &password)
        .map(IdentityView::from)
        .map_err(|_| {
            "No se pudo crear la identidad. No se ha confirmado ningún registro nuevo.".to_string()
        })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct IdentitySessionView {
    identity_id: String,
    display_name: String,
    public_key_fingerprint: String,
}

#[tauri::command]
fn unlock_identity(
    identity_id: String,
    password: String,
    state: State<'_, SignState>,
) -> Result<IdentitySessionView, String> {
    let id = parse_hex_id(&identity_id)
        .ok_or_else(|| "Identificador de identidad no válido.".to_string())?;
    let password = Zeroizing::new(password.into_bytes());
    // Keep the same lock order as delete_identity (session, then identity store).
    // This prevents a delete from racing between key unlock and session install.
    let mut session = state
        .unlocked
        .lock()
        .map_err(|_| "La sesión segura no está disponible.".to_string())?;
    let service = state
        .identities
        .lock()
        .map_err(|_| "El almacén de identidades no está disponible.".to_string())?;
    let record = service
        .list()
        .map_err(|_| "No se pudieron cargar las identidades.".to_string())?
        .into_iter()
        .find(|r| r.identity_id == id)
        .ok_or_else(|| "La identidad no existe.".to_string())?;
    let signer = service
        .unlock(&id, &password)
        .map_err(|_| "No se pudo desbloquear la identidad. Comprueba la contraseña.".to_string())?;
    let digest = Sha256::digest(&record.public_key);
    let view = IdentitySessionView {
        identity_id: hex(&record.identity_id),
        display_name: record.display_name,
        public_key_fingerprint: digest.iter().map(|b| format!("{b:02x}")).collect(),
    };
    *session = Some(UnlockedIdentity {
        identity_id: id,
        key_id: record.key_id,
        _signer: signer,
    });
    Ok(view)
}

#[tauri::command]
fn lock_identity(state: State<'_, SignState>) -> Result<(), String> {
    let mut session = state
        .unlocked
        .lock()
        .map_err(|_| "La sesión segura no está disponible.".to_string())?;
    *session = None;
    Ok(())
}

#[tauri::command]
fn identity_session(state: State<'_, SignState>) -> Result<Option<String>, String> {
    let session = state
        .unlocked
        .lock()
        .map_err(|_| "La sesión segura no está disponible.".to_string())?;
    Ok(session.as_ref().map(|s| hex(&s.identity_id)))
}

#[tauri::command]
fn delete_identity(identity_id: String, state: State<'_, SignState>) -> Result<(), String> {
    let id = parse_hex_id(&identity_id)
        .ok_or_else(|| "Identificador de identidad no válido.".to_string())?;
    // Hold both locks through deletion, using the same order as unlock_identity.
    // Otherwise an unlock could install a session after this command clears it.
    let mut session = state
        .unlocked
        .lock()
        .map_err(|_| "La sesión segura no está disponible.".to_string())?;
    if session.as_ref().is_some_and(|s| s.identity_id == id) {
        *session = None;
    }
    let service = state
        .identities
        .lock()
        .map_err(|_| "El almacén de identidades no está disponible.".to_string())?;
    service
        .delete(&id)
        .map_err(|_| "No se pudo eliminar la identidad.".to_string())
}

/// Inspect a user-selected document without modifying it. The path is never returned.
#[tauri::command]
fn inspect_document(path: String) -> Result<DocumentInfo, String> {
    let canonical = Path::new(&path)
        .canonicalize()
        .map_err(|_| "No se puede acceder al documento seleccionado.".to_string())?;
    let metadata = std::fs::metadata(&canonical)
        .map_err(|_| "No se pueden leer los metadatos del documento.".to_string())?;
    if !metadata.is_file() {
        return Err("La selección no es un archivo normal.".into());
    }
    if metadata.len() > MAX_DOCUMENT_BYTES {
        return Err("El documento supera el límite de 1 GiB para esta versión.".into());
    }
    let file_name = canonical
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("documento")
        .to_string();
    let mut reader = BufReader::new(
        File::open(&canonical)
            .map_err(|_| "No se puede abrir el documento seleccionado.".to_string())?,
    );
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|_| "Error leyendo el documento.".to_string())?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > MAX_DOCUMENT_BYTES {
            return Err("El documento supera el límite de 1 GiB para esta versión.".into());
        }
        hasher.update(&buffer[..read]);
    }
    let sha256 = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok(DocumentInfo {
        file_name,
        size_bytes: total,
        sha256,
    })
}

#[tauri::command]
fn sign_document(path: String, state: State<'_, SignState>) -> Result<SignedDocumentInfo, String> {
    let canonical = Path::new(&path)
        .canonicalize()
        .map_err(|_| "No se puede acceder al documento seleccionado.".to_string())?;
    let mut file = File::open(&canonical)
        .map_err(|_| "No se puede abrir el documento seleccionado.".to_string())?;
    let before = file
        .metadata()
        .map_err(|_| "No se pueden leer los metadatos del documento.".to_string())?;
    if !before.is_file() || before.len() > MAX_DOCUMENT_BYTES {
        return Err("El documento no es un archivo normal o supera el límite de 1 GiB.".into());
    }

    let digest = hash_document(&mut file)?;
    let session = state
        .unlocked
        .lock()
        .map_err(|_| "La sesión segura no está disponible.".to_string())?;
    let active = session
        .as_ref()
        .ok_or_else(|| "Desbloquea una identidad antes de firmar.".to_string())?;
    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "El reloj del dispositivo no es válido.".to_string())?
        .as_secs();
    let manifest = NqsigManifest {
        signature_algorithm: NQSIG_ML_DSA_65,
        digest_algorithm: NQSIG_SHA_256,
        document_digest: digest,
        identity_id: active.identity_id,
        key_id: active.key_id,
        created_at,
    };
    let message = manifest
        .signing_message()
        .map_err(|_| "No se pudo preparar el manifiesto de firma.".to_string())?;
    let signature = active
        ._signer
        .sign(&message)
        .map_err(|_| "La operación criptográfica de firma ha fallado.".to_string())?;
    let envelope = NqsigEnvelope {
        manifest,
        public_key: active._signer.public_key(),
        signature,
    }
    .encode()
    .map_err(|_| "No se pudo codificar el sidecar NQSIG.".to_string())?;

    let digest_after = hash_document(&mut file)?;
    let after = file
        .metadata()
        .map_err(|_| "No se pudieron verificar los cambios del documento.".to_string())?;
    let path_after = fs::metadata(&canonical)
        .map_err(|_| "El documento seleccionado ha cambiado durante la firma.".to_string())?;
    if digest != digest_after
        || !same_file_snapshot(&before, &after)
        || !same_file_snapshot(&before, &path_after)
    {
        return Err("El documento cambió durante la firma. No se ha creado el sidecar.".into());
    }

    let sidecar = PathBuf::from(format!("{}.nqsig", canonical.to_string_lossy()));
    publish_noreplace(&sidecar, &envelope)?;
    record_history(
        &state,
        "sign",
        &canonical,
        Some(digest),
        Some(active.identity_id),
        "signed",
    );
    let file_name = sidecar
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or("documento.nqsig")
        .to_string();
    Ok(SignedDocumentInfo {
        sidecar_file_name: file_name,
        sha256: digest.iter().map(|b| format!("{b:02x}")).collect(),
        history_recorded,
    })
}

#[tauri::command]
fn verify_document(
    document_path: String,
    sidecar_path: String,
    state: State<'_, SignState>,
) -> Result<VerificationInfo, String> {
    let document = Path::new(&document_path)
        .canonicalize()
        .map_err(|_| "No se puede acceder al documento seleccionado.".to_string())?;
    let sidecar_input = Path::new(&sidecar_path);
    let sidecar_input_meta = fs::symlink_metadata(sidecar_input)
        .map_err(|_| "No se pueden leer los metadatos del sidecar.".to_string())?;
    if !sidecar_input_meta.is_file() || sidecar_input_meta.len() > 65_536 {
        return Err("El sidecar no es un archivo normal o supera 65.536 bytes.".into());
    }
    let sidecar = sidecar_input
        .canonicalize()
        .map_err(|_| "No se puede acceder al sidecar seleccionado.".to_string())?;
    let mut sidecar_file = File::open(&sidecar)
        .map_err(|_| "No se puede abrir el sidecar seleccionado.".to_string())?;
    let sidecar_meta = sidecar_file
        .metadata()
        .map_err(|_| "No se pueden leer los metadatos del sidecar.".to_string())?;
    if !same_file_snapshot(&sidecar_input_meta, &sidecar_meta)
        || !sidecar_meta.is_file()
        || sidecar_meta.len() > 65_536
    {
        return Err("El sidecar cambió o no es un archivo normal.".into());
    }
    let mut sidecar_bytes = Vec::with_capacity(sidecar_meta.len() as usize);
    sidecar_file
        .take(65_537)
        .read_to_end(&mut sidecar_bytes)
        .map_err(|_| "No se pudo leer el sidecar.".to_string())?;
    if sidecar_bytes.len() > 65_536 {
        return Ok(verification_status("malformed_sidecar"));
    }
    let envelope = match NqsigEnvelope::decode(&sidecar_bytes) {
        Ok(value) => value,
        Err(NqsigError::UnsupportedVersion) => {
            return Ok(verification_status("unsupported_version"));
        }
        Err(NqsigError::UnsupportedAlgorithm) => {
            return Ok(verification_status("unsupported_algorithm"));
        }
        Err(_) => return Ok(verification_status("malformed_sidecar")),
    };

    let mut document_file = File::open(&document)
        .map_err(|_| "No se puede abrir el documento seleccionado.".to_string())?;
    let metadata = document_file
        .metadata()
        .map_err(|_| "No se pueden leer los metadatos del documento.".to_string())?;
    if !metadata.is_file() || metadata.len() > MAX_DOCUMENT_BYTES {
        return Err("El documento no es un archivo normal o supera el límite de 1 GiB.".into());
    }
    let digest = hash_document(&mut document_file)?;
    let digest_hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    if digest != envelope.manifest.document_digest {
        let history_recorded = record_history(
            &state,
            "verify",
            &document,
            Some(digest),
            Some(envelope.manifest.identity_id),
            "document_changed",
        );
        return Ok(VerificationInfo {
            status: "document_changed".into(),
            document_sha256: digest_hex,
            signer_fingerprint: fingerprint(&envelope.public_key),
            recognized_identity: None,
            history_recorded,
        });
    }

    let message = envelope
        .manifest
        .signing_message()
        .map_err(|_| "No se pudo reconstruir el mensaje autenticado.".to_string())?;
    if verify(&envelope.public_key, &message, &envelope.signature).is_err() {
        let history_recorded = record_history(
            &state,
            "verify",
            &document,
            Some(digest),
            Some(envelope.manifest.identity_id),
            "invalid_signature",
        );
        return Ok(VerificationInfo {
            status: "invalid_signature".into(),
            document_sha256: digest_hex,
            signer_fingerprint: fingerprint(&envelope.public_key),
            recognized_identity: None,
            history_recorded,
        });
    }

    // Re-hash after the cryptographic operation so a concurrently modified or
    // replaced document cannot be reported as successfully verified.
    let digest_after = hash_document(&mut document_file)?;
    let metadata_after = document_file
        .metadata()
        .map_err(|_| "No se pudieron verificar los cambios del documento.".to_string())?;
    let path_after = fs::metadata(&document).map_err(|_| {
        "El documento seleccionado ha cambiado durante la verificación.".to_string()
    })?;
    if digest != digest_after
        || !same_file_snapshot(&metadata, &metadata_after)
        || !same_file_snapshot(&metadata, &path_after)
    {
        let history_recorded = record_history(
            &state,
            "verify",
            &document,
            Some(digest),
            Some(envelope.manifest.identity_id),
            "document_changed",
        );
        return Ok(VerificationInfo {
            status: "document_changed".into(),
            document_sha256: digest_hex,
            signer_fingerprint: fingerprint(&envelope.public_key),
            recognized_identity: None,
            history_recorded,
        });
    }

    let identities = state
        .identities
        .lock()
        .map_err(|_| "El almacén de identidades no está disponible.".to_string())?;
    let records = identities
        .list()
        .map_err(|_| "No se pudieron consultar las identidades locales.".to_string())?;
    let recognized = records.into_iter().find(|record| {
        record.identity_id == envelope.manifest.identity_id
            && record.key_id == envelope.manifest.key_id
            && record.public_key == envelope.public_key
    });
    let (status, recognized_identity) = match recognized {
        Some(record) => (
            "valid_and_recognized".to_string(),
            Some(record.display_name),
        ),
        None => ("valid_unknown_identity".to_string(), None),
    };
    let history_recorded = record_history(
        &state,
        "verify",
        &document,
        Some(digest),
        Some(envelope.manifest.identity_id),
        &status,
    );
    Ok(VerificationInfo {
        status,
        document_sha256: digest_hex,
        signer_fingerprint: fingerprint(&envelope.public_key),
        recognized_identity,
        history_recorded,
    })
}

fn record_history(
    state: &SignState,
    operation: &str,
    document: &Path,
    digest: Option<[u8; 32]>,
    identity_id: Option<[u8; 16]>,
    status: &str,
) -> bool {
    let Some(name) = document.file_name().and_then(|v| v.to_str()) else {
        return false;
    };
    state
        .history
        .lock()
        .ok()
        .and_then(|mut history| {
            history
                .record(operation, name, digest, identity_id, status)
                .ok()
        })
        .is_some()
}

fn verification_status(status: &str) -> VerificationInfo {
    VerificationInfo {
        status: status.to_string(),
        document_sha256: String::new(),
        signer_fingerprint: String::new(),
        recognized_identity: None,
        history_recorded: false,
    }
}

fn fingerprint(public_key: &[u8]) -> String {
    Sha256::digest(public_key)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn hash_document(file: &mut File) -> Result<[u8; 32], String> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| "No se pudo volver a leer el documento.".to_string())?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|_| "Error leyendo el documento.".to_string())?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > MAX_DOCUMENT_BYTES {
            return Err("El documento supera el límite de 1 GiB.".into());
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

fn same_file_snapshot(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    if a.len() != b.len() || a.modified().ok() != b.modified().ok() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        a.dev() == b.dev() && a.ino() == b.ino()
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn publish_noreplace(destination: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = destination
        .parent()
        .ok_or_else(|| "No se pudo determinar la carpeta de destino.".to_string())?;
    for _ in 0..8 {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random)
            .map_err(|_| "No se pudo generar un nombre temporal seguro.".to_string())?;
        let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let temp = parent.join(format!(".nqsig-{suffix}.tmp"));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = match options.open(&temp) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err("No se pudo crear el archivo temporal de firma.".into()),
        };
        let write_result = (|| -> std::io::Result<()> {
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            Ok(())
        })();
        if let Err(_) = write_result {
            let _ = fs::remove_file(&temp);
            return Err("No se pudo escribir el sidecar temporal de firma.".into());
        }
        if let Err(error) = commit_sidecar_noreplace(&temp, destination) {
            let _ = fs::remove_file(&temp);
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                return Err(
                    "Ya existe un sidecar .nqsig para este documento; no se ha sobrescrito.".into(),
                );
            }
            return Err("No se pudo publicar el sidecar de firma.".into());
        }
        #[cfg(unix)]
        if File::open(parent)
            .and_then(|directory| directory.sync_all())
            .is_err()
        {
            return Err(
                "El sidecar se publicó, pero no se pudo confirmar la sincronización de la carpeta."
                    .into(),
            );
        }
        return Ok(());
    }
    Err("No se pudo reservar un nombre temporal para el sidecar.".into())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn commit_sidecar_noreplace(source: &Path, destination: &Path) -> std::io::Result<()> {
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
fn commit_sidecar_noreplace(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::hard_link(source, destination)?;
    fs::remove_file(source)
}

fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(H[(b >> 4) as usize] as char);
        out.push(H[(b & 15) as usize] as char);
    }
    out
}

fn parse_hex_id(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, pair) in s.as_bytes().chunks_exact(2).enumerate() {
        let digit = |b: u8| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        };
        out[i] = (digit(pair[0])? << 4) | digit(pair[1])?;
    }
    Some(out)
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let app_data = app.path().app_data_dir()?;
            let service = IdentityService::open(&app_data)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            let history = HistoryStore::open(app_data.join("history.sqlite3"))
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            app.manage(SignState {
                identities: Mutex::new(service),
                unlocked: Mutex::new(None),
                history: Mutex::new(history),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            app_info,
            list_history,
            clear_history,
            inspect_document,
            list_identities,
            create_identity,
            unlock_identity,
            lock_identity,
            identity_session,
            sign_document,
            verify_document,
            delete_identity
        ])
        .run(tauri::generate_context!())
        .expect("error while running NEXUS-Q Sign");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sidecar_publication_is_atomic_and_never_overwrites() {
        let root =
            std::env::temp_dir().join(format!("nexus-q-sign-sidecar-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create test directory");
        let destination = root.join("document.pdf.nqsig");

        publish_noreplace(&destination, b"first signature").expect("publish first sidecar");
        assert_eq!(std::fs::read(&destination).unwrap(), b"first signature");

        let result = publish_noreplace(&destination, b"replacement signature");
        assert!(result.is_err());
        assert_eq!(std::fs::read(&destination).unwrap(), b"first signature");

        let leftovers: Vec<_> = std::fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(leftovers.len(), 1, "temporary file must be cleaned up");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn sha256_digest_is_lowercase_hex() {
        let digest = Sha256::digest(b"abc");
        let encoded: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            encoded,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn document_size_limit_is_one_gibibyte() {
        assert_eq!(MAX_DOCUMENT_BYTES, 1_073_741_824);
    }

    #[test]
    fn identity_id_parser_accepts_only_lowercase_hex_16_byte_ids() {
        assert_eq!(
            parse_hex_id("00112233445566778899aabbccddeeff").unwrap(),
            [
                0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255
            ]
        );
        assert!(parse_hex_id("001122").is_none());
        assert!(parse_hex_id("00112233445566778899AABBCCDDEEFF").is_none());
    }

    #[test]
    fn inspect_document_returns_expected_sha256_without_changing_source() {
        let path =
            std::env::temp_dir().join(format!("nexus-q-sign-test-{}.bin", std::process::id()));
        std::fs::write(&path, b"abc").expect("write fixture");
        let before = std::fs::read(&path).expect("read fixture");
        let result =
            inspect_document(path.to_string_lossy().into_owned()).expect("inspect fixture");
        let after = std::fs::read(&path).expect("read fixture after inspection");
        let _ = std::fs::remove_file(&path);
        assert_eq!(result.size_bytes, 3);
        assert_eq!(
            result.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(before, after);
    }
}
