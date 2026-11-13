use nexus_q_sign_core::{
    DocumentSigner, IdentityService, NQSIG_ML_DSA_65, NQSIG_SHA_256, NqsigEnvelope, NqsigError,
    NqsigManifest, verify,
};
use sha2::{Digest, Sha256};
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

const MAX_DOC: u64 = 1_073_741_824;
const MAX_SIDE: u64 = 65_536;
type VerificationResult = (&'static str, Option<String>, Option<[u8; 32]>);

fn main() {
    if let Err(e) = run() {
        eprintln!("ERROR: {e}");
        std::process::exit(1);
    }
}
fn run() -> Result<(), String> {
    let root = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("Uso: nqs-cli <directorio-de-datos>")?;
    fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    let service = IdentityService::open(&root).map_err(|e| e.to_string())?;
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut session: Option<([u8; 16], [u8; 16], DocumentSigner)> = None;
    println!("NEXUS-Q Sign CLI temporal | datos={}", root.display());
    println!(
        "help | create <nombre> | list | unlock <id> | lock | session | inspect <archivo> | sign <archivo> | verify <archivo> [sidecar] | delete <id> | quit"
    );
    loop {
        print!("nqs> ");
        io::stdout().flush().map_err(|e| e.to_string())?;
        let mut line = String::new();
        if input.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
            break;
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (cmd, arg) = line.split_once(' ').unwrap_or((line, ""));
        let arg = arg.trim();
        match cmd {
            "help" => println!(
                "Comandos: create <nombre>, list, unlock <id>, lock, session, inspect <archivo>, sign <archivo>, verify <archivo> [sidecar], delete <id>, quit"
            ),
            "create" => {
                if arg.is_empty() {
                    println!("Uso: create <nombre>");
                    continue;
                }
                let pw = password(&mut input, "Nueva contraseña (12–1024 bytes): ")?;
                match service.create(arg.to_string(), &pw) {
                    Ok(r) => println!("CREATED id={} name={}", hex(&r.identity_id), r.display_name),
                    Err(e) => println!("CREATE_FAILED {e}"),
                }
            }
            "list" => match service.list() {
                Ok(rs) => {
                    println!("IDENTITIES {}", rs.len());
                    for r in rs {
                        println!(
                            "{} | {} | {}",
                            hex(&r.identity_id),
                            r.display_name,
                            hex(&Sha256::digest(&r.public_key))
                        );
                    }
                }
                Err(e) => println!("LIST_FAILED {e}"),
            },
            "unlock" => {
                let Some(id) = parse_id(arg) else {
                    println!("ID inválido");
                    continue;
                };
                let pw = password(&mut input, "Contraseña: ")?;
                match service.unlock(&id, &pw) {
                    Ok(s) => {
                        let r = service
                            .list()
                            .map_err(|e| e.to_string())?
                            .into_iter()
                            .find(|r| r.identity_id == id)
                            .ok_or("Identidad no encontrada")?;
                        session = Some((id, r.key_id, s));
                        println!("UNLOCKED {}", hex(&id));
                    }
                    Err(e) => {
                        session = None;
                        println!("UNLOCK_FAILED {e}")
                    }
                }
            }
            "lock" => {
                session = None;
                println!("LOCKED")
            }
            "session" => {
                if let Some((id, _, _)) = &session {
                    println!("SESSION_UNLOCKED {}", hex(id))
                } else {
                    println!("SESSION_LOCKED")
                }
            }
            "inspect" => match inspect(Path::new(arg)) {
                Ok((n, d)) => println!("INSPECT_OK bytes={n} sha256={}", hex(&d)),
                Err(e) => println!("INSPECT_FAILED {e}"),
            },
            "sign" => {
                let Some((id, key, signer)) = &session else {
                    println!("SIGN_FAILED: identidad bloqueada");
                    continue;
                };
                match sign(Path::new(arg), *id, *key, signer) {
                    Ok((p, d)) => println!("SIGNED sidecar={} sha256={}", p.display(), hex(&d)),
                    Err(e) => println!("SIGN_FAILED {e}"),
                }
            }
            "verify" => {
                let mut p = arg.splitn(2, char::is_whitespace);
                let doc = p.next().unwrap_or("");
                let side = p
                    .next()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from(format!("{doc}.nqsig")));
                match verify_doc(Path::new(doc), &side, &service) {
                    Ok((s, n, d)) => println!(
                        "VERIFY status={s} identity={} sha256={}",
                        n.unwrap_or_else(|| "-".into()),
                        d.map(|v| hex(&v)).unwrap_or_default()
                    ),
                    Err(e) => println!("VERIFY_FAILED {e}"),
                }
            }
            "delete" => {
                let Some(id) = parse_id(arg) else {
                    println!("ID inválido");
                    continue;
                };
                if session.as_ref().is_some_and(|(v, _, _)| *v == id) {
                    session = None;
                }
                match service.delete(&id) {
                    Ok(()) => println!("DELETED {}", hex(&id)),
                    Err(e) => println!("DELETE_FAILED {e}"),
                }
            }
            "quit" | "exit" => break,
            _ => println!("Comando desconocido; usa help"),
        }
    }
    println!("CLI cerrada; sesión bloqueada.");
    Ok(())
}
fn password<R: BufRead>(r: &mut R, prompt: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    print!("{prompt}");
    io::stdout().flush().map_err(|e| e.to_string())?;
    let mut s = String::new();
    r.read_line(&mut s).map_err(|e| e.to_string())?;
    while matches!(s.chars().last(), Some('\n' | '\r')) {
        s.pop();
    }
    Ok(Zeroizing::new(s.into_bytes()))
}
fn inspect(p: &Path) -> Result<(u64, [u8; 32]), String> {
    let p = p.canonicalize().map_err(|e| e.to_string())?;
    let mut f = File::open(p).map_err(|e| e.to_string())?;
    let m = f.metadata().map_err(|e| e.to_string())?;
    if !m.is_file() || m.len() > MAX_DOC {
        return Err("Archivo no normal o supera 1 GiB".into());
    }
    Ok((m.len(), hash(&mut f)?))
}
fn sign(
    p: &Path,
    id: [u8; 16],
    key: [u8; 16],
    s: &DocumentSigner,
) -> Result<(PathBuf, [u8; 32]), String> {
    let p = p.canonicalize().map_err(|e| e.to_string())?;
    let mut f = File::open(&p).map_err(|e| e.to_string())?;
    let before = f.metadata().map_err(|e| e.to_string())?;
    if !before.is_file() || before.len() > MAX_DOC {
        return Err("Archivo no normal o supera 1 GiB".into());
    }
    let digest = hash(&mut f)?;
    let m = NqsigManifest {
        signature_algorithm: NQSIG_ML_DSA_65,
        digest_algorithm: NQSIG_SHA_256,
        document_digest: digest,
        identity_id: id,
        key_id: key,
        created_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs(),
    };
    let msg = m.signing_message().map_err(|e| e.to_string())?;
    let sig = s.sign(&msg).map_err(|e| e.to_string())?;
    let bytes = NqsigEnvelope {
        manifest: m,
        public_key: s.public_key(),
        signature: sig,
    }
    .encode()
    .map_err(|e| e.to_string())?;
    let after = hash(&mut f)?;
    let now = f.metadata().map_err(|e| e.to_string())?;
    let current = fs::metadata(&p).map_err(|e| e.to_string())?;
    if digest != after
        || !same_file_snapshot(&before, &now)
        || !same_file_snapshot(&before, &current)
    {
        return Err("El documento cambió durante la firma".into());
    }
    let side = PathBuf::from(format!("{}.nqsig", p.display()));
    publish(&side, &bytes)?;
    Ok((side, digest))
}
fn verify_doc(
    doc: &Path,
    side: &Path,
    svc: &IdentityService,
) -> Result<VerificationResult, String> {
    let side_meta = fs::symlink_metadata(side).map_err(|e| e.to_string())?;
    if !side_meta.is_file() || side_meta.len() > MAX_SIDE {
        return Ok(("malformed_sidecar", None, None));
    }
    let sf = File::open(side).map_err(|e| e.to_string())?;
    let sm = sf.metadata().map_err(|e| e.to_string())?;
    if !same_file_snapshot(&side_meta, &sm) {
        return Ok(("malformed_sidecar", None, None));
    }
    let mut b = Vec::new();
    sf.take(MAX_SIDE + 1)
        .read_to_end(&mut b)
        .map_err(|e| e.to_string())?;
    if b.len() as u64 > MAX_SIDE {
        return Ok(("malformed_sidecar", None, None));
    }
    let e = match NqsigEnvelope::decode(&b) {
        Ok(v) => v,
        Err(NqsigError::UnsupportedVersion) => return Ok(("unsupported_version", None, None)),
        Err(NqsigError::UnsupportedAlgorithm) => return Ok(("unsupported_algorithm", None, None)),
        Err(_) => return Ok(("malformed_sidecar", None, None)),
    };
    let doc = doc.canonicalize().map_err(|e| e.to_string())?;
    let mut f = File::open(&doc).map_err(|e| e.to_string())?;
    let before = f.metadata().map_err(|e| e.to_string())?;
    if !before.is_file() || before.len() > MAX_DOC {
        return Err("Documento no normal o supera 1 GiB".into());
    }
    let d = hash(&mut f)?;
    if d != e.manifest.document_digest {
        return Ok(("document_changed", None, Some(d)));
    }
    let msg = e.manifest.signing_message().map_err(|e| e.to_string())?;
    if verify(&e.public_key, &msg, &e.signature).is_err() {
        return Ok(("invalid_signature", None, Some(d)));
    }
    let after_digest = hash(&mut f)?;
    let after = f.metadata().map_err(|e| e.to_string())?;
    let current = fs::metadata(&doc).map_err(|e| e.to_string())?;
    if after_digest != d
        || !same_file_snapshot(&before, &after)
        || !same_file_snapshot(&before, &current)
    {
        return Ok(("document_changed", None, Some(after_digest)));
    }
    let r = svc
        .list()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|r| {
            r.identity_id == e.manifest.identity_id
                && r.key_id == e.manifest.key_id
                && r.public_key == e.public_key
        });
    Ok(match r {
        Some(v) => ("valid_and_recognized", Some(v.display_name), Some(d)),
        None => ("valid_unknown_identity", None, Some(d)),
    })
}
fn same_file_snapshot(a: &fs::Metadata, b: &fs::Metadata) -> bool {
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

fn hash(f: &mut File) -> Result<[u8; 32], String> {
    use std::io::{Seek, SeekFrom};
    f.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let mut h = Sha256::new();
    let mut b = [0u8; 65536];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut b).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > MAX_DOC {
            return Err("Documento supera 1 GiB".into());
        }
        h.update(&b[..n]);
    }
    Ok(h.finalize().into())
}
fn publish(dst: &Path, b: &[u8]) -> Result<(), String> {
    let par = dst.parent().ok_or("Sin directorio padre")?;
    for i in 0..8 {
        let t = par.join(format!(".nqsig-cli-{}-{i}.tmp", std::process::id()));
        let mut o = OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = match o.open(&t) {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.to_string()),
        };
        if let Err(e) = f.write_all(b).and_then(|_| f.sync_all()) {
            drop(f);
            let _ = fs::remove_file(&t);
            return Err(e.to_string());
        }
        drop(f);
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let c = rustix::fs::renameat_with(
            rustix::fs::CWD,
            &t,
            rustix::fs::CWD,
            dst,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(io::Error::from);
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let c = fs::hard_link(&t, dst).and_then(|_| fs::remove_file(&t));
        if let Err(e) = c {
            let _ = fs::remove_file(&t);
            return Err(format!("No se publicó (¿ya existe?): {e}"));
        }
        #[cfg(unix)]
        File::open(par)
            .and_then(|d| d.sync_all())
            .map_err(|e| e.to_string())?;
        return Ok(());
    }
    Err("No se pudo reservar temporal".into())
}
fn parse_id(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let mut o = [0; 16];
    for (i, p) in s.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let d = |b| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        };
        o[i] = (d(p[0])? << 4) | d(p[1])?;
    }
    Some(o)
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn cli_sign_verify_tamper_collision_and_unknown_identity_flow() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let root = env::temp_dir().join(format!(
            "nexus-q-sign-cli-integration-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("create isolated test directory");

        let result = (|| -> Result<(), String> {
            let service = IdentityService::open(&root).map_err(|e| e.to_string())?;
            let password = Zeroizing::new(b"integration-test-passphrase".to_vec());
            let record = service
                .create("Integration Test".to_string(), &password)
                .map_err(|e| e.to_string())?;
            let listed = service.list().map_err(|e| e.to_string())?;
            assert!(
                listed
                    .iter()
                    .any(|item| item.identity_id == record.identity_id)
            );

            let signer = service
                .unlock(&record.identity_id, &password)
                .map_err(|e| e.to_string())?;
            let document = root.join("fixture.txt");
            let original = b"NEXUS-Q Sign CLI integration fixture";
            fs::write(&document, original).map_err(|e| e.to_string())?;

            let (sidecar, digest) = sign(&document, record.identity_id, record.key_id, &signer)?;
            let expected: [u8; 32] = Sha256::digest(original).into();
            assert_eq!(digest, expected);
            assert_eq!(
                verify_doc(&document, &sidecar, &service)?.0,
                "valid_and_recognized"
            );

            let original_sidecar = fs::read(&sidecar).map_err(|e| e.to_string())?;
            let collision = publish(&sidecar, b"must not overwrite");
            assert!(
                collision.is_err(),
                "existing sidecar must never be overwritten"
            );
            assert_eq!(
                fs::read(&sidecar).map_err(|e| e.to_string())?,
                original_sidecar
            );

            fs::write(&document, b"tampered document").map_err(|e| e.to_string())?;
            assert_eq!(
                verify_doc(&document, &sidecar, &service)?.0,
                "document_changed"
            );

            fs::write(&document, original).map_err(|e| e.to_string())?;
            assert_eq!(
                verify_doc(&document, &sidecar, &service)?.0,
                "valid_and_recognized"
            );

            drop(signer);
            service
                .delete(&record.identity_id)
                .map_err(|e| e.to_string())?;
            assert_eq!(
                verify_doc(&document, &sidecar, &service)?.0,
                "valid_unknown_identity"
            );
            Ok(())
        })();

        let cleanup = fs::remove_dir_all(&root);
        if let Err(error) = result {
            let _ = cleanup;
            panic!("CLI integration flow failed: {error}");
        }
        cleanup.expect("remove isolated test directory");
    }
}
