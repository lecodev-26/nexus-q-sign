# NEXUS-Q Sign — Identity model

Date: 2026-11-13  
Status: v1 metadata model implemented in Sign Core; Tauri integration and security review pending.

## Ownership and meaning

An identity is a locally managed signing-key record owned by NEXUS-Q Sign. It is not a certificate, legal identity proof, trust anchor, or claim that a public key belongs to a verified person or organization. A detached signature's embedded public key is not trusted merely because it verifies.

Sign does not import Vault identities or share identity records, sessions, credentials, or private-key storage with Vault.

## Version 1 model

Each local identity record contains:

- identity_id: random 16-byte identifier for the Sign identity record.
- key_id: independent random 16-byte identifier for its encrypted private-key envelope.
- display_name: user-facing label, 1–128 UTF-8 bytes, non-empty after trimming, no control characters.
- public_key: exactly 1,952 bytes, encoded ML-DSA-65 public key.
- created_at: unsigned Unix seconds from the local clock; informational and not trusted timestamp evidence.

Version 1 deliberately supports one active key per identity record. Key rotation and multiple historical keys require an explicit future model and migration; do not silently overwrite an identity or key.

## On-disk representation

IdentityStore stores one public metadata record per identity_id.nqi file. The private encrypted envelope remains in the separate KeyStore as key_id.nqsk. No private seed, password, decrypted key, or ciphertext is included in the identity metadata record.

NQID v1 binary record:

| Field | Size |
|---|---:|
| Magic NQID | 4 bytes |
| Version | 1 byte |
| Identity ID | 16 bytes |
| Key ID | 16 bytes |
| Informational creation time | 8 bytes, big-endian |
| Display-name length | 2 bytes, big-endian |
| ML-DSA-65 public key | 1,952 bytes |
| UTF-8 display name | 1–128 bytes |

The parser rejects unsupported versions, invalid lengths, invalid UTF-8, empty/control-character names, and public keys of the wrong encoded length. Individual files are created exclusively, flushed, and atomically published in the same directory without replacing an existing record. Linux/Android use `renameat2(RENAME_NOREPLACE)` through safe `rustix`; other Unix targets use a hard-link no-clobber fallback. Unix directory/file permissions are restricted to 0700/0600.

## Current API

crates/sign-core/src/identity_store.rs provides:

- IdentityRecord::generate_ids() for independent random IDs.
- IdentityRecord::now_untrusted(...) for local-clock metadata.
- IdentityStore::open(...), store(...), load(...), and list().
- Public metadata only; no API to persist private plaintext.

`IdentityService` now coordinates the two stores inside Sign Core. Creation generates one ML-DSA-65 keypair, encrypts its seed, stores the ciphertext first, and then commits the public record. If metadata creation fails, it checks whether the record became visible before attempting ciphertext cleanup. This is best-effort crash consistency, not a multi-file filesystem transaction; orphan ciphertext recovery remains a release task. `list()` checks that each record has a corresponding envelope. `unlock()` decrypts in Rust and compares the derived public key with the stored record before returning an in-memory signer. `delete()` removes public metadata first and then the encrypted envelope; a failed second step can leave orphan ciphertext, not a visible broken identity.

Current service API: `IdentityService::open`, `create`, `list`, `unlock`, and `delete`. Tauri initializes the service in managed Rust state and exposes create/list/unlock/lock/delete commands. On unlock, Tauri stores the `DocumentSigner` in a Rust-only session slot; the webview receives only the identity ID, display name and public-key fingerprint. Locking drops the signer. The ML-DSA dependency explicitly enables its `zeroize` feature so the underlying signing key clears secret state on drop. This does not establish protection against process compromise, memory disclosure, keyloggers or all compiler/runtime copies. Signing operations are not yet connected to NQSIG.

## Remaining before release

- Tauri initializes `IdentityService` beneath its private app-data directory and exposes create/list/unlock/lock/delete commands; no storage path is accepted from JavaScript. The unlocked signer remains Rust-only and is dropped on explicit lock or application-state teardown.
- Add crash recovery for interrupted two-file creation and orphan ciphertext cleanup.
- Add uniqueness/collision handling and consistency checks between identity records and key envelopes.
- Define deletion, password change, backup/restore and key rotation.
- Review symlink/race behavior, permissions and atomic commit guarantees on every supported OS.
- Add integration tests for interrupted identity creation and orphaned key files.
- Do not label a locally stored identity as externally verified or certified.
