# NEXUS-Q Sign — Core integration reconnaissance

Date: 2026-11-13  
Core package: `nexusq-core 4.1.2`  
Source: `~/nexus-q` (extracted from the supplied 4.1.2 archive; matches Vault's declared local dependency path).  
Status: ML-DSA primitive integration spike **PASS**. Vault source inspected read-only. No Core or Vault source files modified.

## 1. Core test baseline

Executed on Termux/Android:

```text
cargo test -p nexusq-core --lib
566 passed; 0 failed; 0 ignored
```

This is a test result for the current Termux environment only. It does not establish Windows/macOS/Linux release support.

## 2. ML-DSA-65 public API

Source: `crates/nexusq-core/src/crypto/pq_sign.rs`.

Observed API:
- `MlDsa65KeyPair::try_generate()`
- `MlDsa65KeyPair::from_secret_key(bytes)`
- `MlDsa65KeyPair::secret_key()`
- `MlDsa65KeyPair::public_key()`
- `MlDsa65KeyPair::try_sign(message)`
- `MlDsa65VerifyingKey::from_public_key(bytes)`
- `MlDsa65VerifyingKey::verify(message, signature)`
- `ml_dsa_65_verify(public_key, message, signature)`

Sizes: public key 1,952 bytes; FIPS signing seed 32 bytes; signature 3,309 bytes. Use fallible `try_*` methods.

## 3. Independent Rust integration spike — PASS

Location: `~/nexus-q-sign-design/core-spike`

Command:
```sh
cargo test
```

Result on 2026-11-13:
```text
running 1 test
test tests::mldsa65_document_manifest_sign_verify_and_tamper_rejection ... ok
test result: ok. 1 passed; 0 failed
Doc-tests: 0 passed; 0 failed
Process exit code: 0
```

The test compiled against the exact local Core 4.1.2 source and verified:
1. ML-DSA-65 keypair generation.
2. Public key and seed lengths against Core constants.
3. Signature length against Core constant.
4. Signature verification over a sample NQSIG-style manifest byte string.
5. Rejection after changing the signed message.
6. Rejection after changing a signature byte.
7. Reconstruction from the 32-byte seed and successful verification with the original public key.

**What this proves:** Core's exposed ML-DSA-65 primitive can be consumed from a separate Rust crate on this Termux toolchain.

**What it does not prove:** NQSIG v1 canonicalization/interoperability, Vault identity integration, secure persistent key custody for Sign, timestamp trust, legal validity, or desktop platform support.

## 4. Vault identity-signing mismatch

Source: `crates/nexusq-core/src/vault/container.rs`.

- `Session::create_identity` creates an Ed25519 identity signing key and a separate ML-DSA-65 credential-signing key.
- `Session::identity_sign` explicitly accepts only the identity's Ed25519 key.
- `Session::identity_verify` verifies that Ed25519 signature.
- `Session::issue_credential` unwraps the dedicated credential key inside Core and dispatches to ML-DSA-65 for credential issuance.

Do not call `identity_sign` and describe its output as ML-DSA-65. Do not repurpose credential signing as document signing without a designed, explicit API and purpose separation.

## 5. Key-custody decision gate

See [KEY_CUSTODY_DESIGN.md](KEY_CUSTODY_DESIGN.md). The preferred path is a Core/Vault API that signs a caller-provided, domain-separated document manifest with a Vault-managed ML-DSA key, keeping unwrapping and key reconstruction inside Core. Sign must not copy Vault wrapping internals or pass private key bytes through the UI.

## 6. Backend

RustCrypto is the default provider. Native backend is opt-in/experimental and compile-time selected. Do not enable it for Sign without separate build and security validation.

## 7. Scope and integrity

This reconnaissance and spike did not modify the Vault repository or Core source. The new spike is isolated under `nexus-q-sign-design/core-spike`. No production signing implementation or NQSIG v1 format has been approved.
