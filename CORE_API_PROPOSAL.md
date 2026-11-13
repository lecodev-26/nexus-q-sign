# NEXUS-Q Sign — Core API proposal (review draft)

Date: 2026-11-13  
Target source: NEXUS-Q Core 4.1.2  
Status: proposal only. No Core/Vault source changes made.

## Executive decision

Add a dedicated ML-DSA-65 document-signing key reference to each identity and a dedicated Session API. Do not reuse the Ed25519 identity-authentication key or the ML-DSA-65 credential-signing key.

The API must keep unwrap, seed reconstruction, signing, and zeroization inside Core. Sign receives signature bytes, public-key bytes/key identifier, and typed metadata only.

## Evidence from current implementation

- `Identity` currently has `signing_key`, `signing_key_history`, `credential_signing_key`, and `credential_signing_key_history`; there is no document-specific key reference.
- `Session::create_identity` creates Ed25519 identity-signing and ML-DSA-65 credential-signing keys.
- `Session::identity_sign` enforces Ed25519.
- `Session::issue_credential` unwraps the credential key internally and uses ML-DSA-65.
- `Purpose::Sign` is currently generic, described as allowing documents, messages, and credentials. It does not itself provide protocol/domain separation.
- `PolicyOperation` already has generic `Sign`, `IdentitySign`, and `CredentialIssue`, but no document-sign operation.
- `EventType` has `IdentitySigned` and `CredentialIssued`, but no explicit document-signed event.
- Audit events are hash chained and must never contain secret material.

## Proposed identity data model

Add optional, backward-compatible fields (serde default):

```rust
pub document_signing_key: Option<KeyId>,
pub document_signing_key_history: Vec<KeyId>,
```

The existing Ed25519 `signing_key` fields remain unchanged for compatibility. Credential key fields remain exclusively for credentials.

On new identity creation:
1. Generate Ed25519 identity key as today.
2. Generate ML-DSA-65 credential key as today.
3. Generate a separate ML-DSA-65 document-signing key.
4. Activate each key using existing lifecycle operations.
5. Store the document key id and initialize its history.
6. Ensure any migration/backfill for old identities leaves document key absent until an explicit migration or user-authorized key creation. Do not silently assign an existing credential key to document signing.

The schema change requires explicit Core format/version compatibility review. Serde defaults alone are not sufficient evidence that every old/new vault roundtrip is safe.

## Proposed policy and audit model

Add `PolicyOperation::IdentityDocumentSign` with canonical id `identity_document_sign` and mark it as identity-targeting. Ensure policy evaluation, serialization, parsing, tests, and any exhaustive matches are updated.

Add `EventType::IdentityDocumentSigned` with canonical id `identity_document_signed`. Audit metadata may include identity id, document key id, algorithm, digest algorithm, and manifest version only if the audit schema supports structured safe metadata. Never log document bytes, private material, passphrases, or full sensitive paths.

Policy checks and audit write failure semantics must be consistent with existing `identity_sign` and `issue_credential`. Signing should fail closed if the configured audit log cannot record the operation.

## Proposed API shape (illustrative)

```rust
pub struct DocumentSignature {
    pub algorithm: Algorithm,        // ML-DSA-65 only for v1
    pub key_id: KeyId,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Session {
    pub fn identity_sign_document(
        &self,
        identity_id: &IdentityId,
        manifest: &[u8],
    ) -> Result<DocumentSignature, VaultError>;

    pub fn identity_document_verifying_key(
        &self,
        identity_id: &IdentityId,
        key_id: &KeyId,
    ) -> Result<DocumentVerifyingKey, VaultError>;
}
```

These signatures are design sketches, not current Core symbols. Prefer a typed result over a tuple. The signing API should select the current key internally; callers must not supply an arbitrary key id to bypass identity binding.

The verification-key API must resolve only keys in that identity's document-signing history, check algorithm and public-key presence, and define how retired/revoked keys are represented. Verification of old signatures must remain possible after rotation. Whether revoked identities' signatures are reported as cryptographically valid but identity-revoked is a separate trust-policy result, not a cryptographic failure.

## Core signing algorithm requirements

1. Require writable/unlocked, non-compromised Session state.
2. Check identity exists and is Active.
3. Check identity document key reference exists and points to a key record.
4. Require `Algorithm::MlDsa65`, `Purpose::Sign`, and `KeyStatus::Active`.
5. Evaluate the dedicated identity-document-sign policy with the identity context.
6. Unwrap key inside Core; reconstruct with fallible ML-DSA API.
7. Sign exact manifest bytes; no implicit serialization or normalization inside the primitive API.
8. Ensure secret seed is zeroized on all paths.
9. Append dedicated audit event; fail closed if audit is configured and cannot record.
10. Return algorithm, key id, public key and signature. Do not return secret bytes.

Use the existing `MlDsa65KeyPair::from_secret_key`, `try_sign`, and `public_key`/stored public-key APIs. Avoid panic-based compatibility methods.

## Rotation and revocation

- Rotation creates a fresh ML-DSA-65 document key, activates it, moves the previous active key to Retired using established lifecycle rules, updates current reference and appends history.
- Historical public keys remain available for detached verification.
- Revocation prevents new signatures but does not erase public material needed to verify prior signatures.
- Destroying a key must be an explicit destructive lifecycle operation and should not be part of normal rotation.
- Identity revocation blocks new document signatures. Verification must still report cryptographic validity separately from current identity status.

## Tests required in Core

- New identity has distinct Ed25519, credential ML-DSA, and document ML-DSA key IDs.
- Document key is ML-DSA-65, Sign purpose, Active.
- Document signature verifies with returned public key.
- Altered manifest and altered signature fail verification.
- Identity key and credential key cannot be selected by document signing.
- Missing document key returns a typed error; no silent fallback.
- Locked, sealed, compromised, inactive and revoked identity cases deny signing.
- Retired/revoked document key cannot sign.
- Policy allow/deny behavior and identity targeting.
- Audit success event emitted; audit failure fails closed.
- Rotation preserves old public key and verifies old signatures while new signatures use new key.
- Old vault fixtures deserialize and roundtrip without inventing document key references.
- Serialization migration and downgrade behavior tested explicitly.

## NEXUS-Q Sign integration contract

Sign should call a narrow Rust service that invokes the approved Session API. Frontend IPC never receives private material. The sidecar contains only public verification metadata, manifest bytes or fields, and signature. The document hash and canonical manifest are computed by Sign's Rust backend under a separately specified NQSIG v1 format.

## Open decisions for Core review

1. Should document signing be a dedicated identity field or a typed key-role abstraction reusable for future protocol-specific keys?
2. Should `Purpose::Sign` remain generic with a dedicated policy operation, or should Core add a serialized `DocumentSign` purpose? Adding a purpose changes stable serialization and compatibility and requires a migration plan.
3. What schema version bump and migration strategy are required?
4. What structured fields can the current audit event model safely persist?
5. What exact policy precedence applies when both identity-level and key-level policies exist?

## Implementation boundary

This proposal is isolated in the Sign design workspace. Do not patch Core/Vault until its maintainers approve the identity schema, purpose model, policy operation, audit event, and migration strategy.
