# Core API change specification — document signing

Status: proposal for maintainer review; no Core/Vault source changes made.
Target baseline: NEXUS-Q Core 4.1.2.

## 1. Scope and invariants

Add a Vault-managed ML-DSA-65 identity key dedicated to detached document signing. Preserve existing Ed25519 identity signing and ML-DSA-65 credential signing unchanged.

Hard invariants:
- A document key is never an Ed25519 identity key or credential key.
- Sign callers identify an identity, never a raw KeyId or private key.
- Secret key bytes never leave Core/Vault.
- Existing vaults and policy files retain their current meaning.
- Audit failure prevents a successful signing result.
- Verification cryptographic validity is distinct from identity/key trust status.
- No file paths or document contents are persisted in audit metadata.

## 2. Identity model

Add to Identity:
- document_signing_key: Option<KeyId> with serde(default)
- document_signing_key_history: Vec<KeyId> with serde(default)

For existing records, deserialize as None and empty history. Never infer a document key from signing_key, credential_signing_key, or either history.

New identity creation should provision a third independent ML-DSA-65 key. If generation or vault persistence fails, identity creation must fail atomically. Existing identity provisioning is explicit, authenticated, policy-checked and auditable.

## 3. Public Session API — proposed Rust shape

    pub struct DocumentSignature {
        pub identity_id: IdentityId,
        pub key_id: KeyId,
        pub algorithm: Algorithm,
        pub public_key: Vec<u8>,
        pub signature: Vec<u8>,
    }

    pub struct DocumentVerifyingKey {
        pub identity_id: IdentityId,
        pub key_id: KeyId,
        pub algorithm: Algorithm,
        pub public_key: Vec<u8>,
        pub lifecycle_status: KeyStatus,
    }

    impl Session {
        pub fn provision_document_signing_key(
            &mut self, identity_id: &IdentityId,
        ) -> Result<KeyId, CoreError>;

        pub fn rotate_document_signing_key(
            &mut self, identity_id: &IdentityId,
        ) -> Result<KeyId, CoreError>;

        pub fn identity_sign_document(
            &mut self, identity_id: &IdentityId, message: &[u8],
        ) -> Result<DocumentSignature, CoreError>;

        pub fn identity_document_verifying_keys(
            &self, identity_id: &IdentityId,
        ) -> Result<Vec<DocumentVerifyingKey>, CoreError>;
    }

These signatures are an API proposal, not a claim that all named types already exist. Adapt names to current public type conventions before implementation.

## 4. Signing execution order

1. Require unlocked, writable session.
2. Resolve identity and require Active status.
3. Resolve active document_signing_key from the identity record.
4. Verify key belongs to that identity and appears in document key history.
5. Require ML-DSA-65, Purpose::Sign and KeyStatus::Active.
6. Evaluate PolicyOperation::IdentityDocumentSign for the identity.
7. Unwrap/use the key only inside Core/Vault; never return secret bytes.
8. Sign exact caller-provided message bytes using the fallible ML-DSA API.
9. Construct bounded, versioned audit context with identity id, key id, algorithm and operation version only.
10. Append IdentityDocumentSigned using existing audit-chain semantics.
11. Persist atomically; only then return DocumentSignature.

No fallback to Ed25519 or credential signing. Any mismatch is a typed error.

## 5. Verification key resolution

Return only public keys bound to the requested identity's document key history. Do not resolve arbitrary key IDs supplied by Sign.

Return lifecycle status separately. A mathematically valid signature may be cryptographically valid while identity trust is unknown, revoked or historical. The caller must not collapse these states into one Boolean.

## 6. Policy and audit changes

Policy:
- Add PolicyOperation::IdentityDocumentSign.
- Canonical serialized id: identity_document_sign.
- Mark as identity-targeting.
- Update exhaustive matches, policy evaluation and serde round-trip tests.
- Existing policy files must deserialize and behave identically.

Audit:
- Add EventType::IdentityDocumentSigned with canonical id identity_document_signed.
- Preserve old serialized enum compatibility. Append variants; test old fixtures and hash-chain verification.
- Use bounded CBOR context with explicit version.
- Exclude path, filename, document bytes, signature bytes, public key bytes, secrets and passphrases.
- Omit document digest in v1 pending privacy/threat-model review.
- Audit append failure aborts signing and cannot return signature success.

## 7. Key lifecycle

Provision:
- Generate a fresh ML-DSA-65 key pair internally.
- Add key ID to document history and set active document key.
- Persist atomically with audit event.

Rotate:
- Generate a new independent key.
- Move old active key to historical status without deleting public verification material.
- Set new active key and append to history.
- Audit rotation with a dedicated event if supported; otherwise add a separate event rather than mislabeling a signing event.
- Never rotate credential or Ed25519 keys as a side effect.

Revoke:
- Preserve public material for historical verification, but mark lifecycle/revocation status.
- Define whether revoked keys can verify old signatures; expose status so application policy can decide.
- Never silently delete key history.

## 8. Migration and compatibility tests

Required tests:
1. Old vault fixture deserializes and unlocks; document key remains absent.
2. Old vault lock/reopen/unlock preserves absent document key.
3. Existing identity explicit provisioning creates a distinct ML-DSA-65 key.
4. New identity has three distinct key IDs with expected algorithms and purposes.
5. Credential issuance remains unchanged.
6. Ed25519 identity_sign remains unchanged.
7. Document sign rejects locked/read-only session, inactive identity, absent key, wrong algorithm, wrong purpose, non-active key, foreign key and denied policy.
8. Key material never appears in returned values, errors, logs or audit context.
9. Audit failure returns error and no signature success.
10. Rotation retains historical public verification keys and does not rotate other key roles.
11. Old audit fixtures deserialize and verify after the new event is introduced.
12. Old policy fixtures deserialize and evaluate identically.
13. New API rejects arbitrary key selection because caller cannot pass KeyId.
14. Tampered message/signature fails verification using Core ML-DSA verifier.

## 9. Rollback and downgrade

Do not claim downgrade safety until tested. Older binaries may reject or discard new identity fields when rewriting a vault. Define a schema-version gate or explicit minimum-reader version before enabling document keys in production. Safe rollback must not silently erase document key references or histories.

## 10. Maintainer decisions required

- Approve explicit identity key fields versus typed key-role abstraction.
- Approve automatic provisioning for new identities.
- Confirm existing Session error variants and public type names.
- Confirm audit enum serialization and append-only compatibility.
- Choose schema-version/downgrade strategy.
- Approve policy default behavior for the new operation.

## 11. Out of scope

This change does not define NQSIG v1, document hashing/canonicalization, trust roots, timestamps, external certificates, legal validity, PDF embedded signatures or UI behavior.
