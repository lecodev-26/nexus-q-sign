# Core API review — findings and decisions

Date: 2026-11-13
Target: NEXUS-Q Core 4.1.2
Scope: read-only review; no Core or Vault source files modified.

## Confirmed source facts

1. `Identity.signing_key` is documented in `identity/record.rs` as the key that signs documents, but `Session::create_identity` explicitly creates it as Ed25519 and `Session::identity_sign` rejects any algorithm other than Ed25519. The current implementation is therefore not the required ML-DSA-65 document-signing path.
2. `credential_signing_key` is generated as ML-DSA-65 and used by the credential issuance path. It must not be silently reused for detached document signatures.
3. `Purpose::Sign` is a stable serialized identifier (`sign`) and is shared by multiple signature use cases. Adding a new purpose would affect serialization and key compatibility. For the first implementation, keep `Purpose::Sign` and enforce the document-specific boundary through identity binding plus a dedicated policy operation.
4. `PolicyOperation` is a closed enum. A new operation must be added to its canonical string mapping, identity-targeting classification, policy evaluation, serialization/round-trip tests, and every exhaustive match.
5. `EventType` is a serialized enum and `AuditEvent` stores `event_type`, `actor`, `subject`, `outcome`, and opaque byte `context`. A document-sign event can use the existing structured event envelope; the context should be a bounded, versioned CBOR record with only non-secret metadata.
6. `Session` already has typed errors for identity, key lifecycle, policy, PQ signing and audit failures. The proposed API should add only the missing precise error cases if no existing variant expresses the failure safely.
7. `Session::unlock` already backfills historical key-id vectors. Any document-key migration must preserve old vaults without assigning a credential or Ed25519 key as a document key.

## Recommended v1 decisions

- Add `document_signing_key: Option<KeyId>` and `document_signing_key_history: Vec<KeyId>` to `Identity`, both with `serde(default)`.
- Keep `Purpose::Sign` for serialized compatibility. Document key use is authorized only by the dedicated `IdentityDocumentSign` policy operation and explicit identity/key checks.
- Add `PolicyOperation::IdentityDocumentSign` with canonical id `identity_document_sign`, marked as identity-targeting. Do not make it a generic key-targeted `Sign` operation.
- Add `EventType::IdentityDocumentSigned` with canonical id `identity_document_signed`. Append new enum variants rather than reordering existing variants, and test old audit segment fixtures before accepting the change.
- New identities get a third, independent ML-DSA-65 key for documents. Existing identities remain without a document key until an explicit, auditable provisioning action creates one.
- Add dedicated provisioning and rotation APIs. Do not overload `rotate_identity_key`, which currently rotates Ed25519 identity signing and credential ML-DSA keys together.
- The signing API chooses the active document key internally. The caller cannot pass an arbitrary KeyId. It checks identity Active, session writable/unlocked, key ownership, ML-DSA-65, Sign purpose, Active status and policy before unwrapping.
- Verification resolves a key only from that identity's document-signing history and returns key lifecycle/identity status separately from cryptographic validity.

## Audit context proposal

Use a versioned bounded CBOR structure, for example `DocumentSignAuditContextV1`, containing:
- `identity_id`
- `document_key_id`
- `algorithm` (`mldsa65`)
- `digest_algorithm` (once NQSIG v1 fixes it)
- `manifest_version` (once NQSIG v1 fixes it)

Do not persist source file paths, document bytes, document contents, signatures, public-key blobs, passphrases or private material in audit context. Decide whether a document digest is acceptable metadata in the threat model before adding it.

## Migration and compatibility gates

- Old vault fixture -> deserialize -> unlock -> lock -> reopen -> unlock; document key must remain absent.
- New vault -> create identity -> three distinct key IDs and correct algorithms/purposes.
- Old identity -> explicit provision -> document key appears; no credential key reassignment.
- New vault with document key -> downgrade behavior must be explicitly defined. Older binaries may reject unknown schema or lose unknown fields on rewrite; do not claim downgrade safety without tests.
- Audit log fixture -> read/verify after appending the new EventType variant; confirm enum encoding stability.
- Policy fixtures -> old policy documents still deserialize and evaluate identically.

## Remaining maintainer decisions

1. Whether the identity model remains explicit fields or evolves to typed key roles. For v1, explicit fields are easier to review and safer than a broad refactor.
2. Whether new identities should provision document keys automatically or only on first use. Recommendation: provision during identity creation once the API is approved, with an explicit migration path for existing identities.
3. Whether document digests belong in audit metadata. Recommendation: omit in v1 unless a concrete audit requirement outweighs correlation/privacy risk.
4. Exact audit write semantics. Follow existing fail-closed session behavior; a failed audit write must prevent persistence and must not return a successful signature result.

## Non-goals

This review does not define NQSIG v1 serialization, document canonicalization, digest selection, trust policy, or legal validity. Those require a separate format specification and review.
