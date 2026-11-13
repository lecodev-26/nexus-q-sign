# Backend scaffold — implementation note

**Status:** Rust scaffold created and tested on Termux. Not production-ready.

## Structure
- `domain.rs`: document, identity reference, sidecar artifact and verification types.
- `error.rs`: typed domain errors with safe user-facing messages.
- `provider.rs`: `DocumentSigningProvider` boundary; default `UnavailableProvider` fails closed.
- `service.rs`: input validation and service orchestration.

## Verified
`cargo test` in `backend-scaffold/`: 4 passed, 0 failed.

Tests prove:
1. Signing cannot succeed while the Core/Vault provider is unavailable.
2. Verification cannot claim validity while the provider is unavailable.
3. The sidecar cannot target the same path as the original.
4. An empty identity reference is rejected.

## Explicitly not implemented
- Tauri commands or UI wiring.
- Core/Vault integration or private-key access.
- NQSIG v1 encoding, hashing, canonicalization or atomic sidecar writing.
- Real document verification, identity listing, history or reports.

## Next gate
Review and approve the dedicated Core/Vault document-key API proposal. Only then implement a provider against that API, with tests for identity ownership, key lifecycle, policy enforcement, audit events, tamper detection and backward-compatible vault schema migration.
