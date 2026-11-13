# NEXUS-Q Sign backend scaffold

Rust-only application boundary aligned with Vault's Rust/Tauri 2 architecture.

## Status
Architectural scaffold only. The default provider is intentionally unavailable. Both sign and verify return `ProviderUnavailable` until the approved Core/Vault document-key custody APIs are integrated.

## Safety
- No private-key material in frontend-facing types.
- No fake cryptographic result or mock-success provider.
- Signing rejects empty identity references and prevents the sidecar from matching the source path.
- Provider contract is reserved for the approved Core/Vault custody boundary.
- No NQSIG serialization is implemented.

## Tests
Run `cargo test`.
