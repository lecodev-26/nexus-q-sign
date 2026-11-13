# Changelog

All notable changes to NEXUS-Q Sign are documented here.

## [0.1.0] — 2026-11-13

First public release of the standalone NEXUS-Q Sign desktop application.

### Added
- Rust + Tauri 2 desktop application with Svelte 5, TypeScript and Vite.
- English default interface with Spanish and Catalan translations.
- Local identity and encrypted private-key storage.
- Detached document signing and verification using ML-DSA-65 and SHA-256.
- Versioned `.nqsig` sidecar; original documents remain unchanged.
- Local SQLite metadata history.
- Native packaging for Linux x86_64, Windows x86_64, macOS Apple Silicon and Intel.
- English documentation, NEXUS-Q branding and public GitHub release.

### Security and limitations
- Sign is independent of Vault and other NEXUS-Q apps; no runtime connection or shared storage.
- Private signing material remains in Rust, not the frontend.
- No cloud signing, PAdES, qualified certificates, timestamp authority or bulk signing.
- Cryptographic verification does not establish legal validity or human identity.
- NQSIG v1 external interoperability is not guaranteed.
- CI builds do not replace end-to-end installation and runtime testing on each OS.

### Release
- [GitHub v0.1.0](https://github.com/lecodev-26/nexus-q-sign/releases/tag/v0.1.0)
- CI is manual-only (`workflow_dispatch`); pushes, pull requests and tags no longer trigger builds.
