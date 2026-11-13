# AGENT.md — NEXUS-Q Sign

Project hand-off and mandatory operating rules for coding agents.

## Product
- Repository: https://github.com/lecodev-26/nexus-q-sign
- Website: https://nexus-q.link
- Current release: 0.1.0 (2026-11-13)
- Stack: Rust, Tauri 2, Svelte 5, TypeScript, Vite.
- Local-first detached document signing and verification using ML-DSA-65.
- English is the default UI language; Spanish and Catalan are supported.

## Product boundaries — never violate
1. Sign is a standalone application.
2. Never connect Sign to Vault or another NEXUS-Q app: no runtime API, IPC, sockets, shared backend/database/key store, synchronization, deep links or orchestration.
3. Sign owns its identities, encrypted keys, settings, configuration and history.
4. Never read, write or depend on Vault data directories.
5. Sharing brand assets and visual design is allowed; sharing runtime state is not.
6. Do not add process monitoring, background process enumeration, PID tracking or process-output polling.
7. Never claim legal validity, qualified signature status, verified human identity or external interoperability without independent evidence.

## Architecture
- `apps/desktop`: Tauri 2 application; Svelte 5 + TypeScript + Vite frontend; Rust backend commands.
- `crates/sign-core`: Sign-specific Rust domain logic.
- Keep cryptography and private signing material in Rust. The frontend receives only necessary public metadata and operation results.
- Use pinned `nexusq-core = 4.1.2` and `nexusq-ml-dsa = 4.1.2` dependencies as declared in the crate manifest. Do not modify upstream Core or Vault for Sign-specific work.
- Dedicated encrypted Sign identity/key store. Envelope design uses Argon2id v1.3 and XChaCha20-Poly1305; consult the implementation/design docs for exact parameters.
- SQLite history stores metadata only: never document contents, private keys, passphrases or signature blobs.
- Restrictive Unix permissions (directories 0700, files 0600 where applicable) and atomic writes.
- ML-DSA-65 signatures over a SHA-256 digest of exact document bytes. Detached, versioned `.nqsig` NQSIG v1 sidecar.
- Never alter original document bytes or silently overwrite a sidecar. Keep strict parser limits and fail-closed behavior.
- Verification distinguishes digest/integrity, mathematical signature validity and local identity recognition. A self-declared public key is not proof of identity.

## UX and localization
- English default; Spanish and Catalan translations must remain complete.
- Update all locale dictionaries for new UI strings and run `npm run test:i18n` from `apps/desktop`.
- Preserve NEXUS-Q visual identity and light/dark themes.
- Never show simulated success as real cryptographic signing/verification. UI state must reflect backend results.

## Security
- Never expose private keys, seeds, passphrases or decrypted key material to JavaScript.
- Never log secrets, document contents or unnecessary absolute paths.
- Do not weaken crypto parameters, storage permissions, parser limits or atomic-write guarantees without documented security review.
- Do not accept ambiguous verification as success. No cloud signing or external signing service.
- A valid signature does not by itself establish key ownership or legal validity.
- Do not set `crypto_ready` true merely because compilation/CI passed; require end-to-end runtime validation.

## Engineering procedure
Before editing:
1. Inspect `git status`, recent commits and relevant project docs.
2. Read design docs before changing NQSIG, identity/key custody or product boundaries.
3. Make the smallest change in the correct layer; preserve user changes.
4. Never introduce cross-app dependencies.

After editing:
1. Run focused tests.
2. For frontend changes run `npm run test:i18n`, `npm run check` and `npm run build` from `apps/desktop` as applicable.
3. For Rust changes run fmt, locked metadata, Clippy and tests where supported.
4. Review `git diff --check` and the final diff; ensure no credentials, secrets, local DBs, signing keys or build outputs are committed.
5. State exactly what passed and what could not be run. Never invent test results.

Useful commands (verify manifests/scripts exist first):
- `npm ci`, `npm run test:i18n`, `npm run check`, `npm run build` in `apps/desktop`.
- `cargo fmt --manifest-path crates/sign-core/Cargo.toml -- --check`
- `cargo metadata --locked --manifest-path crates/sign-core/Cargo.toml --format-version 1`
- `cargo clippy --locked --manifest-path crates/sign-core/Cargo.toml --all-targets -- -D warnings`
- `cargo test --locked --manifest-path crates/sign-core/Cargo.toml`
- Also check Tauri Rust manifest at `apps/desktop/src-tauri/Cargo.toml` when editing desktop backend.

## CI and releases
- `.github/workflows/build.yml` is manual-only via `workflow_dispatch`.
- Do not restore automatic `push`, `pull_request`, tag or scheduled triggers without explicit maintainer approval.
- Manual workflow validates frontend and Sign Core and builds Linux x86_64 (.deb/.AppImage), Windows x86_64 (.msi/.exe), macOS ARM64 (.dmg) and macOS Intel (.dmg). Artifacts expire after 14 days.
- CI artifacts are not automatically attached to GitHub Releases; upload release assets separately.
- Never create duplicate release assets or a new tag/release without explicit request. Inspect existing release assets first and independently verify uploads.
- CI build success is not runtime E2E proof. Test installation, identity create/unlock, signing, verification, history and persistence on each claimed OS.

## 0.1.0 delivery history
- Established Rust/Tauri 2 + Svelte 5/TypeScript/Vite app.
- English-first UI plus Spanish/Catalan; README and project docs in English; NEXUS-Q logo/banner.
- Repository made public, English description and search topics added, homepage set to `https://nexus-q.link`.
- Release `v0.1.0` published with platform installer artifacts.
- CI switched to manual-only to prevent automatic artifact generation.
- Previously confirmed release assets: `nexus-q-sign-linux-installers.zip`, `nexus-q-sign-macos-arm64-installer.zip`, `nexus-q-sign-macos-x64-installer.zip`, `nexus-q-sign-windows-installers.zip`, `NEXUS-Q.Sign_0.1.0_aarch64.dmg`, `NEXUS-Q.Sign_0.1.0_x64.dmg`, `NEXUS-Q.Sign_0.1.0_x64-setup.exe`, `NEXUS-Q.Sign_0.1.0_x64_en-US.msi`. This is a snapshot, not a guarantee for future releases.

## Known limitations
- Cross-platform end-to-end runtime validation remains separate from CI builds.
- NQSIG v1 is project-defined; do not claim third-party compatibility without interoperability tests.
- No PAdES, embedded PDF signing, qualified certificates, timestamp authority, cloud/remote signing, team workflow or bulk signing.
- Do not claim code signing/notarization unless verified for the artifact.
- Keep README, CHANGELOG, release notes and UI claims aligned with implementation.

## Key documents
Read as relevant: `README.md`, `CHANGELOG.md`, `RELEASE_0.1.0.md`, `PRODUCT_BOUNDARIES.md`, `NQSIG_FORMAT.md`, `IDENTITY_MODEL.md`, `KEY_CUSTODY_DESIGN.md`, `UX_UI_DESIGN.md`, `CORE_API_*`, `CORE_INTEGRATION_SPIKE.md`.

## Agent principles
- Work incrementally; ask before changing agreed product scope.
- Do not invent files, APIs, test results, release assets or runtime behavior.
- Prefer small, reviewable commits.
- Keep docs in English unless intended for Spanish-speaking contributors.
- Do not rewrite history to hide limitations. State uncertainty and the next verification step.
