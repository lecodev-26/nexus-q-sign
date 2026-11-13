# NEXUS-Q Sign desktop application

The desktop client is a **Tauri 2** application with a **Svelte 5 + TypeScript + Vite** frontend and a Rust backend.

## Development

Install Node.js 22+ and Rust 1.90+, then install the frontend dependencies:

```sh
npm ci
npm run dev
```

Run the native application from this directory:

```sh
cargo tauri dev
```

Build the frontend and native application:

```sh
npm run test:i18n
npm run build
cargo tauri build
```

The Tauri configuration starts Vite on port 1420 and packages the production frontend from `dist/`.

## Frontend structure

- `src/App.svelte` — application shell and views.
- `src/lib/i18n/` — locale manifest, English base dictionary, Spanish and Catalan translations.
- `src/app.css` — shared NEXUS-Q visual foundation and Sign-specific layout.
- `public/assets/` — static brand assets.

English is the primary locale. To add a language, register its code and display name in `src/lib/i18n/locales.json`, add a dictionary with the same keys as `en.json`, and register it in `src/lib/i18n/index.ts`. The locale test enforces full key coverage.

## Native boundary

The frontend invokes explicit Tauri commands. Private signing material and unlocked signer state remain in Rust. Do not expose key seeds, encrypted key payloads, passwords, or signer objects through frontend responses.
