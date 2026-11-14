# Linux blank Tauri window caused by Fontconfig and WebKitGTK

**Documented:** 2026-11-14  
**Reproduced and fixed in:** NEXUS-Q Sign (Tauri 2 + Rust + Svelte)  
**Related precedent:** NEXUS-Q Vault  
**Observed environment:** Linux x86_64, Wayland, WebKitGTK 2.52.6, Mesa 25.2.8, Intel Alder Lake-N

## Summary

On the affected machine, a Tauri application started but its window was black or failed to render the web interface. The identified cause was not in the Svelte components or Vite build: the system font catalogue was exceptionally large, and Fontconfig font discovery affected initialization of the WebKitGTK engine used by Tauri on Linux.

The system exposed approximately **2,183 unique font families**. Running the application with an isolated Fontconfig configuration restricted to DejaVu families restored rendering. The mitigation was added to NEXUS-Q Sign's Rust startup path and validated with both the compiled application and its AppImage.

> This is the confirmed cause in the environment described here, not a universal explanation for every black Tauri window. Diagnose the affected system before applying this workaround elsewhere.

## Symptoms

- The Tauri window opens, but its web content is black or blank.
- The frontend builds without errors.
- TypeScript/Svelte checks and the Vite build may pass normally.
- The issue is observed on Linux/WebKitGTK and may not reproduce on Windows or macOS.

## Identified technical cause

Tauri 2 uses WebKitGTK to render its interface on Linux. On the affected machine, Fontconfig exposed a catalogue of approximately 2,183 font families. Enumerating/resolving that catalogue during WebKitGTK initialization caused the rendering failure observed in this environment.

The evidence did not point to incorrect Vite asset paths, Svelte components, or a frontend packaging failure. It was also not identified as a DMA-BUF or GPU failure: restricting the Fontconfig catalogue available to the application session restored the interface.

## How to diagnose another machine

1. Confirm that the issue occurs on Linux and that the Tauri window opens without rendering its interface.
2. Inspect application startup logs and WebKitGTK logs.
3. Check how many font families Fontconfig discovers. For example:

   ```bash
   fc-list : family | sort -u | wc -l
   ```

4. Check whether a custom configuration is selected through `FONTCONFIG_FILE`:

   ```bash
   printf 'FONTCONFIG_FILE=%s\\n' "${FONTCONFIG_FILE:-<not set>}"
   ```

5. Compare behavior using a temporary/restricted Fontconfig configuration without changing system-wide fonts.
6. If rendering returns after restricting the catalogue, the Fontconfig/WebKitGTK hypothesis is strengthened. Record the distribution, WebKitGTK, Fontconfig and Mesa versions, GPU, and graphical session.

The 500-family threshold used by NEXUS-Q Sign is a defensive implementation choice, not an official WebKitGTK limit.

## Mitigation implemented in NEXUS-Q Sign

**Implementation:** `apps/desktop/src/main.rs`

The application includes a Linux-specific mitigation:

- Detects unusually large font catalogues.
- When the configured threshold (>500 families) is exceeded, prepares an isolated, reduced Fontconfig configuration in the application's user-space/cache area.
- Makes DejaVu families available to WebKitGTK for that application session.
- Does not modify or remove system fonts.
- Does not require administrator privileges.
- Respects an existing `FONTCONFIG_FILE` rather than overriding the user's explicit environment configuration.
- Is Linux-only and does not change Windows or macOS behavior.

The test log contained a message equivalent to:

```text
NEXUS-Q Sign: limited WebKit Fontconfig catalogue from 2183 to DejaVu families for this session.
```

The configuration must be applied before Tauri initializes/creates the WebView. Applying Fontconfig settings after window creation is too late for this class of issue.

## Validation performed

The following checks passed for NEXUS-Q Sign:

- Frontend: i18n dictionary tests, Svelte/TypeScript check, and Vite build.
- Rust: `cargo fmt --check` and `cargo check --locked`.
- The locally compiled native application rendered its interface.
- The local AppImage launched and the user confirmed that its interface rendered correctly.
- Logs confirmed that the Fontconfig catalogue was restricted after detecting 2,183 families.

Validation of a local AppImage must not be confused with validation of every artifact later produced by CI or published. Each distributed package should be tested in the affected environment.

## Reusing this approach in other Tauri applications

When another Tauri application shows a blank Linux window:

1. Do not immediately assume the cause is Svelte, Vite, or Tauri itself.
2. Check the number of Fontconfig families and the WebKitGTK version.
3. Review this document and the implementation in `apps/desktop/src/main.rs`.
4. Adapt the mitigation to the new application's initialization lifecycle; do not copy it blindly or force it on every system.
5. Keep the configuration isolated per application/session and do not modify `/etc/fonts` or global system fonts.
6. Respect `FONTCONFIG_FILE` and other explicit user configuration.
7. Test the actual package (AppImage, DEB, etc.), not only `npm run dev` or IDE execution.
8. Also test on a Linux machine with a normal-sized font catalogue to ensure the usual behavior is unaffected.

## References

- NEXUS-Q Sign mitigation: `apps/desktop/src/main.rs`.
- Related NEXUS-Q Vault diagnosis: `docs/diagnostics/2026-11-09-linux-webkitgtk-blank-window.md` in the `nexus-q-vault` repository.
- Sign fix commit: `80a6650` (`fix(linux): limit oversized Fontconfig catalogue for WebKitGTK`).

---

Keep this document as a diagnostic reference. If the issue reappears with different symptoms, collect logs and environment versions before concluding that Fontconfig is responsible.
