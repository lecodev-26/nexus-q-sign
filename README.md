# NEXUS-Q Sign — development workspace

NEXUS-Q Sign es una aplicación de escritorio autónoma para crear y verificar firmas digitales detached. Su milestone de desarrollo es **0.1.0**.

## Decisión de producto

Sign funciona de forma independiente. No se conecta a NEXUS-Q Vault ni a otras aplicaciones NEXUS-Q. Mantiene su propio backend, almacenamiento, identidades, claves, configuración y ciclo de vida.

Puede reutilizar bibliotecas criptográficas Rust versionadas, como `nexusq-core`, compiladas dentro del propio proceso. Esto no implica servicios compartidos ni comunicación entre aplicaciones. La única continuidad de producto en la interfaz es la estética visual de Vault.

Consulta [PRODUCT_BOUNDARIES.md](PRODUCT_BOUNDARIES.md).

## Release target

La versión objetivo es **NEXUS-Q Sign 0.1.0**. No está publicada ni se considera lista para producción. Consulta [RELEASE_0.1.0.md](RELEASE_0.1.0.md).

## Desktop application

La aplicación Tauri 2 está en `apps/desktop/`. El crate privado `crates/sign-core/` proporciona ML-DSA-65 mediante `nexusq-core 4.1.2`, cifrado autenticado de semillas, almacenes separados para sobres cifrados y metadatos públicos NQID v1, y un `IdentityService` para las identidades locales. El signer desbloqueado permanece solo en Rust. La app conecta el flujo detached NQSIG v1: calcula SHA-256 en streaming, firma el manifiesto canónico, publica el sidecar junto al original mediante rename atómico sin reemplazo, y verifica digest, firma y reconocimiento local por separado. El frontend ofrece selección del documento y sidecar. Esta integración está escrita, pero su compilación y las pruebas end-to-end de esta iteración siguen pendientes de confirmación; NQSIG requiere además revisión independiente y validación de plataforma.

## Design prototype

Abre `preview.html` en un navegador. Es una referencia navegable con datos ficticios; no firma, verifica ni accede a claves.

## Documentación principal

- `PRODUCT_BOUNDARIES.md` — independencia entre productos y límites de reutilización de bibliotecas.
- `NQSIG_FORMAT.md` — propuesta técnica inicial del formato detached NQSIG v1 (pendiente de revisión).
- `RELEASE_0.1.0.md` — alcance, criterios de aceptación y estado del milestone.
- `UX_UI_DESIGN.md` — sistema visual y pantallas.
- `IDENTITY_MODEL.md` — modelo versionado de identidades y metadatos públicos.
- `apps/desktop/README.md` — estado técnico de la app.
- `crates/sign-core/` — adaptador Rust privado de Sign sobre ML-DSA-65.
- `CORE_INTEGRATION_SPIKE.md`, `KEY_CUSTODY_DESIGN.md`, `CORE_API_PROPOSAL.md`, `CORE_API_REVIEW.md`, `CORE_API_CHANGE_SPEC.md` — investigación histórica.
- `backend-scaffold/` — servicios de dominio experimentales, con proveedor fail-closed.
- `core-spike/` — spike criptográfico aislado.
- `assets/vault-reference.css` — referencia local del sistema visual de Vault.
- `assets/sign-preview.css` — extensiones visuales de Sign.
- `assets/` — activos de marca facilitados para Sign.

## Entorno inspeccionado

Desarrollo y pruebas actuales en Android/Termux ARM64. Esto no demuestra soporte de escritorio para Windows, macOS o Linux. No se ha modificado el repositorio de Vault ni el código fuente de Core.

## Estado de seguridad

Sign Core contiene el adaptador ML-DSA-65, cifrado autenticado de semillas, almacenamiento separado de sobres cifrados y metadatos públicos NQID v1, y el servicio coordinador de identidades. Tauri conecta creación, listado, desbloqueo, bloqueo y eliminación; el signer solo permanece en memoria Rust. El backend desktop ya contiene comandos de firma y verificación NQSIG: el sidecar se crea con temporal exclusivo y publicación atómica sin reemplazo; el original se vuelve a leer para detectar cambios; la verificación separa digest documental, validez matemática y reconocimiento local. La compilación del backend desktop y las pruebas end-to-end de esta integración están pendientes de confirmación. No hay empaquetado de escritorio ni revisión independiente del formato. No se debe presentar 0.1.0 como lista para producción.
## CLI temporal de integración

Hay un ejecutable interactivo temporal para ejercitar el mismo `IdentityService` y las operaciones NQSIG del crate sin abrir Tauri. No es una interfaz de producción ni forma parte del alcance publicado de 0.1.0. Consulta `crates/sign-core/CLI_TEMPORAL.md` y ejecútalo con:

```sh
cargo run --offline --manifest-path crates/sign-core/Cargo.toml --bin nqs-cli -- ~/nexus-q-sign-cli-data
```

Usa un directorio de datos de prueba separado. La compilación Rust de la CLI se ha confirmado en Termux ARM64 (`cargo check --offline --bin nqs-cli`). El flujo funcional end-to-end aún no está confirmado y sigue pendiente antes de considerar superadas las pruebas de integración.
