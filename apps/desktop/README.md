# NEXUS-Q Sign Desktop 0.1.0

Aplicación autónoma de escritorio basada en Tauri 2, con el sistema visual de NEXUS-Q Vault como referencia.

## Independencia entre aplicaciones

- No se conecta a Vault ni a ninguna otra aplicación NEXUS-Q.
- No comparte sesiones, almacenes, claves, bases de datos, procesos, IPC ni servicios.
- Mantiene su propio almacenamiento local, identidades, claves y configuración.
- Puede enlazar bibliotecas criptográficas Rust como dependencias compiladas dentro del proceso.
- Solo comparte con Vault el lenguaje visual del frontend.
- No requiere que Vault esté instalado o abierto.

## Estado actual

- Shell Tauri 2: creado.
- Interfaz inicial: resumen, firma, verificación, identidades e historial.
- Hoja de estilos base: copia local usada como referencia visual.
- Selector nativo de archivos: implementado.
- Inspección de documento y SHA-256 en Rust: implementados.
- Límite de tamaño de documento: 1 GiB.
- Crate privado `nexus-q-sign-core`: creado en `../../crates/sign-core`.
- Adaptador ML-DSA-65: implementado sobre `nexusq-core = 4.1.2`, con versión exacta y activación explícita de `zeroize` para la implementación ML-DSA subyacente.
- El adaptador expone generación/importación de semilla, firma y verificación; no expone exportación de semilla privada.
- Firma y verificación documental NQSIG v1: comandos Tauri `sign_document` y `verify_document` implementados y conectados al frontend; compilación de la app y flujo end-to-end pendientes de confirmación.
- La firma genera un sidecar detached `.nqsig` sin sobrescribir; calcula SHA-256 en streaming y vuelve a comprobar el documento tras firmar.
- La verificación distingue documento alterado, firma inválida, sidecar malformado, identidad reconocida e identidad desconocida. Rechaza sidecars simbólicos y compara la identidad del archivo abierto con sus metadatos iniciales.
- Almacén cifrado de semillas y metadatos NQID v1: implementados en Sign Core.
- Servicio de identidades: crea, lista, desbloquea internamente y elimina identidades; Tauri inicializa el servicio en el directorio privado de datos de Sign.
- Comandos Tauri conectados: `create_identity`, `list_identities`, `unlock_identity`, `lock_identity`, `identity_session`, `delete_identity`.
- Pantalla Identities: formulario de creación, listado con huella de clave, desbloqueo con contraseña, estado de sesión y bloqueo explícito.
- Historial local SQLite en `history.sqlite3`, administrado por Sign Core y conectado a Tauri (`list_history`, `clear_history`); registra firma y verificaciones con nombre base del documento, digest, ID de identidad, fecha y estado. No persiste contenido ni rutas completas; límite de 10.000 entradas.
- Pantalla Historial conectada a la base local, con listado y borrado explícito.
- El signer desbloqueado permanece exclusivamente en estado Rust; el webview solo recibe metadatos públicos. Al bloquear o destruir el estado de la app, el signer se descarta.
- Se activa explícitamente `zeroize` en ML-DSA para limpiar el estado secreto de la clave subyacente al destruirla; no implica protección integral frente a malware, volcados de memoria o copias temporales del runtime.
- NQSIG v1: especificación interna cerrada y codec binario/CBOR estricto implementado en Sign Core y conectado a los comandos Tauri de firma/verificación. Pruebas añadidas; ejecución end-to-end y revisión independiente pendientes.

La interfaz invoca los comandos Rust reales de firma y verificación; no simula resultados. `crypto_ready` permanece en `false` hasta confirmar compilación desktop, pruebas end-to-end y revisión de seguridad.

## Pruebas y validación

Validaciones confirmadas en Termux ARM64:
- `cargo fmt --check` para Sign Core y Tauri: correcto.
- `node --check apps/desktop/ui/app.js`: correcto.
- `cargo metadata --offline` para la app desktop: correcto.
- `cargo build --offline --bin nqs-cli`: correcto.
- `cargo check --offline --bin nqs-cli`: correcto, sin warnings.

La prueba unitaria específica del historial SQLite ha pasado (1/1): escritura, reapertura, persistencia y validación de entradas. La compilación completa de Tauri y la suite total siguen pendientes.

Pendiente de resultado confirmado:
- `cargo test --offline --bin nqs-cli`: ejecución iniciada; no se consultará su proceso ni se afirmará un resultado sin salida final.
- `cargo check --offline --manifest-path apps/desktop/Cargo.toml`: ejecución iniciada; compilación desktop no confirmada.
- Flujo funcional completo de CLI/Tauri y revisión independiente de NQSIG.

Esto no equivale a validar una compilación de escritorio empaquetada ni compatibilidad multiplataforma.

## Desarrollo

Requiere Rust 1.90+, dependencias de sistema de Tauri 2 y su CLI.

```sh
cargo check
cargo test
```

La interfaz estática se encuentra en `ui/`. El crate de dominio criptográfico está en `../../crates/sign-core/`.
