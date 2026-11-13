# CLI temporal de NEXUS-Q Sign

Este binario sirve como harness manual para ejercitar el backend Rust sin abrir Tauri. Reutiliza `IdentityService`, `DocumentSigner`, el formato NQSIG v1 y la verificación ML-DSA-65 del crate `nexus-q-sign-core`.

## Compilar y ejecutar en Termux

```sh
cd ~/nexus-q-sign-design
cargo run --offline --manifest-path crates/sign-core/Cargo.toml --bin nqs-cli -- ~/nexus-q-sign-cli-data
```

El directorio indicado es independiente del directorio de datos de la app. No uses datos reales ni contraseñas habituales: esta CLI es temporal y la entrada de contraseña se lee desde stdin (la terminal puede mostrar lo que escribes).

## Secuencia de prueba

1. `create Prueba local` — crea identidad y almacena metadatos + clave cifrada.
2. `list` — enumera identidades locales.
3. `unlock <id>` — desbloquea y mantiene el firmante solo en memoria durante esta ejecución.
4. `inspect /ruta/documento.bin` — calcula SHA-256 sin modificar el original.
5. `sign /ruta/documento.bin` — genera `.nqsig` sin sobrescribir sidecars existentes.
6. `verify /ruta/documento.bin` — debe devolver `valid_and_recognized`.
7. Modifica una copia o el documento de prueba y vuelve a verificar: debe devolver `document_changed`.
8. `lock`, `session`, `delete <id>` y `quit`.

Los comandos aceptan rutas sin espacios en esta primera CLI. La verificación rechaza sidecars que sean enlaces simbólicos, limita su lectura a 65.536 bytes y vuelve a comprobar el documento después de la verificación criptográfica. La firma y la verificación comparan tamaño, fecha de modificación e identidad del archivo (dispositivo/inode en Unix) para detectar cambios concurrentes; estas comprobaciones reducen riesgos de carrera, pero no sustituyen una revisión de seguridad específica del sistema de archivos.

El harness no es una interfaz de producción, no forma parte del contrato público de NEXUS-Q Sign y no reemplaza las pruebas de Tauri ni las pruebas de seguridad. Al salir, el firmante en memoria se descarta. La contraseña se introduce por stdin y puede mostrarse en la terminal.

