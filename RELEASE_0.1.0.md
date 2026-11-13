# NEXUS-Q Sign 0.1.0 — release baseline

**Estado:** objetivo de desarrollo; no publicado ni listo para producción.  
**Versión:** 0.1.0  
**Fecha:** 2026-11-13

## 1. Propósito

0.1.0 será la primera preview funcional de NEXUS-Q Sign como aplicación autónoma para firma detached y verificación local. El objetivo es demostrar el flujo completo con ML-DSA-65, un almacén cifrado propio y el formato NQSIG v1.

## 2. Independencia de producto (requisito obligatorio)

Sign es independiente de Vault y de las demás aplicaciones NEXUS-Q. Solo comparte la estética del frontend.

- No hay conexión entre aplicaciones, integración en tiempo de ejecución, API, IPC, sockets, CLI, deep links, sincronización ni backend compartido.
- Sign mantiene su propio almacén cifrado, identidades, claves, configuración e historial.
- No lee ni modifica almacenes de Vault.
- Vault no es requisito para instalar, ejecutar, desbloquear ni usar Sign.
- La lógica criptográfica se ejecuta dentro del proceso de Sign mediante una biblioteca Rust revisada e integrada como dependencia, sin servicio externo.
- Los datos de Sign se guardan en el directorio privado propio de la aplicación.

## 3. Alcance 0.1.0

### Incluido (P0)
1. Standalone Tauri 2 desktop application with a Svelte 5 + TypeScript + Vite frontend and the NEXUS-Q visual identity.
2. Inicialización, apertura, bloqueo y desbloqueo del almacén local cifrado propio de Sign.
3. Creación y gestión básica de identidades Sign con claves ML-DSA-65 dedicadas a firma de documentos.
4. Importación/selección local de documentos mediante diálogos nativos.
5. Cálculo de SHA-256 en streaming sin modificar el original.
6. Formato detached `.nqsig` versionado, acotado y determinista.
7. Firma local real ML-DSA-65.
8. Verificación local de firma y correspondencia del documento.
9. Detección de documento alterado, sidecar inválido, formato no soportado e identidad desconocida.
10. Escritura atómica del sidecar, sin sobrescritura silenciosa.
11. Historial local SQLite de metadatos, sin almacenar documentos, rutas completas ni claves privadas.
12. Informe de verificación exportable.
13. Estados de error, bloqueo, progreso y éxito sin simular resultados.
14. Interface built with Svelte 5, TypeScript and Vite; English by default with Spanish and Catalan options, light/dark themes and basic accessibility.

### Fuera de alcance
- Conexión o integración con Vault u otras aplicaciones NEXUS-Q.
- Sincronización entre productos o almacenes compartidos.
- Firma PDF incrustada / PAdES.
- Firma cualificada, certificados o afirmaciones de validez legal.
- Autoridad de sellado de tiempo.
- Cuentas cloud, firma remota o sincronización.
- Firma masiva, equipos y flujos de aprobación.
- Compatibilidad multiplataforma no validada en cada sistema.

## 4. Requisitos de seguridad

- Claves privadas protegidas por el almacén cifrado independiente de Sign.
- Ninguna clave privada, semilla o passphrase pasa al frontend.
- ML-DSA-65 para firma documental; no reutilizar claves Ed25519 o claves destinadas a credenciales de otros productos.
- Desbloqueo explícito y bloqueo automático configurable si se implementa de forma segura.
- Derivación de claves y cifrado autenticado con parámetros documentados y versionados.
- Comparaciones y errores de verificación sin aceptar estados ambiguos.
- El sidecar no es un ancla de confianza por sí solo: la clave pública debe vincularse a una identidad local o reportarse como desconocida.
- Digest del documento calculado sobre los bytes exactos del original.
- Sidecar con límites estrictos de tamaño, campos, versión y asignaciones de memoria.
- Escritura atómica; no sobrescribir sin consentimiento explícito.
- No registrar secretos, contenido documental ni rutas absolutas innecesarias.
- Diferenciar validez criptográfica, reconocimiento local de identidad y validez legal.

## 5. Pruebas obligatorias

### Formato y criptografía
- Vectores conocidos ML-DSA-65 y tamaños esperados.
- Round-trip NQSIG v1 y bytes canónicos estables.
- Rechazo de versión desconocida, truncamiento, exceso de tamaño, campos duplicados y entradas malformadas.
- Firma válida para archivo intacto.
- Rechazo tras modificar un byte del documento.
- Rechazo de firma alterada y clave pública incorrecta.
- Rechazo de sidecar truncado o manipulado.

### Almacén independiente
- Crear, cerrar, reabrir, desbloquear y bloquear almacén.
- Passphrase incorrecta no desbloquea.
- Datos cifrados no revelan claves privadas.
- Rotación/revocación y verificación de firmas históricas según política definida.
- Sign funciona sin Vault instalado, abierto o accesible.
- Ninguna prueba depende del directorio de datos de Vault.

### Archivos y UX
- Original permanece byte por byte idéntico.
- Archivo grande dentro del límite y rechazo por encima del límite.
- Sidecar escrito atómicamente y colisión de nombre controlada.
- Errores de permisos, disco lleno, ruta inválida y archivo corrupto.
- Pruebas de teclado, tema claro/oscuro y lector de pantalla básico.

## 6. Criterios de aceptación

0.1.0 solo puede etiquetarse como preview funcional cuando todos los P0 están implementados, las pruebas de seguridad pasan, NQSIG v1 está revisado y congelado, no hay proveedor simulado, el almacén independiente está probado y existe al menos un paquete de escritorio validado en la plataforma declarada.

Hasta entonces, etiquetar como desarrollo interno `0.1.0-dev`. No presentar el prototipo ni el scaffold actual como firma funcional.

## 7. Secuencia de trabajo

1. Congelar el límite de independencia de producto.
2. Especificar NQSIG v1 (baseline interna cerrada), validar parser/encoder con vectores y revisión independiente.
3. Seleccionar y revisar la biblioteca ML-DSA-65 que se integrará directamente en Sign.
4. Diseñar e implementar el almacén cifrado propio de Sign.
5. Implementar firma/verificación y escritura detached atómica.
6. Completar historial e informes.
7. Endurecer seguridad, UX, accesibilidad y pruebas.
8. Validar empaquetado en cada plataforma que se anuncie.

## 8. Estado real a 2026-11-13

- Diseño visual basado en Vault: preparado.
- Prototipo UI: preparado; solo datos ficticios.
- Shell Tauri 2: creado.
- Selector de archivos y SHA-256 streaming en Rust: implementados.
- Pruebas desktop-shell ejecutadas en Termux ARM64: 3/3 correctas.
- Spike aislado ML-DSA-65 contra Core 4.1.2: 1/1 correcto; no es implementación integrada ni crea almacén Sign.
- Backend scaffold: 4/4 tests correctos; proveedor fail-closed.
- Almacén cifrado independiente Sign: implementado en Sign Core; integración Tauri de creación, listado, desbloqueo, bloqueo y eliminación realizada. Validación completa de compilación pendiente.
- Sesión de identidad: signer mantenido solo en Rust; la UI recibe metadatos públicos. Zeroization activada en la implementación ML-DSA subyacente.
- Firma y verificación documental: comandos Tauri conectados al flujo NQSIG v1. La firma calcula SHA-256 en streaming, autentica el manifiesto con ML-DSA-65 y publica el sidecar mediante rename atómico sin reemplazo. La verificación separa integridad, validez matemática y reconocimiento local, y vuelve a calcular el digest tras la operación criptográfica para detectar cambios concurrentes. Añadida prueba desktop de publicación sin sobrescritura y limpieza del temporal. Compilación y pruebas end-to-end de esta integración pendientes de confirmación.
- NQSIG v1: baseline interna cerrada; codec binario/CBOR determinista y seis pruebas unitarias en Sign Core, incluida firma/verificación criptográfica del manifiesto. La ejecución completa de las pruebas y la revisión independiente siguen pendientes.
- Historial SQLite: módulo Sign Core, comandos Tauri de listado/borrado y pantalla UI conectados; prueba unitaria específica de persistencia confirmada (1/1). Compilación completa de Tauri y suite total pendientes.
- Build empaquetado de escritorio: pendiente.
- Release 0.1.0: no publicada.
