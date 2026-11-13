# NEXUS-Q product boundaries — Sign 0.1.0

## Decisión aprobada — 2026-11-13

NEXUS-Q Sign es una aplicación autónoma. NEXUS-Q Vault y las demás apps NEXUS-Q no se conectan con Sign en tiempo de ejecución.

La continuidad entre productos tiene dos ámbitos deliberadamente limitados:
- Identidad visual del frontend coherente con Vault.
- Reutilización de bibliotecas criptográficas Rust publicadas, como `nexusq-core`, enlazadas y compiladas dentro de cada aplicación.

Reutilizar una biblioteca no crea comunicación entre aplicaciones. No se comparten procesos, sesiones, almacenes, claves, bases de datos, endpoints ni estado en ejecución.

## Consecuencias para Sign

- Sign tiene su propio ciclo de vida, configuración y almacenamiento local.
- Sign crea y administra sus propias identidades y claves privadas dentro de su propio almacén cifrado.
- Sign no abre, desbloquea, modifica ni depende de un Vault existente.
- Sign no llama a una API, proceso, socket, CLI, deep link ni IPC de Vault.
- Sign no lee ni escribe datos privados de otras aplicaciones NEXUS-Q.
- Sign no necesita que Vault esté instalado o ejecutándose.
- Los formatos de exportación/importación, si se añaden, serán explícitos, documentados y opt-in; no constituyen sincronización entre apps.
- No se copiarán claves privadas ni almacenes entre aplicaciones.
- No existe un backend compartido como servicio. La lógica criptográfica se incorpora como biblioteca dentro del proceso de Sign.
- No se cambia el repositorio ni la instalación de Vault para desarrollar o ejecutar Sign.

## Biblioteca criptográfica

Sign incorpora `nexusq-core` como dependencia Rust versionada, compilada dentro de su propio ejecutable. La dependencia no se ejecuta como daemon ni requiere que otra aplicación esté activa.

La integración inicial se limita al adaptador ML-DSA-65 de `nexusq-core`:
- Generación de claves con el CSPRNG del sistema.
- Importación de una semilla privada de 32 bytes desde la custodia propia de Sign.
- Firma y verificación ML-DSA-65.
- Sin reutilizar modelos de identidad, sesiones, almacenes ni APIs de Vault.
- Sin exportar la semilla privada a la interfaz frontend.

La versión de dependencia se fija exactamente en Cargo y debe quedar registrada en `Cargo.lock`. No se utilizarán dependencias Git con autenticación implícita.

## Qué sí puede reutilizarse

- Bibliotecas Rust criptográficas versionadas, integradas en proceso.
- Como referencia visual, estilos, tokens, patrones de interacción y activos de marca autorizados.
- La copia local de la hoja de estilos de Vault sirve como referencia visual; Sign mantiene su propio código de aplicación, estado, persistencia y backend.

## Pruebas de independencia obligatorias

- Sign arranca, crea su almacén, se bloquea y se desbloquea sin Vault instalado.
- Sign funciona con Vault cerrado y sin procesos/servicios de Vault.
- Ningún test de Sign necesita el directorio de datos de Vault.
- No existen dependencias de runtime, endpoints, IPC, sockets, deep links ni rutas privadas de Vault.
- Los datos de Sign se guardan en su propio directorio de aplicación.
- Desinstalar o borrar los datos de Vault no afecta a Sign; desinstalar o borrar los datos de Sign no afecta a Vault.

## Estado

Esta decisión sustituye cualquier propuesta anterior de integrar Sign con la API de identidad/custodia de Vault. Las bibliotecas criptográficas compartidas son dependencias de código, no una integración entre aplicaciones.
