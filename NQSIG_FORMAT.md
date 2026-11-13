# NQSIG v1 — especificación interna del sidecar detached

**Producto:** NEXUS-Q Sign 0.1.0  
**Estado:** baseline de formato cerrada para implementación y pruebas internas; no implica interoperabilidad externa ni revisión criptográfica independiente.  
**Formato:** sidecar binario `.nqsig`; el documento original nunca se incorpora ni modifica.

## 1. Propósito y límites

NQSIG transporta una firma detached, el digest del documento y la clave pública necesaria para verificar matemáticamente la firma. No transporta el documento, una identidad legal, un certificado, una prueba de identidad ni un sello de tiempo confiable.

La confianza se determina localmente en NEXUS-Q Sign. Una firma puede ser matemáticamente válida y tener identidad desconocida. Solo se reconoce localmente cuando los tres valores `identity_id`, `key_id` y `public_key` coinciden exactamente con un registro local de Sign. No se confía en nombres, rutas o metadatos declarados por el sidecar.

0.1.0 no implementa rotación, revocación ni certificados. Si el registro local ya no existe o la clave no coincide, el firmante se informa como desconocido; no se inventa un estado de revocación.

## 2. Parámetros criptográficos fijos

| Parámetro | Valor |
|---|---|
| Firma | ML-DSA-65, FIPS 204, pure mode |
| Clave pública codificada | 1.952 bytes exactos |
| Firma codificada | 3.309 bytes exactos |
| Digest documental | SHA-256, 32 bytes |
| Identificador de algoritmo de firma | unsigned integer `1` = ML-DSA-65 |
| Identificador de algoritmo digest | unsigned integer `1` = SHA-256 |

No existe negociación de algoritmos en v1. Cualquier otro identificador se rechaza. No es HashML-DSA: ML-DSA-65 pure mode firma el mensaje canónico completo definido en §5.

## 3. Framing binario

El archivo es la concatenación exacta de:

| Offset | Campo | Tamaño | Codificación |
|---:|---|---:|---|
| 0 | Magic | 8 bytes | ASCII `NQSIG\r\n\x1A` |
| 8 | Format version | 2 bytes | unsigned big-endian; `1` |
| 10 | Payload length | 4 bytes | unsigned big-endian |
| 14 | Payload | variable | CBOR determinista |

Reglas obligatorias:

- Tamaño máximo total: 65.536 bytes.
- Payload length debe ser exactamente el número de bytes restantes.
- Se rechazan truncamientos, bytes sobrantes, longitud cero, longitud superior al límite, magic incorrecto y versión no soportada.
- No se permite concatenar varios sidecars ni añadir trailers.
- El parser valida límites antes de reservar memoria.

## 4. CBOR determinista y estructura

Se usa CBOR determinista conforme a RFC 8949, con longitudes definidas, representación más corta de enteros y claves de mapa ordenadas por su valor numérico ascendente. Se rechazan claves duplicadas, claves desconocidas, tipos inesperados, enteros no mínimos, longitudes indefinidas, profundidad excesiva y cualquier representación que no sea la codificación determinista exacta.

El payload es un mapa CBOR de exactamente tres pares:

| Clave entera | Valor | Tipo y restricción |
|---:|---|---|
| 1 | manifest | byte string que contiene el mapa de manifiesto CBOR determinista |
| 2 | public_key | byte string de exactamente 1.952 bytes |
| 3 | signature | byte string de exactamente 3.309 bytes |

El byte string `manifest` contiene el manifiesto completo. Los bytes de ese byte string, no una reserialización permisiva, son los bytes autenticados.

El manifiesto es un mapa CBOR de exactamente siete pares:

| Clave entera | Campo | Tipo y restricción |
|---:|---|---|
| 1 | manifest_version | unsigned integer; exactamente `1` |
| 2 | signature_algorithm | unsigned integer; exactamente `1` |
| 3 | digest_algorithm | unsigned integer; exactamente `1` |
| 4 | document_digest | byte string de exactamente 32 bytes |
| 5 | identity_id | byte string de exactamente 16 bytes |
| 6 | key_id | byte string de exactamente 16 bytes |
| 7 | created_at | unsigned integer Unix seconds |

Todos los campos son obligatorios en v1. `created_at` es una declaración del reloj local del dispositivo firmante; puede ser incorrecto y no acredita el momento real de firma.

No se incluyen nombre de archivo, ruta absoluta, contenido documental, passphrase, semilla, clave privada, certificado ni datos personales. El nombre visible durante la verificación procede del archivo seleccionado por el usuario y no es una entrada de confianza.

## 5. Mensaje exacto firmado

El mensaje entregado a ML-DSA-65 pure mode es:

```text
ASCII("NEXUS-Q-SIGN-DOCUMENT\0V1\0") || manifest_bytes
```

Donde `manifest_bytes` son exactamente los bytes del byte string de la clave 1 del payload. El dominio ASCII tiene 25 bytes e incluye los dos bytes NUL indicados. No se firma el framing exterior, el payload completo, la clave pública ni el campo signature.

El verificador valida primero que `manifest_bytes` sean un mapa canónico válido y que todos sus campos y longitudes sean exactos; solo entonces verifica la firma sobre el dominio concatenado con esos bytes.

## 6. Firma

1. Abrir el documento seleccionado como archivo regular y calcular SHA-256 en streaming sobre los bytes exactos.
2. Obtener del almacén independiente de Sign la identidad activa y su clave ML-DSA-65.
3. Construir el manifiesto con los IDs de esa identidad, los identificadores fijos de algoritmo, el digest y `created_at`.
4. Codificar el manifiesto CBOR determinista.
5. Firmar el mensaje de §5 con ML-DSA-65 pure mode.
6. Codificar el payload CBOR determinista y el framing binario.
7. Escribir el sidecar en un temporal exclusivo dentro del directorio de destino; sincronizar el archivo y publicar mediante rename atómico sin reemplazar un destino existente. Sincronizar el directorio cuando la plataforma lo permita.
8. Si el sidecar ya existe, fallar con colisión. La UI podrá solicitar al usuario una ruta alternativa; nunca sobrescribir silenciosamente.
9. Detectar cambios concurrentes del documento comparando metadatos de archivo y recalculando SHA-256 antes de publicar. Si no se puede establecer que los bytes no cambiaron durante la operación, abortar.
10. No modificar, renombrar ni eliminar el documento original.

## 7. Verificación

1. Leer el sidecar con límite máximo de 65.536 bytes.
2. Validar framing, versión, longitud exacta y ausencia de bytes sobrantes.
3. Parsear CBOR con límites estrictos y validar codificación determinista, número exacto de campos, tipos, enums y longitudes.
4. Calcular SHA-256 del documento seleccionado en streaming.
5. Si el digest no coincide, devolver `document_changed`; no presentar la firma como verificación satisfactoria del documento seleccionado.
6. Verificar ML-DSA-65 sobre el mensaje de §5.
7. Comparar `identity_id`, `key_id` y `public_key` contra el almacén local de Sign.
8. Informar por separado integridad del documento, validez matemática y reconocimiento local.

La validez matemática no depende de que la identidad sea conocida. El reconocimiento local nunca se infiere del contenido del sidecar.

## 8. Estados de resultado

- `valid_and_recognized`: digest coincidente, firma válida y triple identidad/clave coincidente con un registro local.
- `valid_unknown_identity`: digest coincidente y firma válida, pero no hay coincidencia local exacta.
- `document_changed`: digest del documento seleccionado diferente al manifiesto.
- `invalid_signature`: estructura válida, digest coincidente, firma ML-DSA-65 inválida.
- `malformed_sidecar`: framing, CBOR, tipos, longitudes o canonicalización inválidos.
- `unsupported_version`: versión de framing o manifiesto no soportada.
- `unsupported_algorithm`: identificador de algoritmo distinto de los definidos en v1.
- `verification_error`: fallo de E/S o error interno que impide concluir; nunca se transforma en éxito.

No existe estado de revocación en 0.1.0. Una clave desconocida no debe etiquetarse como revocada. La UI mostrará los tres ejes por separado y evitará un único indicador ambiguo de “válido”.

## 9. Límites y tratamiento de errores

- No procesar sidecars mayores de 65.536 bytes.
- No aceptar mapas CBOR con claves duplicadas, campos adicionales o ausentes.
- No aceptar longitudes alternativas ni codificaciones no deterministas.
- No incluir secretos, rutas completas ni contenido documental en logs.
- Errores de contraseña no deben distinguir entre contraseña errónea y corrupción del sobre.
- El sidecar es entrada no confiable: parsear antes de usar cualquier campo y no ejecutar contenido alguno.

## 10. Vectores y pruebas obligatorias

La implementación debe incorporar fixtures binarios deterministas y comprobar:

- bytes exactos de magic, versión y longitud;
- codificación CBOR canónica de manifiesto y payload;
- round-trip byte por byte del sidecar;
- rechazo de enteros no mínimos, longitudes indefinidas, claves duplicadas/desordenadas/desconocidas y tipos incorrectos;
- rechazo de truncamiento en cada frontera, longitud falsa, trailer y tamaño excedido;
- rechazo de versión y algoritmo no soportados;
- firma válida con ML-DSA-65 y digest coincidente;
- modificación de un byte del documento produce `document_changed`;
- firma modificada produce `invalid_signature`;
- clave pública o IDs cambiados nunca producen reconocimiento local;
- firma matemáticamente válida de clave no registrada produce `valid_unknown_identity`;
- el documento original permanece byte por byte intacto;
- colisión de destino no sobrescribe sidecar existente.

Los fixtures criptográficos deben registrar semilla de prueba únicamente en datos de test no distribuidos como identidad de usuario. Ninguna semilla de prueba debe entrar en el almacén real de la aplicación.

## 11. Estado de implementación

Esta especificación cierra las decisiones de formato para comenzar la implementación interna de NEXUS-Q Sign 0.1.0. No es una afirmación de conformidad FIPS del producto, revisión independiente, certificación, validez legal ni interoperabilidad con otras implementaciones. Antes de declarar 0.1.0 funcional se requieren parser estricto, vectores reproducibles, pruebas de manipulación, revisión de seguridad y pruebas del empaquetado de la plataforma anunciada.
