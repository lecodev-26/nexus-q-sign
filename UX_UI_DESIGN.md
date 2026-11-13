# NEXUS-Q Sign — UX/UI Design v0.1

**Estado:** frontend NEXUS-Q Sign 0.1.0 implementado sobre la referencia visual de NEXUS-Q Vault
**Referencia:** `~/nexus-q-vault`, commit `eaab774` (rama `main`)  
**Alcance:** sistema visual, arquitectura de navegación y especificación de pantallas. No es todavía la aplicación productiva.

## 1. Principio rector

NEXUS-Q Sign debe sentirse como otra aplicación de la misma familia que NEXUS-Q Vault. La fidelidad visual es el requisito principal: reutilizar estructura, escala, proporciones, tokens, controles, estados, temas, navegación y responsive. No rediseñar Vault ni introducir un lenguaje visual alternativo.

Se conserva la marca NEXUS-Q y se sustituye únicamente el descriptor de producto: **SIGN DESKTOP** / **NEXUS-Q Sign**. Reutilizar el icono oficial de Vault copiado en `assets/nexus-q-mark.png`.

## 2. Referencia inspeccionada

Referencias visuales revisadas en NEXUS-Q Vault:
- `apps/desktop/ui/index.html`
- `apps/desktop/ui/styles.css`
- `apps/desktop/ui/app.js`
- `apps/desktop/tauri.conf.json`
- Capturas: `docs/screenshots/{overview,vault-access,file-operations,settings}.png`

Vault usa Tauri 2 + Rust + HTML/CSS/JavaScript (no Svelte). Sign conserva su sistema visual —especialmente la barra lateral, los tokens, los paneles y los temas— pero su frontend propio se implementa con **Svelte 5 + TypeScript + Vite**. La interfaz de Sign tiene diccionarios separados y English como idioma principal, con español y catalán. El repositorio de Vault se inspeccionó en `main`, commit `eaab774`; no se ha modificado.

## 3. Sistema visual — tokens de referencia

### Layout y geometría
| Token | Valor de referencia |
|---|---:|
| Sidebar desktop | 252 px |
| Sidebar medio | 210 px |
| Sidebar compacto | 72 px |
| Shell padding | 30 px vertical; clamp(28px, 3vw, 58px) horizontal |
| Shell max width | 1700 px |
| Ventana inicial | 1440 × 940 |
| Ventana mínima | 980 × 680 |
| Panel radius | 11 px |
| Control radius | 7 px |
| Sidebar nav radius | 8 px |
| Panel padding | 22 px |
| Grid gap | 14–18 px |

### Color
| Token | Claro | Oscuro |
|---|---|---|
| Canvas | `#f5f5f3` | `#101010` |
| Sidebar | `#101010` | `#101010` |
| Surface | `#ffffff` | `#191919` |
| Surface secondary | `#fafaf9` | `#141414` |
| Text | `#171717` | `#eeeeee` |
| Muted | `#777777` | `#999999` |
| Border | `#e5e5e2` | `#303030` |
| Accent | `#111111` | `#ffffff` |
| Accent ink | `#ffffff` | `#111111` |

Estados semánticos (éxito, error, advertencia) deben conservar el tratamiento discreto de Vault; no sustituir el acento monocromo de marca por un color dominante. El verde de estado solo indica actividad/resultado positivo y nunca confianza jurídica.

### Tipografía
- Familia: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif.
- Titular hero: clamp(38px, 4.2vw, 62px), peso 650, tracking -2.9px, line-height 1.08.
- Título de página: 18 px / peso 750.
- Título de panel: 17 px.
- Cuerpo: 11–14 px, line-height 1.55–1.7.
- Eyebrow: 9 px, peso 750, tracking 2 px, mayúsculas.
- No introducir fuentes display ni escalas tipográficas nuevas.

### Componentes a mantener
- Sidebar sticky, marca superior, etiqueta WORKSPACE, navegación activa gris carbón, tarjeta OPEN SOURCE y perfil local.
- Header de contenido con marca, selector de idioma, toggle de tema y estado a la derecha.
- Paneles blancos/oscuros con borde fino, step badge, formularios verticales, inputs secundarios, botones primarios monocromos.
- Feedback inline con `role=status`, `aria-live`; error diferenciado sin modal intrusivo.
- Footer con nombre de producto, estado local y privacidad.
- Respeto a `prefers-reduced-motion`.

## 4. Navegación principal

Orden recomendado de la barra lateral:
1. Overview
2. Sign document
3. Verify signature
4. Identities
5. History
6. Settings
7. Help & guide

La navegación reproduce el patrón `.app-page` de Vault: vistas independientes, una activa, navegación lateral y hash estable. Mantener los mismos iconos tipográficos/sencillos de Vault en la primera implementación; no cambiar a un set visual distinto.

## 5. Especificación de pantallas

### 5.1 Overview
- Hero con eyebrow "LOCAL-FIRST DOCUMENT SIGNING".
- Titular: "Sign your documents." / segunda línea "Verify every change."
- Texto breve: firma detached local; el documento original no se modifica.
- Cuatro tarjetas de resumen con el patrón overview de Vault: Sign locally, Verify integrity, Manage identities, Local history.
- Bloque de workflow de cuatro pasos: Select document → Choose identity → Review & sign → Save signature.
- Panel lateral "Important distinction": validez criptográfica, confianza de identidad y validez legal son conceptos distintos.
- CTA principal "Sign a document" navega a Sign document.

### 5.2 Sign document
- Vista operativa con título "Create a detached signature".
- Panel superior de selección de documento: nombre, tamaño y huella SHA-256 calculada en backend; selector nativo de archivo.
- Panel de identidad: identidad seleccionada, algoritmo disponible (ML-DSA-65 solo si Core confirma disponibilidad), fingerprint abreviado y estado de desbloqueo.
- Resumen de salida: documento original preservado; firma lateral `.nqsig`; destino editable/selector nativo.
- CTA "Review signature" antes de la operación criptográfica.
- Confirmación explícita de identidad y archivo antes de firmar. No enviar clave privada al frontend.
- Progreso cancelable solo si el backend garantiza cancelación segura. Finalización: "Signature created" con rutas/nombres no sensibles y acceso a Verify.

### 5.3 Verify signature
- Dos selectores: documento original y archivo `.nqsig`.
- CTA "Verify signature".
- Resultado dividido en tres bloques independientes:
  1. **Cryptographic signature:** valid / invalid / malformed / unsupported.
  2. **Document integrity:** matches signed digest / content changed / cannot compare.
  3. **Signer identity:** recognized locally / unknown / disabled (no inferir confianza solo de la clave incluida).
- Advertencia fija: "A cryptographically valid signature does not by itself establish legal validity."
- Si hay fallo, explicar la causa concreta y no usar una única marca verde/roja para los tres estados.

### 5.4 Identities
- Lista en tarjetas/filas con nombre, fingerprint, algoritmo, fecha de creación y estado.
- Acciones: create identity, view public details, set default, disable (si soportado), export public key/card (si formato definido).
- Crear identidad en flujo de dos paneles, coherente con Create/Open Vault de Vault.
- Claves privadas bajo custodia de NEXUS-Q Core/Vault; nunca mostrarlas ni exportarlas por defecto.
- No afirmar certificado, validación legal ni hardware-backed sin evidencia técnica.

### 5.5 History
- Tabla/lista local con tipo de operación, fecha local, resultado y referencia no sensible.
- Filtros: All / Signed / Verified / Failed.
- Detalle de evento con hashes/fingerprint solo si la política de privacidad lo permite.
- Historial local editable por el propietario del dispositivo; no etiquetarlo "immutable audit log".
- No guardar contenido documental ni rutas absolutas por defecto.

### 5.6 Settings
- Mantener composición de tarjetas de Vault.
- Preferencias locales: idioma, tema, perfil local, ubicación predeterminada (opt-in), privacidad, formato de informe y versión.
- Sección de seguridad con límites y algoritmo realmente soportado.
- No añadir toggles que no tengan implementación backend.

### 5.7 Help & guide
- Tarjetas numeradas al estilo guía de Vault: qué es detached signature, cómo firmar, cómo verificar, cómo gestionar identidades y limitaciones legales.
- Glosario para digest, fingerprint, clave pública, firma detached y confianza.
- Explicar que el fichero original permanece intacto.

## 6. Estados y microcopy

- Empty: "No document selected" / "Choose a document to continue."
- Ready: "Ready to sign" solo cuando documento e identidad estén validados.
- Locked: "Identity locked" y acción "Unlock identity".
- Working: "Calculating document digest…" / "Creating signature…".
- Success: "Signature created. Your original document was not modified."
- Invalid: "Signature invalid. The signed data could not be authenticated."
- Changed: "Document content does not match the signed digest."
- Unknown signer: "Signature is mathematically valid, but this signer is not in your local trusted identities."
- Unsupported: "This signature format or algorithm is not supported by this version."
- Error: explicar causa y siguiente paso, sin exponer rutas internas, stack traces ni secretos.

## 7. Accesibilidad y comportamiento
- Foco visible equivalente a Vault; todos los controles operables por teclado.
- Labels asociados a inputs; no usar placeholder como único label.
- Estado de proceso anunciado con aria-live; no depender solo del color.
- Contraste suficiente en ambos temas.
- Respetar movimiento reducido.
- Layout desktop primero; a <=1100 px reducir sidebar y columnas; a <=850 px sidebar compacto de 65 px y grids de una columna, siguiendo Vault.
- Tamaño mínimo de ventana propuesto 1024×700, sujeto a prueba con diálogos nativos.

## 8. Reglas de seguridad que afectan a UX
- Frontend no recibe claves privadas ni semillas.
- El backend vuelve a validar paths y archivos; el frontend no decide confianza.
- Separar siempre firma criptográfica válida, identidad confiable y validez legal.
- El nombre del archivo no demuestra integridad; la comprobación usa digest.
- `created_at` es hora local declarada, no sello de tiempo confiable.
- No mostrar "legal", "qualified", "certified" o "tamper-proof" sin fundamento verificable.
- Operaciones sensibles requieren revisión y confirmación antes de ejecutar.

## 9. Pendientes antes de convertir en producción
1. Seleccionar y revisar la biblioteca Rust ML-DSA-65 integrada directamente en Sign.
2. Diseñar el almacén cifrado autónomo de identidades y claves de Sign.
3. Especificar serialización/canonicalización y esquema definitivo NQSIG.
4. Confirmar disponibilidad de capacidades en los sistemas operativos objetivo.
5. Completar diálogos de archivo, escritura atómica y cancelación segura.
6. Sustituir textos de maqueta por traducciones reales; mantener coherencia con la familia visual NEXUS-Q.
7. Comparar capturas de Sign y Vault a igual resolución, tema y escala; aprobar paridad visual.
8. Pruebas de teclado, contraste, lectores de pantalla y ventanas mínimas.

## 10. Independencia de producto

Sign es una aplicación autónoma. No se conecta a Vault ni a otras apps NEXUS-Q y no comparte sesiones, almacenes, claves, bases de datos, procesos, IPC o servicios. La única continuidad entre productos es la estética del frontend. Sign mantiene su propio backend, persistencia, identidades, claves y configuración. La hoja de estilos de Vault se conserva como referencia visual local, no como integración de runtime.

Las propuestas antiguas de utilizar APIs de Vault/Core para custodiar las claves de Sign quedan sustituidas por esta decisión. La implementación criptográfica se resolverá dentro del proceso de Sign mediante una biblioteca Rust revisada o código propio.

## 11. Archivos de entrega
- `UX_UI_DESIGN.md`: esta especificación.
- `preview.html`: prototipo navegable de pantallas con tema claro/oscuro (datos ficticios, sin operaciones criptográficas).
- `assets/nexus-q-mark.png`: marca copiada de la interfaz de Vault.

**No se ha modificado el repositorio de Vault ni se ha iniciado aún la implementación productiva de NEXUS-Q Sign.**
