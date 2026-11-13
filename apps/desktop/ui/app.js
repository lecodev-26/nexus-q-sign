const pages = {
 overview:{title:"Resumen",render:overview},
 sign:{title:"Firmar documento",render:()=>documentWorkspace("sign")},
 verify:{title:"Verificar firma",render:()=>documentWorkspace("verify")},
 identities:{title:"Identidades",render:identities},
 history:{title:"Historial",render:history},
 settings:{title:"Ajustes",render:settings}
};
const contentRoot=document.querySelector("#page-content");
const title=document.querySelector("#page-title");
const invoke=()=>window.__TAURI__?.core?.invoke;
let selectedDocumentPath=null;
let selectedSidecarPath=null;
function overview(){return `
 <div class="hero-card"><span class="eyebrow">FIRMA DIGITAL DETACHED</span><h2>Firma y verifica documentos con control local.</h2><p class="muted">NEXUS-Q Sign crea firmas independientes del documento original. El archivo fuente permanece intacto.</p><div class="meta-row"><span>Versión objetivo: 0.1.0</span><span>Formato previsto: .nqsig</span><span>Algoritmo objetivo: ML-DSA-65</span></div></div>
 <div class="action-grid">
  <button class="action-card" data-go="sign"><span class="feature-icon">✎</span><h3>Firmar documento</h3><p>Selecciona un documento y prepara una firma detached.</p></button>
  <button class="action-card" data-go="verify"><span class="feature-icon">✓</span><h3>Verificar firma</h3><p>Comprueba la firma y detecta cambios en el documento.</p></button>
  <button class="action-card" data-go="identities"><span class="feature-icon">◇</span><h3>Identidades</h3><p>Gestiona tus claves locales de Sign.</p></button>
  <button class="action-card" data-go="history"><span class="feature-icon">◷</span><h3>Historial</h3><p>Consulta firmas y verificaciones realizadas en este dispositivo.</p></button>
 </div><div class="notice"><b>Estado de desarrollo:</b> firma y verificación NQSIG conectadas al backend local; pendientes pruebas end-to-end y validación del empaquetado de la plataforma.</div>`}
function documentWorkspace(mode){const signing=mode==="sign";return `
 <div class="hero-card"><h2>${signing?"Preparar documento para firma":"Verificar un archivo firmado"}</h2><p class="muted">${signing?"Selecciona el documento original. La firma se guardará en un archivo .nqsig independiente.":"Selecciona el documento original y el sidecar .nqsig para comprobar integridad, firma matemática y reconocimiento local por separado."}</p>
 <div class="dropzone"><div class="feature-icon">⇧</div><b>Selecciona un documento</b><p class="muted">El archivo original no se modifica.</p><button id="choose-document" class="primary-action" type="button">Seleccionar documento</button>${signing?'':'<button id="choose-sidecar" class="secondary-action" type="button">Seleccionar firma .nqsig</button>'}</div>
 <div id="file-info" class="meta-row"></div>${signing?'<button id="sign-document" class="primary-action" type="button" disabled>Firmar y crear .nqsig</button>':'<button id="verify-document" class="primary-action" type="button" disabled>Verificar firma</button>'}<div id="document-message" class="notice" role="status" aria-live="polite">${signing?'Desbloquea una identidad y selecciona un documento.':'Selecciona el documento y su sidecar .nqsig.'}</div></div>`}
function identities(){return `
 <div class="hero-card"><h2>Identidades de firma</h2><p class="muted">Identidades independientes, almacenadas localmente en NEXUS-Q Sign. Las claves privadas se cifran y permanecen bajo control del backend Rust.</p>
 <form id="identity-form" class="identity-form">
  <label for="identity-name">Nombre de la identidad</label><input id="identity-name" name="displayName" maxlength="128" required placeholder="Ej. Identidad personal">
  <label for="identity-password">Contraseña de protección</label><input id="identity-password" name="password" type="password" minlength="12" maxlength="1024" required autocomplete="new-password" placeholder="Mínimo 12 caracteres">
  <label for="identity-password-confirm">Confirmar contraseña</label><input id="identity-password-confirm" type="password" minlength="12" maxlength="1024" required autocomplete="new-password" placeholder="Repite la contraseña">
  <button class="primary-action" type="submit">Crear identidad ML-DSA-65</button>
  <p class="muted">La contraseña solo se envía al comando Rust para cifrar la semilla. No se almacena como metadato.</p>
 </form><div id="identity-message" class="notice" role="status" aria-live="polite"></div></div>
 <section class="hero-card"><div class="section-heading"><h2>Identidades guardadas</h2><button id="refresh-identities" class="secondary-action" type="button">Actualizar</button></div><div id="identity-list" class="identity-list"><p class="muted">Cargando identidades…</p></div></section>`}
function history(){return `<section class="hero-card"><div class="section-heading"><div><h2>Historial de operaciones</h2><p class="muted">Solo metadatos locales; no se guardan documentos ni rutas completas.</p></div><button id="clear-history" class="secondary-action danger-action" type="button">Vaciar historial</button></div><div id="history-list" class="identity-list"><p class="muted">Cargando historial…</p></div></section>`}
async function loadHistory(){
 const target=document.querySelector('#history-list');if(!target)return;const call=invoke();
 if(!call){target.textContent='El historial está disponible en la aplicación de escritorio.';return;}
 target.textContent='Cargando…';
 try{const rows=await call('list_history',{limit:200});
 if(!rows.length){target.innerHTML='<p class="muted">Todavía no hay operaciones registradas.</p>';return;}
 target.innerHTML=rows.map(row=>'<article class="identity-card"><div><h3>'+escapeHtml(row.operation==='sign'?'Firma':'Verificación')+' · '+escapeHtml(row.documentName)+'</h3><p class="muted">'+new Date(row.createdAt*1000).toLocaleString()+' · '+escapeHtml(row.status)+'</p>'+(row.documentSha256?'<code>SHA-256: '+escapeHtml(row.documentSha256)+'</code>':'')+(row.identityId?'<p class="muted">ID identidad: '+escapeHtml(row.identityId)+'</p>':'')+'</div></article>').join('');
 }catch(error){target.textContent=typeof error==='string'?error:'No se pudo cargar el historial.';}
}
async function clearHistory(){
 if(!window.confirm('¿Vaciar el historial local de operaciones? Esta acción no se puede deshacer.'))return;
 try{await invoke()('clear_history');await loadHistory();}catch(error){const target=document.querySelector('#history-list');if(target)target.textContent=typeof error==='string'?error:'No se pudo vaciar el historial.';}
}
function settings(){return `<div class="empty-state"><h2>Preferencias</h2><p class="muted">Interfaz y accesibilidad.</p><button id="settings-theme" class="primary-action">Alternar tema</button></div>`}
function escapeHtml(s){return String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function formatBytes(n){if(n<1024)return n+" B";if(n<1048576)return (n/1024).toFixed(1)+" KB";if(n<1073741824)return (n/1048576).toFixed(1)+" MB";return (n/1073741824).toFixed(2)+" GB";}
function toggleTheme(){document.body.classList.toggle("dark");}
async function chooseDocument(){
 const dialog=window.__TAURI__?.dialog;const call=invoke();const info=document.querySelector("#file-info");
 if(!dialog?.open||!call){info.textContent="El selector solo está disponible en la aplicación de escritorio.";return;}
 try{const selected=await dialog.open({multiple:false,directory:false});if(!selected)return;selectedDocumentPath=selected;info.textContent="Calculando SHA-256…";
 const result=await call("inspect_document",{path:selected});
 info.innerHTML='<span><b>Archivo:</b> '+escapeHtml(result.fileName)+'</span><span><b>Tamaño:</b> '+formatBytes(result.sizeBytes)+'</span><span style="width:100%;overflow-wrap:anywhere"><b>SHA-256:</b> <code>'+escapeHtml(result.sha256)+'</code></span>';
  const signButton=document.querySelector('#sign-document');if(signButton){const active=await call('identity_session');signButton.disabled=!active;}
  const verifyButton=document.querySelector('#verify-document');if(verifyButton)verifyButton.disabled=!selectedSidecarPath;
 }catch(error){selectedDocumentPath=null;info.textContent=typeof error==="string"?error:"No se pudo inspeccionar el documento.";}
}
async function chooseSidecar(){
 const dialog=window.__TAURI__?.dialog;const info=document.querySelector('#document-message');
 if(!dialog?.open){info.textContent='El selector solo está disponible en la aplicación de escritorio.';return;}
 try{const selected=await dialog.open({multiple:false,directory:false,filters:[{name:'NEXUS-Q Signature',extensions:['nqsig']}]});if(!selected)return;selectedSidecarPath=selected;info.textContent='Sidecar seleccionado: '+selected.split(/[\\/]/).pop();const button=document.querySelector('#verify-document');if(button)button.disabled=!selectedDocumentPath;}
 catch(error){selectedSidecarPath=null;info.textContent=typeof error==='string'?error:'No se pudo seleccionar el sidecar.';}
}
async function verifySelectedDocument(){
 const message=document.querySelector('#document-message');const button=document.querySelector('#verify-document');
 if(!selectedDocumentPath||!selectedSidecarPath){message.textContent='Selecciona el documento y el sidecar .nqsig.';return;}
 button.disabled=true;message.textContent='Analizando el sidecar y verificando la firma…';
 try{const result=await invoke()('verify_document',{documentPath:selectedDocumentPath,sidecarPath:selectedSidecarPath});const labels={valid_and_recognized:'Firma válida; identidad reconocida localmente.',valid_unknown_identity:'Firma válida; identidad no reconocida en este dispositivo.',document_changed:'El documento no coincide con el digest firmado.',invalid_signature:'La firma criptográfica no es válida.',malformed_sidecar:'El sidecar está mal formado o no es canónico.',unsupported_version:'Versión NQSIG no compatible.',unsupported_algorithm:'Algoritmo no compatible.'};message.textContent=(labels[result.status]||'No se pudo completar la verificación.')+(result.signerFingerprint?' Huella: '+result.signerFingerprint:'')+(result.historyRecorded?' · Historial guardado.':' · No se pudo guardar en el historial.');}
 catch(error){message.textContent=typeof error==='string'?error:'No se pudo verificar el documento.';}
 finally{button.disabled=false;}
}
async function signSelectedDocument(){
 const message=document.querySelector('#document-message');const button=document.querySelector('#sign-document');const call=invoke();
 if(!selectedDocumentPath||!call){message.textContent='Selecciona primero un documento en la aplicación de escritorio.';return;}
 button.disabled=true;message.textContent='Firmando el documento y publicando el sidecar…';
 try{const result=await call('sign_document',{path:selectedDocumentPath});message.textContent='Firma creada: '+result.sidecarFileName+' · SHA-256 '+result.sha256+(result.historyRecorded?' · Historial guardado.':' · No se pudo guardar en el historial.');}
 catch(error){message.textContent=typeof error==='string'?error:'No se pudo firmar el documento.';}
 finally{button.disabled=false;}
}
async function loadIdentities(){
 const target=document.querySelector("#identity-list");if(!target)return;const call=invoke();
 if(!call){target.innerHTML='<p class="muted">La gestión de identidades está disponible dentro de la aplicación de escritorio.</p>';return;}
 target.textContent="Cargando…";
 try{const records=await call("list_identities");
 const activeSession=await call("identity_session");
 if(!records.length){target.innerHTML='<p class="muted">Todavía no hay identidades. Crea una para empezar.</p>';return;}
 target.innerHTML=records.map(r=>{
  const unlocked=activeSession===r.identityId;
  const sessionControl=unlocked
   ? '<div class="identity-session"><span class="session-state">Identidad desbloqueada</span><button class="secondary-action" data-lock-identity type="button">Bloquear</button></div>'
   : '<form class="identity-unlock" data-unlock-identity="'+escapeHtml(r.identityId)+'"><input name="password" type="password" minlength="12" maxlength="1024" required autocomplete="current-password" aria-label="Contraseña para '+escapeHtml(r.displayName)+'" placeholder="Contraseña de la identidad"><button class="secondary-action" type="submit">Desbloquear</button></form>';
  return '<article class="identity-card"><div><h3>'+escapeHtml(r.displayName)+'</h3><p class="muted">ML-DSA-65 · Creada: '+new Date(r.createdAt*1000).toLocaleString()+'</p><code>Huella: '+escapeHtml(r.publicKeyFingerprint)+'</code><p class="muted">ID: '+escapeHtml(r.identityId)+'</p>'+sessionControl+'</div><button class="secondary-action danger-action" data-delete-identity="'+escapeHtml(r.identityId)+'" type="button">Eliminar</button></article>';
 }).join("");
 }catch(error){target.textContent=typeof error==="string"?error:"No se pudieron cargar las identidades.";}
}
async function createIdentity(event){
 event.preventDefault();const form=event.currentTarget;const message=document.querySelector("#identity-message");const name=form.elements.displayName.value.trim();const password=form.elements.password.value;const confirm=form.querySelector("#identity-password-confirm").value;
 if(password!==confirm){message.textContent="Las contraseñas no coinciden.";return;}
 const call=invoke();if(!call){message.textContent="Esta operación requiere la aplicación de escritorio.";return;}
 const submit=form.querySelector('button[type="submit"]');submit.disabled=true;message.textContent="Generando clave y protegiendo la identidad…";
 try{await call("create_identity",{displayName:name,password});form.reset();message.textContent="Identidad creada y guardada localmente.";await loadIdentities();}
 catch(error){message.textContent=typeof error==="string"?error:"No se pudo crear la identidad.";}
 finally{submit.disabled=false;}
}
async function unlockIdentity(id,form){
 const password=form.elements.password.value;const button=form.querySelector('button[type="submit"]');
 button.disabled=true;
 try{await invoke()("unlock_identity",{identityId:id,password});form.reset();await loadIdentities();}
 catch(error){const message=document.querySelector("#identity-message");if(message)message.textContent=typeof error==="string"?error:"No se pudo desbloquear la identidad.";}
 finally{form.reset();button.disabled=false;}
}
async function lockIdentity(){
 try{await invoke()("lock_identity");await loadIdentities();}
 catch(error){const message=document.querySelector("#identity-message");if(message)message.textContent=typeof error==="string"?error:"No se pudo bloquear la identidad.";}
}
async function deleteIdentity(id){
 if(!window.confirm("¿Eliminar esta identidad y su clave privada cifrada? Esta acción no se puede deshacer."))return;
 try{await invoke()("delete_identity",{identityId:id});await loadIdentities();}
 catch(error){const message=document.querySelector("#identity-message");if(message)message.textContent=typeof error==="string"?error:"No se pudo eliminar la identidad.";}
}
function navigate(page){
 const p=pages[page]||pages.overview;title.textContent=p.title;contentRoot.innerHTML=p.render();
 selectedDocumentPath=null;selectedSidecarPath=null;
 document.querySelector("#choose-document")?.addEventListener("click",chooseDocument);
 document.querySelector("#choose-sidecar")?.addEventListener("click",chooseSidecar);
 document.querySelector("#sign-document")?.addEventListener("click",signSelectedDocument);
 document.querySelector("#verify-document")?.addEventListener("click",verifySelectedDocument);
 document.querySelector("#settings-theme")?.addEventListener("click",toggleTheme);
 document.querySelector("#identity-form")?.addEventListener("submit",createIdentity);
 document.querySelector("#refresh-identities")?.addEventListener("click",loadIdentities);
 if(page==="identities")loadIdentities();
 if(page==="history")loadHistory();
 document.querySelector("#clear-history")?.addEventListener("click",clearHistory);
}
document.addEventListener("click",e=>{
 const nav=e.target.closest("[data-page]");if(nav)navigate(nav.dataset.page);
 const go=e.target.closest("[data-go]");if(go)navigate(go.dataset.go);
 const del=e.target.closest("[data-delete-identity]");if(del)deleteIdentity(del.dataset.deleteIdentity);
 const lock=e.target.closest("[data-lock-identity]");if(lock)lockIdentity();
});
document.addEventListener("submit",e=>{
 const unlock=e.target.closest("[data-unlock-identity]");
 if(unlock){e.preventDefault();unlockIdentity(unlock.dataset.unlockIdentity,unlock);}
});
document.querySelector("#theme-toggle").addEventListener("click",toggleTheme);
navigate("overview");
if(invoke())invoke()("app_info").then(info=>{document.documentElement.dataset.appVersion=info.version;}).catch(()=>{});
