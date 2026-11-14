<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";
  import { isLocale, localeNames, translate, type Locale, type TranslationKey } from "./lib/i18n";

  type Page = "overview" | "sign" | "verify" | "identities" | "history" | "settings";
  type Identity = { identityId: string; displayName: string; createdAt: number; publicKeyFingerprint: string };
  type DocumentInfo = { fileName: string; sizeBytes: number; sha256: string };
  type HistoryRow = { id: number; createdAt: number; operation: string; documentName: string; documentSha256: string | null; identityId: string | null; status: string };
  type AppInfo = { name: string; version: string; releaseChannel: string; cryptoReady: boolean };

  let page: Page = "overview";
  let locale: Locale = "en";
  let dark = false;
  let isDesktop = false;
  let appVersion = "0.1.0";
  let documentPath: string | null = null;
  let sidecarPath: string | null = null;
  let documentInfo: DocumentInfo | null = null;
  let operationMessage = "";
  let operationBusy = false;
  let identities: Identity[] = [];
  let activeIdentity: string | null = null;
  let identityName = "";
  let identityPassword = "";
  let identityPasswordConfirm = "";
  let identityMessage = "";
  let identityBusy = false;
  let historyRows: HistoryRow[] = [];
  let historyMessage = "";
  let historyBusy = false;

  let t: (key: TranslationKey) => string;
  $: t = (key) => translate(locale, key);
  let formatBytes: (bytes: number) => string;
  $: formatBytes = (bytes) => {
    if (bytes < 1024) return `${bytes} ${t("bytes")}`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} ${t("kilobytes")}`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} ${t("megabytes")}`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} ${t("gigabytes")}`;
  };
  let dateTime: (seconds: number) => string;
  $: dateTime = (seconds) => new Date(seconds * 1000).toLocaleString(locale);

  function localizeError(error: unknown, fallback: TranslationKey): string {
    const message = typeof error === "string" ? error : error instanceof Error ? error.message : "";
    if (!message) return t(fallback);
    if (/^(?:No se |No puede|No se puede|No se pudieron|No se pudo|El |La |Desbloquea )/i.test(message) || /[áéíóúñ¿¡]/i.test(message)) return t(fallback);
    return message;
  }
  const navItems: { id: Page; icon: string; label: TranslationKey }[] = [
    { id: "overview", icon: "◫", label: "overview" },
    { id: "sign", icon: "✎", label: "sign" },
    { id: "verify", icon: "✓", label: "verify" },
    { id: "identities", icon: "◇", label: "identities" },
    { id: "history", icon: "◷", label: "history" },
  ];

  function desktopOnly(): void {
    operationMessage = t("backendUnavailable");
  }

  async function desktopInvoke<T>(command: string, args?: Record<string, unknown>): Promise<T> {
    if (!isDesktop) throw new Error(t("backendUnavailable"));
    return invoke<T>(command, args);
  }

  function changeLocale(value: string): void {
    if (!isLocale(value)) return;
    locale = value;
    document.documentElement.lang = value;
    localStorage.setItem("nexus-q-sign-language", value);
  }

  function applyTheme(value: boolean): void {
    dark = value;
    document.body.classList.toggle("dark", value);
    document.documentElement.style.colorScheme = value ? "dark" : "light";
    localStorage.setItem("nexus-q-sign-theme", value ? "dark" : "light");
  }

  function toggleTheme(): void {
    applyTheme(!dark);
  }

  function navigate(next: Page): void {
    page = next;
    documentPath = null;
    sidecarPath = null;
    documentInfo = null;
    operationMessage = "";
    if (next === "identities") void loadIdentities();
    if (next === "history") void loadHistory();
  }

  async function chooseDocument(): Promise<void> {
    if (!isDesktop) { desktopOnly(); return; }
    try {
      const selected = await open({ multiple: false, directory: false });
      if (typeof selected !== "string") return;
      documentPath = selected;
      sidecarPath = null;
      operationMessage = t("calculating");
      documentInfo = await desktopInvoke<DocumentInfo>("inspect_document", { path: selected });
      const session = await desktopInvoke<string | null>("identity_session");
      if (page === "sign" && !session) operationMessage = t("identityRequired");
      else operationMessage = "";
    } catch (error) {
      documentPath = null;
      documentInfo = null;
      operationMessage = localizeError(error, "errorInspectDocument");
    }
  }

  async function chooseSidecar(): Promise<void> {
    if (!isDesktop) { desktopOnly(); return; }
    try {
      const selected = await open({ multiple: false, directory: false, filters: [{ name: "NEXUS-Q Signature", extensions: ["nqsig"] }] });
      if (typeof selected !== "string") return;
      sidecarPath = selected;
      operationMessage = `${t("documentSelected")} ${selected.split(/[\\/]/).pop() ?? selected}`;
    } catch (error) {
      operationMessage = localizeError(error, "errorSelectSidecar");
    }
  }

  async function signDocument(): Promise<void> {
    if (!documentPath) { operationMessage = t("selectDocFirst"); return; }
    if (!isDesktop) { desktopOnly(); return; }
    operationBusy = true;
    operationMessage = t("signing");
    try {
      const result = await desktopInvoke<{ sidecarFileName: string; sha256: string; historyRecorded: boolean }>("sign_document", { path: documentPath });
      operationMessage = `${t("signatureCreated")} ${result.sidecarFileName} · SHA-256 ${result.sha256} · ${result.historyRecorded ? t("historySaved") : t("historyNotSaved")}`;
    } catch (error) {
      operationMessage = localizeError(error, "errorSignDocument");
    } finally {
      operationBusy = false;
    }
  }

  async function verifyDocument(): Promise<void> {
    if (!documentPath || !sidecarPath) { operationMessage = t("selectBoth"); return; }
    if (!isDesktop) { desktopOnly(); return; }
    operationBusy = true;
    operationMessage = t("verifying");
    try {
      const result = await desktopInvoke<{ status: string; signerFingerprint: string; historyRecorded: boolean }>("verify_document", { documentPath, sidecarPath });
      const messages: Record<string, string> = {
        valid_and_recognized: t("signatureValidRecognized"),
        valid_unknown_identity: t("signatureValidUnknown"),
        document_changed: t("documentChanged"),
        invalid_signature: t("invalidSignature"),
        malformed_sidecar: t("malformedSidecar"),
        unsupported_version: t("unsupportedVersion"),
        unsupported_algorithm: t("unsupportedAlgorithm"),
      };
      operationMessage = `${messages[result.status] ?? t("verificationFailed")}${result.signerFingerprint ? ` · ${t("fingerprint")}: ${result.signerFingerprint}` : ""} · ${result.historyRecorded ? t("historySaved") : t("historyNotSaved")}`;
    } catch (error) {
      operationMessage = localizeError(error, "errorVerifyDocument");
    } finally {
      operationBusy = false;
    }
  }

  async function loadIdentities(): Promise<void> {
    if (!isDesktop) { identities = []; identityMessage = t("backendUnavailable"); return; }
    identityBusy = true;
    try {
      identities = await desktopInvoke<Identity[]>("list_identities");
      activeIdentity = await desktopInvoke<string | null>("identity_session");
      identityMessage = "";
    } catch (error) {
      identityMessage = localizeError(error, "errorLoadIdentities");
    } finally {
      identityBusy = false;
    }
  }

  async function createIdentity(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (identityPassword !== identityPasswordConfirm) { identityMessage = t("passwordMismatch"); return; }
    identityBusy = true;
    identityMessage = t("creatingIdentity");
    try {
      await desktopInvoke<Identity>("create_identity", { displayName: identityName.trim(), password: identityPassword });
      identityName = "";
      identityPassword = "";
      identityPasswordConfirm = "";
      identityMessage = t("identityCreated");
      await loadIdentities();
    } catch (error) {
      identityMessage = localizeError(error, "errorCreateIdentity");
    } finally {
      identityPassword = "";
      identityPasswordConfirm = "";
      identityBusy = false;
    }
  }

  async function unlockIdentity(event: SubmitEvent, identityId: string): Promise<void> {
    event.preventDefault();
    const form = event.currentTarget as HTMLFormElement;
    const password = String(new FormData(form).get("password") ?? "");
    const button = form.querySelector("button");
    if (button) button.disabled = true;
    try {
      await desktopInvoke("unlock_identity", { identityId, password });
      form.reset();
      await loadIdentities();
    } catch (error) {
      identityMessage = localizeError(error, "errorUnlockIdentity");
    } finally {
      form.reset();
      if (button) button.disabled = false;
    }
  }

  async function lockIdentity(): Promise<void> {
    try { await desktopInvoke("lock_identity"); await loadIdentities(); }
    catch (error) { identityMessage = localizeError(error, "errorLockIdentity"); }
  }

  async function deleteIdentity(identityId: string): Promise<void> {
    if (!window.confirm(t("deleteIdentityConfirm"))) return;
    try { await desktopInvoke("delete_identity", { identityId }); await loadIdentities(); }
    catch (error) { identityMessage = localizeError(error, "errorDeleteIdentity"); }
  }

  async function loadHistory(): Promise<void> {
    if (!isDesktop) { historyRows = []; historyMessage = t("backendUnavailable"); return; }
    historyBusy = true;
    try {
      historyRows = await desktopInvoke<HistoryRow[]>("list_history", { limit: 200 });
      historyMessage = "";
    } catch (error) {
      historyMessage = localizeError(error, "errorLoadHistory");
    } finally {
      historyBusy = false;
    }
  }

  async function clearHistory(): Promise<void> {
    if (!window.confirm(t("deleteHistoryConfirm"))) return;
    historyBusy = true;
    try {
      await desktopInvoke("clear_history");
      historyRows = [];
      historyMessage = t("historyCleared");
    } catch (error) {
      historyMessage = localizeError(error, "errorClearHistory");
    } finally {
      historyBusy = false;
    }
  }

  onMount(() => {
    const savedLocale = localStorage.getItem("nexus-q-sign-language");
    if (savedLocale && isLocale(savedLocale)) locale = savedLocale;
    document.documentElement.lang = locale;
    applyTheme(localStorage.getItem("nexus-q-sign-theme") === "dark");
    isDesktop = "__TAURI_INTERNALS__" in window;
    if (isDesktop) {
      void desktopInvoke<AppInfo>("app_info").then((info) => { appVersion = info.version; }).catch(() => {});
      void loadIdentities();
    }
  });
</script>

<svelte:head>
  <title>NEXUS-Q Sign</title>
  <meta name="description" content="Local-first detached document signing and verification." />
</svelte:head>

<div class="app-layout">
  <aside class="sidebar">
    <a class="side-brand" href="#overview" onclick={(event) => { event.preventDefault(); navigate("overview"); }}>
      <img src="./assets/nexus-q-mark.png" alt="" />
      <span><b>NEXUS-Q <strong>Sign</strong></b><small>{t("brandTagline")}</small></span>
    </a>
    <div class="side-label">{t("workspace")}</div>
    <nav class="side-nav" aria-label={t("primaryNavigation")}>
      {#each navItems as item (item.id)}
        <button class:active={page === item.id} class="nav-item" type="button" onclick={() => navigate(item.id)}>
          <span class="nav-icon">{item.icon}</span><span class="nav-label">{t(item.label)}</span>
        </button>
      {/each}
    </nav>
    <div class="sidebar-spacer"></div>
    <button class:active={page === "settings"} class="nav-item settings-nav" type="button" onclick={() => navigate("settings")}>
      <span class="nav-icon">⚙</span><span class="nav-label">{t("settings")}</span>
    </button>
    <div class="vault-status"><i></i><span><b>{t("independentStorage")}</b><small>{t("notConnected")}</small></span></div>
    <div class="version">{appVersion === "0.1.0" ? t("appVersion") : `NEXUS-Q Sign · v${appVersion}`}</div>
  </aside>

  <main class="main-area">
    <header class="topbar">
      <div>
        <span class="eyebrow">{t("ecosystem")}</span>
        <h1>{t(page)}</h1>
      </div>
      <div class="top-actions">
        <span class="status-pill">{isDesktop ? t("desktopMode") : t("webMode")}</span>
        <label class="sr-only" for="language-select">{t("language")}</label>
        <select id="language-select" class="language-select" aria-label={t("language")} value={locale} onchange={(event) => changeLocale(event.currentTarget.value)}>
          {#each Object.entries(localeNames) as [code, label]}
            <option value={code}>{label}</option>
          {/each}
        </select>
        <button id="theme-toggle" class="icon-button" type="button" aria-label={t("themeToggle")} aria-pressed={dark} title={t("themeToggle")} onclick={toggleTheme}>◐</button>
      </div>
    </header>

    <section class="content">
      {#if page === "overview"}
        <div class="hero-card overview-hero">
          <span class="eyebrow">{t("overviewKicker")}</span>
          <h2>{t("overviewTitle")}</h2>
          <p class="muted">{t("overviewDescription")}</p>
          <div class="meta-row"><span>{t("versionLabel")}</span><span>{t("formatLabel")}</span><span>{t("algorithmLabel")}</span></div>
        </div>
        <div class="action-grid">
          <button class="action-card" type="button" onclick={() => navigate("sign")}><span class="feature-icon">✎</span><h3>{t("sign")}</h3><p>{t("signDescription")}</p></button>
          <button class="action-card" type="button" onclick={() => navigate("verify")}><span class="feature-icon">✓</span><h3>{t("verify")}</h3><p>{t("verifyDescription")}</p></button>
          <button class="action-card" type="button" onclick={() => navigate("identities")}><span class="feature-icon">◇</span><h3>{t("identities")}</h3><p>{t("identityDescription")}</p></button>
          <button class="action-card" type="button" onclick={() => navigate("history")}><span class="feature-icon">◷</span><h3>{t("history")}</h3><p>{t("historyDescription")}</p></button>
        </div>
        <div class="notice"><b>{t("localNoticeTitle")}</b><p>{t("localNotice")}</p></div>
      {:else if page === "sign" || page === "verify"}
        <div class="hero-card document-card">
          <h2>{page === "sign" ? t("signTitle") : t("verifyTitle")}</h2>
          <p class="muted">{page === "sign" ? t("signIntro") : t("verifyIntro")}</p>
          <div class="dropzone">
            <div class="feature-icon">⇧</div>
            <b>{t("selectDocument")}</b>
            <p class="muted">{t("originalUnchanged")}</p>
            <button class="primary-action" type="button" onclick={chooseDocument}>{t("chooseDocument")}</button>
            {#if page === "verify"}<button class="secondary-action" type="button" onclick={chooseSidecar}>{t("chooseSidecar")}</button>{/if}
          </div>
          {#if documentInfo}
            <div class="meta-row file-meta">
              <span><b>{t("fileName")}:</b> {documentInfo.fileName}</span>
              <span><b>{t("fileSize")}:</b> {formatBytes(documentInfo.sizeBytes)}</span>
              <span class="hash-row"><b>{t("sha256")}:</b> <code>{documentInfo.sha256}</code></span>
              {#if sidecarPath}<span>{t("documentSelected")} {sidecarPath.split(/[\\/]/).pop()}</span>{/if}
            </div>
          {/if}
          {#if page === "sign"}
            <button class="primary-action" type="button" disabled={!documentPath || operationBusy} onclick={signDocument}>{t("signAndCreate")}</button>
          {:else}
            <button class="primary-action" type="button" disabled={!documentPath || !sidecarPath || operationBusy} onclick={verifyDocument}>{t("verifyNow")}</button>
          {/if}
          {#if operationMessage}<div class="notice" role="status" aria-live="polite">{operationMessage}</div>{/if}
        </div>
      {:else if page === "identities"}
        <div class="hero-card">
          <h2>{t("identityTitle")}</h2>
          <p class="muted">{t("identityIntro")}</p>
          <form class="identity-form" onsubmit={createIdentity}>
            <label for="identity-name">{t("identityName")}</label>
            <input id="identity-name" bind:value={identityName} maxlength="128" required placeholder={t("identityNamePlaceholder")} />
            <label for="identity-password">{t("password")}</label>
            <input id="identity-password" bind:value={identityPassword} type="password" minlength="12" maxlength="1024" required autocomplete="new-password" placeholder={t("passwordPlaceholder")} />
            <label for="identity-password-confirm">{t("confirmPassword")}</label>
            <input id="identity-password-confirm" bind:value={identityPasswordConfirm} type="password" minlength="12" maxlength="1024" required autocomplete="new-password" placeholder={t("confirmPasswordPlaceholder")} />
            <button class="primary-action" type="submit" disabled={identityBusy}>{t("createIdentity")}</button>
            <p class="muted">{t("passwordNote")}</p>
          </form>
          {#if identityMessage}<div class="notice" role="status" aria-live="polite">{identityMessage}</div>{/if}
        </div>
        <section class="hero-card list-card">
          <div class="section-heading"><div><h2>{t("savedIdentities")}</h2></div><button class="secondary-action" type="button" onclick={loadIdentities} disabled={identityBusy}>{t("refresh")}</button></div>
          {#if identityBusy}<p class="muted">{t("loading")}</p>
          {:else if identities.length === 0}<p class="muted">{t("noIdentities")}</p>
          {:else}
            <div class="identity-list">
              {#each identities as identity (identity.identityId)}
                <article class="identity-card">
                  <div class="identity-details">
                    <h3>{identity.displayName}</h3>
                    <p class="muted">ML-DSA-65 · {t("created")}: {dateTime(identity.createdAt)}</p>
                    <code>{t("fingerprint")}: {identity.publicKeyFingerprint}</code>
                    <p class="muted">{t("identityId")}: {identity.identityId}</p>
                    {#if activeIdentity === identity.identityId}
                      <div class="identity-session"><span class="session-state">{t("unlocked")}</span><button class="secondary-action" type="button" onclick={lockIdentity}>{t("lock")}</button></div>
                    {:else}
                      <form class="identity-unlock" onsubmit={(event) => unlockIdentity(event, identity.identityId)}>
                        <input name="password" type="password" minlength="12" maxlength="1024" required autocomplete="current-password" aria-label={t("unlockPlaceholder")} placeholder={t("unlockPlaceholder")} />
                        <button class="secondary-action" type="submit">{t("unlock")}</button>
                      </form>
                    {/if}
                  </div>
                  <button class="secondary-action danger-action" type="button" onclick={() => deleteIdentity(identity.identityId)}>{t("delete")}</button>
                </article>
              {/each}
            </div>
          {/if}
        </section>
      {:else if page === "history"}
        <section class="hero-card">
          <div class="section-heading">
            <div><h2>{t("historyTitle")}</h2><p class="muted">{t("historyIntro")}</p></div>
            <button class="secondary-action danger-action" type="button" onclick={clearHistory} disabled={historyBusy || historyRows.length === 0}>{t("clearHistory")}</button>
          </div>
          {#if historyMessage}<p class="muted" role="status">{historyMessage}</p>{/if}
          {#if historyBusy}<p class="muted">{t("loading")}</p>
          {:else if historyRows.length === 0}<p class="muted">{t("noHistory")}</p>
          {:else}
            <div class="history-list">
              {#each historyRows as row (row.id)}
                <article class="identity-card">
                  <div><h3>{row.operation === "sign" ? t("operationSign") : t("operationVerify")} · {row.documentName}</h3><p class="muted">{dateTime(row.createdAt)} · {row.status}</p>
                    {#if row.documentSha256}<code>SHA-256: {row.documentSha256}</code>{/if}
                    {#if row.identityId}<p class="muted">{t("identityId")}: {row.identityId}</p>{/if}
                  </div>
                </article>
              {/each}
            </div>
          {/if}
        </section>
      {:else if page === "settings"}
        <section class="hero-card settings-card">
          <h2>{t("preferences")}</h2>
          <div class="setting-line"><div><b>{t("language")}</b><p class="muted">{t("appearance")}</p></div>
            <select aria-label={t("language")} value={locale} onchange={(event) => changeLocale(event.currentTarget.value)}>
              {#each Object.entries(localeNames) as [code, label]}<option value={code}>{label}</option>{/each}
            </select>
          </div>
          <div class="setting-line"><div><b>{t("theme")}</b><p class="muted">{dark ? t("darkTheme") : t("lightTheme")}</p></div>
            <button class="secondary-action" type="button" onclick={toggleTheme}>{t("themeToggle")}</button>
          </div>
          <p class="settings-version">{t("appVersion")}</p>
        </section>
      {/if}
    </section>
  </main>
</div>
