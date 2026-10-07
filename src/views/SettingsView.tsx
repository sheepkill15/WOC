import { useEffect, useState } from "react";
import { useCleaner } from "../store";
import { formatCount, formatDate } from "../format";
import type { Settings } from "../types";
import { Icon, Notice, PageHeader, Section } from "../ui";

export type Theme = "system" | "light" | "dark";

export function SettingsView({ theme, setTheme }: { theme: Theme; setTheme: (theme: Theme) => void }) {
  const { settings, saveSettings, publicData, updatePublicData, exportDiagnostics, definitions, appInfo, openPath, backend, running } = useCleaner();
  const [draft, setDraft] = useState<Settings | null>(settings);
  const [updating, setUpdating] = useState(false);
  const [exporting, setExporting] = useState(false);
  const connected = backend === "tauri" || backend === "agent";
  useEffect(() => setDraft(settings), [settings]);
  const dirty = draft && settings && JSON.stringify(draft) !== JSON.stringify(settings);

  return <div className="page">
    <PageHeader title="Settings" />
    <Section title="Appearance">
      <div className="segmented">
        {(["system", "light", "dark"] as const).map(value => <button key={value} className={theme === value ? "active" : ""} onClick={() => setTheme(value)}>
          <Icon name={value === "light" ? "sun" : value === "dark" ? "moon" : "overview"} size={14} /> {value[0].toUpperCase() + value.slice(1)}
        </button>)}
      </div>
    </Section>
    {draft && <Section title="Scanning & cleanup" actions={<button className="primary" disabled={!dirty} onClick={() => void saveSettings(draft)}>Save</button>}>
      <div className="settings-grid">
        <label><span>Default scan mode</span>
          <select value={draft.defaultScanMode} onChange={event => setDraft({ ...draft, defaultScanMode: event.target.value as Settings["defaultScanMode"] })}>
            <option value="quick">Quick — AppData, ProgramData and Downloads</option><option value="deep">Deep — also personal folders, other drives and Program Files</option>
          </select></label>
        <label><span>Quarantine retention</span>
          <select value={draft.quarantineRetentionDays} onChange={event => setDraft({ ...draft, quarantineRetentionDays: Number(event.target.value) })}>
            {[7, 14, 30, 60, 90].map(days => <option key={days} value={days}>Delete permanently after {days} days</option>)}
            <option value={0}>Keep until I delete them</option>
          </select></label>
        <label className="check-row"><input type="checkbox" checked={draft.checkRemovedOnLaunch} onChange={event => setDraft({ ...draft, checkRemovedOnLaunch: event.target.checked })} /><span>Check for uninstalled applications when the app starts</span></label>
      </div>
    </Section>}
    <Section title="Public folder data" description="Game save locations from Ludusavi and cache paths from Winapp2. Both databases update automatically before each scan; cached data remains available offline."
      actions={<button className="secondary" disabled={!connected || updating || running} onClick={async () => { setUpdating(true); await updatePublicData(); setUpdating(false); }}>{updating ? "Updating…" : "Update folder data"}</button>}>
      <p className="muted">{publicData?.updatedAtUnix ? `Updated ${formatDate(publicData.updatedAtUnix)}` : "Not downloaded"} · {formatCount(publicData?.gameDirectories ?? 0, "game folder name")} · {formatCount(publicData?.cleanerDirectories ?? 0, "cleaner folder name")}</p>
      {publicData?.warnings.map((warning, index) => <Notice key={index} tone="warn">{warning}</Notice>)}
      <p className="muted small">Sources: <a href="https://github.com/mtkennerly/ludusavi-manifest" target="_blank" rel="noreferrer">Ludusavi manifest</a> (MIT repository; compiled partly from PCGamingWiki, CC BY-NC-SA) and <a href="https://github.com/MoscaDotTo/Winapp2" target="_blank" rel="noreferrer">Winapp2</a> (CC BY-SA 4.0). A path match never makes a whole folder disposable.</p>
    </Section>
    <Section title="Application definitions" description="Definitions describe known data folders (for example Discord's Cache or logs). They refine classification; inference works without them."
      actions={definitions && connected ? <button className="ghost" onClick={() => void openPath(definitions.directory)}><Icon name="open" size={15} /> Open folder</button> : undefined}>
      {definitions ? <>
        <p className="muted">{definitions.builtIn} built-in · {definitions.user} of your own. Add <code>.yaml</code> files to <code>{definitions.directory}</code> and scan again.</p>
        {definitions.warnings.map((warning, index) => <Notice key={index} tone="warn">{warning}</Notice>)}
        <details className="code-sample"><summary>Definition format</summary><pre>{`id: my-app
vendor: example
product: My App
identifiers:
  executables: [MyApp.exe]
paths:
  - { path: "%APPDATA%\\\\MyApp\\\\Cache", type: CACHE }
  - { path: "%APPDATA%\\\\MyApp\\\\Saves", type: SAVE_GAME }`}</pre></details>
      </> : <p className="muted">Unavailable until the backend is connected.</p>}
    </Section>
    <Section title="Diagnostics" description="A privacy-reviewed JSON file for troubleshooting, saved to Downloads."
      actions={<button className="secondary" disabled={!connected || exporting || running} onClick={async () => { setExporting(true); await exportDiagnostics(); setExporting(false); }}>{exporting ? "Exporting…" : "Export diagnostics"}</button>}>
      <p className="muted small">Contains installed application names and versions, scanned folder paths with their immediate subfolder names, aggregate sizes and file-type totals, classifier evidence, executable version metadata (without file names), startup/task/service/shortcut references, up to ten scans and recent log lines. Your user-profile path is replaced with %USERPROFILE%. No file contents or individual file names are included.</p>
    </Section>
    {appInfo && <Section title="About">
      <dl className="about">
        <dt>Version</dt><dd>{appInfo.version} · {appInfo.backend === "tauri" ? "Desktop app" : "Browser + local agent"}</dd>
        <dt>Data folder</dt><dd><code>{appInfo.dataDirectory}</code> <button className="link" onClick={() => void openPath(appInfo.dataDirectory)}>Open</button></dd>
        <dt>Quarantine</dt><dd><code>{appInfo.quarantineDirectory}</code></dd>
        <dt>Log file</dt><dd><code>{appInfo.logFile}</code></dd>
      </dl>
      <p className="muted small">Everything runs locally. Nothing about your files or applications is uploaded. No AI model makes cleanup decisions; every rule is deterministic and explained.</p>
    </Section>}
  </div>;
}
