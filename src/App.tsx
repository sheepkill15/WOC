import { useEffect, useMemo, useState } from "react";
import { connectBackend, disconnectBackend, invokeBackend, listenBackend, type BackendKind } from "./backend";

type Application = { id: string; name: string; publisher: string | null; version: string | null; installLocation: string | null; displayIconExecutable?: string | null; packageFamilyName: string | null; sources: string[] };
type Inventory = { applications: Application[]; warnings: string[] };
type Evidence = { kind: string; description: string; strength: string };
type DirectoryResult = {
  path: string; root: string; parentPath?: string | null; sizeBytes: number; fileCount: number; directoryCount: number;
  newestModifiedUnix: number | null; skippedEntries: number; owner: Application | null; ownerHint?: string | null;
  ownership: string; orphanStatus: string; evidence: Evidence[];
};
type ScanSummary = { directories: number; bytes: number; skippedEntries: number; canceled: boolean; scannedRoots: string[]; warnings: string[] };
type SavedScan = { capturedAtUnix: number; inventory: Inventory; summary: ScanSummary; results: DirectoryResult[] };
type ScanFinishedEvent = { summary: ScanSummary; savedAtUnix: number | null; saveError: string | null };
type PublicDataStatus = { updatedAtUnix: number | null; gameDirectories: number; cleanerDirectories: number; warnings: string[] };
type HistoricalDirectory = { path: string; root: string; sizeBytes: number; orphanStatus: string };
type HistoricalApplication = {
  application: Application; lastSeenAtUnix: number | null; firstMissingAtUnix: number | null;
  newlyMissing: boolean; remainingBytes: number; confidence: "probable" | "possible"; directories: HistoricalDirectory[];
};
type HistoryReport = { completeScans: number; currentScanAtUnix: number | null; applications: HistoricalApplication[] };
type DiagnosticsExport = { path: string; scans: number; directories: number };

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes;
  let index = -1;
  do { value /= 1024; index++; } while (value >= 1024 && index < units.length - 1);
  return `${value.toFixed(value >= 10 ? 1 : 2)} ${units[index]}`;
}

function shortPath(path: string): string {
  const parts = path.split("\\");
  return parts.slice(-2).join("\\");
}

function assessment(result: DirectoryResult): { label: string; className: string } {
  if (result.orphanStatus === "probable_orphan") return { label: "Probable leftover", className: "former" };
  if (result.evidence.some(item => item.kind === "newer_product_version_installed")) return { label: "Possible old version", className: "former" };
  if (result.orphanStatus === "possibly_orphaned") return { label: "Possible leftover", className: "former" };
  if (result.orphanStatus === "associated_with_installed") return { label: "Vendor / shared", className: "matched" };
  if (result.orphanStatus === "not_orphaned") return { label: "Installed match", className: "matched" };
  if (result.orphanStatus === "known_application_data") return { label: "Known data", className: "known" };
  return { label: "Unknown", className: "unknown" };
}

export default function App() {
  const [apps, setApps] = useState<Application[]>([]);
  const [inventoryWarnings, setInventoryWarnings] = useState<string[]>([]);
  const [results, setResults] = useState<DirectoryResult[]>([]);
  const [selectedPath, setSelectedPath] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [currentPath, setCurrentPath] = useState("");
  const [summary, setSummary] = useState<ScanSummary | null>(null);
  const [savedAt, setSavedAt] = useState<number | null>(null);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState<"all" | "matched" | "known" | "former" | "unknown">("all");
  const [query, setQuery] = useState("");
  const [publicData, setPublicData] = useState<PublicDataStatus | null>(null);
  const [updatingData, setUpdatingData] = useState(false);
  const [dataMessage, setDataMessage] = useState("");
  const [history, setHistory] = useState<HistoryReport | null>(null);
  const [exportingDiagnostics, setExportingDiagnostics] = useState(false);
  const [diagnosticsMessage, setDiagnosticsMessage] = useState("");
  const [backend, setBackend] = useState<BackendKind | "connecting" | "unavailable">("connecting");
  const [connectNonce, setConnectNonce] = useState(0);

  useEffect(() => {
    let mounted = true;
    const unlisteners: Array<() => void> = [];
    function showSaved(scan: SavedScan) {
      setApps(scan.inventory.applications);
      setInventoryWarnings(scan.inventory.warnings);
      setResults(scan.results);
      setSummary(scan.summary);
      setSavedAt(scan.capturedAtUnix);
    }
    async function connect() {
      try {
        const connection = await connectBackend();
        if (!mounted) return;
        setBackend(connection.kind);
        setRunning(connection.running);
        const register = (unlisten: () => void) => { if (mounted) unlisteners.push(unlisten); else unlisten(); };
        register(await listenBackend<DirectoryResult>("scan-result", payload => {
          if (mounted) setResults(previous => [...previous, payload]);
        }));
        register(await listenBackend<{path: string}>("scan-progress", payload => {
          if (mounted) setCurrentPath(payload.path);
        }));
        register(await listenBackend<ScanFinishedEvent>("scan-finished", payload => {
          if (!mounted) return;
          setSummary(payload.summary);
          setRunning(false);
          setCurrentPath("");
          if (payload.saveError) setError(payload.saveError);
          if (payload.savedAtUnix !== null || payload.summary.canceled || payload.saveError) {
            void Promise.all([
              invokeBackend<SavedScan | null>("load_latest_scan"),
              invokeBackend<HistoryReport>("load_history_report"),
            ])
              .then(([scan, report]) => { if (mounted) { if (scan) showSaved(scan); setHistory(report); } })
              .catch(cause => { if (mounted) setError(String(cause)); });
          }
        }));
        register(await listenBackend<Inventory>("scan-inventory", payload => {
          if (mounted) { setApps(payload.applications); setInventoryWarnings(payload.warnings); }
        }));
        let saved: SavedScan | null = null;
        try {
          const status = await invokeBackend<PublicDataStatus>("public_data_status");
          if (mounted) setPublicData(status);
        } catch (cause) { if (mounted) setDataMessage(`Public folder data could not be loaded: ${String(cause)}`); }
        try { saved = await invokeBackend<SavedScan | null>("load_latest_scan"); }
        catch (cause) { if (mounted) setError(`Saved scan could not be loaded: ${String(cause)}`); }
        if (saved) {
          if (mounted) showSaved(saved);
          try {
            const report = await invokeBackend<HistoryReport>("load_history_report");
            if (mounted) setHistory(report);
          } catch (cause) { if (mounted) setError(`Historical observations could not be loaded: ${String(cause)}`); }
        } else {
          const inventory = await invokeBackend<Inventory>("installed_applications");
          if (mounted) { setApps(inventory.applications); setInventoryWarnings(inventory.warnings); }
        }
      } catch (cause) {
        if (mounted) { setBackend("unavailable"); setError(`Windows cleaner backend is unavailable: ${String(cause)}`); }
      }
    }
    void connect();
    return () => { mounted = false; unlisteners.forEach(unlisten => unlisten()); disconnectBackend(); };
  }, [connectNonce]);

  const visible = useMemo(() => results.filter(result => {
    if (filter === "matched" && !["not_orphaned", "associated_with_installed"].includes(result.orphanStatus)) return false;
    if (filter === "known" && result.orphanStatus !== "known_application_data") return false;
    if (filter === "former" && !["probable_orphan", "possibly_orphaned"].includes(result.orphanStatus)) return false;
    if (filter === "unknown" && result.orphanStatus !== "unknown") return false;
    const text = `${result.path} ${result.owner?.name ?? ""} ${result.ownerHint ?? ""}`.toLowerCase();
    return text.includes(query.toLowerCase());
  }).sort((a, b) => b.sizeBytes - a.sizeBytes), [results, filter, query]);
  const selected = results.find(result => result.path === selectedPath);
  const total = summary?.bytes ?? results.filter(result => !result.parentPath).reduce((sum, result) => sum + result.sizeBytes, 0);
  const matched = results.filter(result => ["not_orphaned", "associated_with_installed"].includes(result.orphanStatus)).length;
  const known = results.filter(result => result.orphanStatus === "known_application_data").length;
  const former = results.filter(result => ["probable_orphan", "possibly_orphaned"].includes(result.orphanStatus)).length;
  const unknown = results.filter(result => result.orphanStatus === "unknown").length;
  const newlyMissing = history?.applications.filter(application => application.newlyMissing).length ?? 0;
  const connected = backend === "tauri" || backend === "agent";

  async function start() {
    setError(""); setResults([]); setSelectedPath(null); setSummary(null); setSavedAt(null); setCurrentPath(""); setHistory(null); setRunning(true);
    try { await invokeBackend("start_scan"); }
    catch (cause) {
      setError(String(cause)); setRunning(false);
      try {
        const saved = await invokeBackend<SavedScan | null>("load_latest_scan");
        if (saved) { setApps(saved.inventory.applications); setResults(saved.results); setSummary(saved.summary); setSavedAt(saved.capturedAtUnix); }
      } catch { /* The original start error remains visible. */ }
    }
  }

  async function cancel() {
    try { await invokeBackend("cancel_scan"); }
    catch (cause) { setError(String(cause)); }
  }

  async function updateData() {
    setUpdatingData(true); setDataMessage("");
    try {
      const status = await invokeBackend<PublicDataStatus>("update_public_data");
      setPublicData(status);
      setDataMessage(status.gameDirectories || status.cleanerDirectories
        ? "Folder data updated. Refresh the scan to apply it to the directory results."
        : "No folder data could be downloaded. The scan can still run without it.");
    } catch (cause) { setDataMessage(`Folder data update failed: ${String(cause)}`); }
    finally { setUpdatingData(false); }
  }

  async function exportDiagnostics() {
    setExportingDiagnostics(true); setDiagnosticsMessage("");
    try {
      const exported = await invokeBackend<DiagnosticsExport>("export_diagnostics");
      setDiagnosticsMessage(`Exported ${exported.scans} retained scan${exported.scans === 1 ? "" : "s"} and ${exported.directories} directory record${exported.directories === 1 ? "" : "s"} to ${exported.path}`);
    } catch (cause) { setDiagnosticsMessage(`Diagnostics export failed: ${String(cause)}`); }
    finally { setExportingDiagnostics(false); }
  }

  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark">◎</div><div><strong>Orphan Cleaner</strong><span>Windows storage explorer</span></div></div>
      <div className="nav-label">WORKSPACE</div>
      <div className="nav-item active">▦ <span>Directory inventory</span></div>
      <div className="sidebar-bottom"><span className="read-only-dot" /> Read-only preview <small>No files can be deleted in this version.</small></div>
    </aside>
    <main className="main">
      <header className="topbar"><div><div className="eyebrow">LOCAL ANALYSIS · WINDOWS 10/11</div><h1>Directory inventory</h1><p>See which application data can be linked to installed software.</p></div><div className="top-actions">{running ? <button className="secondary" onClick={cancel}>Cancel scan</button> : <button className="primary" onClick={() => void start()} disabled={!connected}>{savedAt ? "Refresh scan" : "Start scan"}</button>}</div></header>
      {backend === "connecting" && <div className="notice">Connecting to the Windows cleaner backend…</div>}
      {backend === "agent" && <div className="notice connected">Connected to the local Rust cleaner agent. The web interface has native scan access.</div>}
      {backend === "unavailable" && <div className="notice error notice-action"><span>Start the local Rust agent with <code>npm run agent</code>, then reconnect.</span><button className="secondary" onClick={() => { setError(""); setBackend("connecting"); setConnectNonce(value => value + 1); }}>Reconnect</button></div>}
      {savedAt && !running && <div className="notice">Saved scan from {new Date(savedAt * 1000).toLocaleString()}. Results may have changed since then; refresh when you want current data.</div>}
      {error && <div className="notice error">{error}</div>}
      {inventoryWarnings.map((warning, index) => <div className="notice" key={index}>{warning}</div>)}
      <div className="public-data"><div><strong>Public folder data</strong><span>{publicData?.updatedAtUnix ? `Updated ${new Date(publicData.updatedAtUnix * 1000).toLocaleString()} · ` : "Not downloaded · "}{publicData?.gameDirectories ?? 0} game folder names · {publicData?.cleanerDirectories ?? 0} cleaner folder names</span><small>Read-only hints from <a href="https://github.com/mtkennerly/ludusavi-manifest" target="_blank" rel="noreferrer">Ludusavi</a> (MIT repository; sourced partly from PCGamingWiki) and <a href="https://github.com/MoscaDotTo/Winapp2" target="_blank" rel="noreferrer">Winapp2</a> (CC BY-SA 4.0). A path match does not prove that a whole folder is disposable.</small></div><button className="secondary" disabled={!connected || updatingData || running} onClick={() => void updateData()}>{updatingData ? "Updating…" : "Update folder data"}</button></div>
      {dataMessage && <div className="notice">{dataMessage}</div>}
      {publicData?.warnings.map((warning, index) => <div className="notice" key={index}>{warning}</div>)}
      <div className="public-data diagnostics"><div><strong>Diagnostics export</strong><span>Privacy-reviewed JSON for troubleshooting</span><small>Contains installed application names and versions, top-level and positively matched nested directory paths, aggregate sizes and counts, classifier evidence, warnings, and up to ten complete scans. User-profile and app-data prefixes are redacted. File contents and individual filenames are not included.</small></div><button className="secondary" disabled={!connected || exportingDiagnostics || running} onClick={() => void exportDiagnostics()}>{exportingDiagnostics ? "Exporting…" : "Export diagnostics"}</button></div>
      {diagnosticsMessage && <div className="notice diagnostics-message">{diagnosticsMessage}</div>}
      <section className="stats">
        <div><span>Installed apps found</span><strong>{apps.length}</strong><small>Registry and current-user MSIX</small></div>
        <div><span>Directories inspected</span><strong>{results.length}</strong><small>{running ? "Scan in progress" : summary ? summary.canceled ? "Scan canceled" : "Scan complete" : "Awaiting scan"}</small></div>
        <div><span>Linked to installed apps</span><strong>{matched}</strong><small>Includes shared vendor associations</small></div>
        <div><span>Inspected storage</span><strong>{formatBytes(total)}</strong><small>Excludes inaccessible entries</small></div>
      </section>
      {running && <div className="progress"><div className="progress-pulse" /><div><strong>Scanning directories…</strong><span title={currentPath}>{currentPath || "Preparing application inventory"}</span></div></div>}
      {summary && summary.skippedEntries > 0 && <div className="notice">{summary.skippedEntries.toLocaleString()} entries were inaccessible or skipped, including reparse points. Sizes may be incomplete.</div>}
      {summary?.warnings.map((warning, index) => <div className="notice" key={index}>{warning}</div>)}
      {summary && <div className="scan-coverage" title={summary.scannedRoots.join("\n")}>Scanned roots: {summary.scannedRoots.map(root => root.split(": ")[0]).join(", ") || "none"}{summary.canceled ? " (partial scan)" : ""}</div>}
      {history && history.completeScans >= 2 && <section className="history-section">
        <div className="section-heading"><div><h2>Previously observed applications</h2><p>{newlyMissing ? `${newlyMissing} application${newlyMissing === 1 ? "" : "s"} disappeared since the previous complete scan.` : "No newly missing applications were identified in the latest complete scan."} Historical ownership is evidence, not deletion approval.</p></div><span className="history-retention">Based on {history.completeScans} retained scans</span></div>
        {history.applications.length > 0 ? <div className="history-cards">{history.applications.map(item => <button className="history-card" key={item.application.id} onClick={() => { setFilter("former"); setQuery(""); setSelectedPath(item.directories[0]?.path ?? null); }}>
          <span className={`history-status ${item.newlyMissing ? "new" : ""}`}>{item.newlyMissing ? "New since previous scan" : "Previously detected"}</span>
          <strong>{item.application.name}</strong>
          <small>{item.application.publisher ?? "Publisher unknown"}{item.lastSeenAtUnix ? ` · Last installed observation ${new Date(item.lastSeenAtUnix * 1000).toLocaleString()}` : " · Installed observation is older than retained history"}</small>
          <div><span>{formatBytes(item.remainingBytes)} remaining</span><span>{item.directories.length} director{item.directories.length === 1 ? "y" : "ies"}</span><span>{item.confidence === "probable" ? "Strong path history" : "Name-based path history"}</span></div>
        </button>)}</div> : <div className="history-empty">No remaining directory is linked to an application that disappeared from the retained inventories.</div>}
      </section>}
      <div className="section-heading"><div><h2>Application data</h2><p>Unmatched means ownership is unknown. It does not mean safe to remove.</p></div></div>
      <div className="toolbar"><div className="tabs"><button className={filter === "all" ? "selected" : ""} onClick={() => setFilter("all")}>All <span>{results.length}</span></button><button className={filter === "matched" ? "selected" : ""} onClick={() => setFilter("matched")}>Installed <span>{matched}</span></button><button className={filter === "known" ? "selected" : ""} onClick={() => setFilter("known")}>Known data <span>{known}</span></button><button className={filter === "former" ? "selected" : ""} onClick={() => setFilter("former")}>Former app data <span>{former}</span></button><button className={filter === "unknown" ? "selected" : ""} onClick={() => setFilter("unknown")}>Unknown <span>{unknown}</span></button></div><input aria-label="Search directories" placeholder="Search directories or applications" value={query} onChange={event => setQuery(event.target.value)} /></div>
      <div className="content-grid"><div className="table-wrap"><table><thead><tr><th>Directory</th><th>Size</th><th>Probable owner</th></tr></thead><tbody>{visible.map(result => <tr key={result.path} className={selectedPath === result.path ? "selected-row" : ""} onClick={() => setSelectedPath(result.path)} onKeyDown={event => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); setSelectedPath(result.path); } }} tabIndex={0} aria-selected={selectedPath === result.path}><td><strong>{shortPath(result.path)}</strong><small title={result.path}>{result.path}</small></td><td>{formatBytes(result.sizeBytes)}</td><td><span className="owner-name">{result.owner?.name ?? result.ownerHint ?? (result.ownership === "shared" ? result.path.split("\\").pop() || "Shared application data" : "Unresolved")}</span><span className={`badge ${assessment(result).className}`}>{assessment(result).label}</span></td></tr>)}</tbody></table>{visible.length === 0 && <div className="empty">{results.length === 0 ? "Start a scan to inspect application data directories." : "No directories match these filters."}</div>}</div>
      <aside className="details">{selected ? <><div className="details-head"><span>DIRECTORY DETAILS</span><h3>{shortPath(selected.path)}</h3><p>{selected.path}</p>{selected.parentPath && <small>Matched inside vendor container {selected.parentPath}</small>}</div><div className="detail-grid"><div><span>Size</span><strong>{formatBytes(selected.sizeBytes)}</strong></div><div><span>Files</span><strong>{selected.fileCount.toLocaleString()}</strong></div><div><span>Subfolders</span><strong>{selected.directoryCount.toLocaleString()}</strong></div><div><span>Source</span><strong>{selected.root}</strong></div></div><h4>Ownership assessment</h4><p>{["probable_orphan", "possibly_orphaned"].includes(selected.orphanStatus) ? selected.evidence.some(item => item.kind === "newer_product_version_installed") ? `A previous scan linked this exact directory to ${selected.owner?.name ?? "an installed version"}, and a strictly newer version is now registered. This may still contain settings or other valuable data.` : selected.owner ? `Previously associated with ${selected.owner.name}. That app is absent from the current inventory. This may still contain valuable data.` : `${selected.ownerHint ?? "This application"} is known application data, but no matching installed registration was found. Launcher-managed or portable software may still use it.` : selected.orphanStatus === "associated_with_installed" ? "The folder name is associated with installed software, but a single owner cannot be established. Its contents may include older or unrelated data." : selected.orphanStatus === "known_application_data" ? "This is a recognized application or system data location. Its current owner and cleanup safety have not been established." : selected.owner ? `Associated with installed application ${selected.owner.name}.` : "No reliable owner identified. This directory is not classified as an orphan."}</p>{selected.evidence.some(item => item.kind === "ludusavi_game_data") && <p className="detail-warning">This folder may contain valuable game data such as saves or settings. Check the exact files before removing anything.</p>}<h4>Evidence</h4>{selected.evidence.length ? selected.evidence.map((item, index) => <div className="evidence" key={index}><span>{item.strength}</span><p>{item.description}</p></div>) : <p className="muted">No ownership evidence yet.</p>}{selected.skippedEntries > 0 && <p className="detail-warning">{selected.skippedEntries} entries were skipped; the displayed size may be incomplete.</p>}<div className="detail-foot">Read only · No cleanup actions available</div></> : <div className="detail-empty"><div>◎</div><h3>Select a directory</h3><p>Review the evidence behind each ownership assessment.</p></div>}</aside></div>
    </main>
  </div>;
}
