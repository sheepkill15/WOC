import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

type Application = { id: string; name: string; publisher: string | null; version: string | null; installLocation: string | null; packageFamilyName: string | null; sources: string[] };
type Inventory = { applications: Application[]; warnings: string[] };
type Evidence = { kind: string; description: string; strength: string };
type DirectoryResult = {
  path: string; root: string; sizeBytes: number; fileCount: number; directoryCount: number;
  newestModifiedUnix: number | null; skippedEntries: number; owner: Application | null;
  ownership: string; orphanStatus: string; evidence: Evidence[];
};
type ScanSummary = { directories: number; bytes: number; skippedEntries: number; canceled: boolean; scannedRoots: string[]; warnings: string[] };
type SavedScan = { capturedAtUnix: number; inventory: Inventory; summary: ScanSummary; results: DirectoryResult[] };
type ScanFinishedEvent = { summary: ScanSummary; savedAtUnix: number | null; saveError: string | null };
const native = "__TAURI_INTERNALS__" in window;

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
  if (result.orphanStatus === "possibly_orphaned") return { label: "Possible leftover", className: "former" };
  if (result.orphanStatus === "not_orphaned") return { label: "Installed match", className: "matched" };
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
  const [filter, setFilter] = useState<"all" | "matched" | "former" | "unknown">("all");
  const [query, setQuery] = useState("");

  useEffect(() => {
    if (!native) return;
    let mounted = true;
    const unlisteners: UnlistenFn[] = [];
    function showSaved(scan: SavedScan) {
      setApps(scan.inventory.applications);
      setInventoryWarnings(scan.inventory.warnings);
      setResults(scan.results);
      setSummary(scan.summary);
      setSavedAt(scan.capturedAtUnix);
    }
    async function connect() {
      try {
        const register = (unlisten: UnlistenFn) => { if (mounted) unlisteners.push(unlisten); else unlisten(); };
        register(await listen<DirectoryResult>("scan-result", event => {
          if (mounted) setResults(previous => [...previous, event.payload]);
        }));
        register(await listen<{path: string}>("scan-progress", event => {
          if (mounted) setCurrentPath(event.payload.path);
        }));
        register(await listen<ScanFinishedEvent>("scan-finished", event => {
          if (!mounted) return;
          setSummary(event.payload.summary);
          setRunning(false);
          setCurrentPath("");
          if (event.payload.saveError) setError(event.payload.saveError);
          if (event.payload.savedAtUnix !== null || event.payload.summary.canceled || event.payload.saveError) {
            void invoke<SavedScan | null>("load_latest_scan")
              .then(scan => { if (mounted && scan) showSaved(scan); })
              .catch(cause => { if (mounted) setError(String(cause)); });
          }
        }));
        register(await listen<Inventory>("scan-inventory", event => {
          if (mounted) { setApps(event.payload.applications); setInventoryWarnings(event.payload.warnings); }
        }));
        let saved: SavedScan | null = null;
        try { saved = await invoke<SavedScan | null>("load_latest_scan"); }
        catch (cause) { if (mounted) setError(`Saved scan could not be loaded: ${String(cause)}`); }
        if (saved) {
          if (mounted) showSaved(saved);
        } else {
          const inventory = await invoke<Inventory>("installed_applications");
          if (mounted) { setApps(inventory.applications); setInventoryWarnings(inventory.warnings); }
        }
      } catch (cause) {
        if (mounted) setError(String(cause));
      }
    }
    void connect();
    return () => { mounted = false; unlisteners.forEach(unlisten => unlisten()); };
  }, []);

  const visible = useMemo(() => results.filter(result => {
    if (filter === "matched" && result.orphanStatus !== "not_orphaned") return false;
    if (filter === "former" && !["probable_orphan", "possibly_orphaned"].includes(result.orphanStatus)) return false;
    if (filter === "unknown" && result.orphanStatus !== "unknown") return false;
    const text = `${result.path} ${result.owner?.name ?? ""}`.toLowerCase();
    return text.includes(query.toLowerCase());
  }).sort((a, b) => b.sizeBytes - a.sizeBytes), [results, filter, query]);
  const selected = results.find(result => result.path === selectedPath);
  const total = results.reduce((sum, result) => sum + result.sizeBytes, 0);
  const matched = results.filter(result => result.orphanStatus === "not_orphaned").length;
  const former = results.filter(result => ["probable_orphan", "possibly_orphaned"].includes(result.orphanStatus)).length;
  const unknown = results.filter(result => result.orphanStatus === "unknown").length;

  async function start() {
    setError(""); setResults([]); setSelectedPath(null); setSummary(null); setSavedAt(null); setCurrentPath(""); setRunning(true);
    try { await invoke("start_scan"); }
    catch (cause) {
      setError(String(cause)); setRunning(false);
      try {
        const saved = await invoke<SavedScan | null>("load_latest_scan");
        if (saved) { setApps(saved.inventory.applications); setResults(saved.results); setSummary(saved.summary); setSavedAt(saved.capturedAtUnix); }
      } catch { /* The original start error remains visible. */ }
    }
  }

  async function cancel() {
    try { await invoke("cancel_scan"); }
    catch (cause) { setError(String(cause)); }
  }

  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark">◎</div><div><strong>Orphan Cleaner</strong><span>Windows storage explorer</span></div></div>
      <div className="nav-label">WORKSPACE</div>
      <div className="nav-item active">▦ <span>Directory inventory</span></div>
      <div className="sidebar-bottom"><span className="read-only-dot" /> Read-only preview <small>No files can be deleted in this version.</small></div>
    </aside>
    <main className="main">
      <header className="topbar"><div><div className="eyebrow">LOCAL ANALYSIS · WINDOWS 10/11</div><h1>Directory inventory</h1><p>See which application data can be linked to installed software.</p></div><div className="top-actions">{running ? <button className="secondary" onClick={cancel}>Cancel scan</button> : <button className="primary" onClick={() => void start()} disabled={!native}>{savedAt ? "Refresh scan" : "Start scan"}</button>}</div></header>
      {!native && <div className="notice">Open this project with Tauri to scan this Windows installation. The web preview cannot access your application data.</div>}
      {savedAt && !running && <div className="notice">Saved scan from {new Date(savedAt * 1000).toLocaleString()}. Results may have changed since then; refresh when you want current data.</div>}
      {error && <div className="notice error">{error}</div>}
      {inventoryWarnings.map((warning, index) => <div className="notice" key={index}>{warning}</div>)}
      <section className="stats">
        <div><span>Installed apps found</span><strong>{apps.length}</strong><small>Registry and current-user MSIX</small></div>
        <div><span>Directories inspected</span><strong>{results.length}</strong><small>{running ? "Scan in progress" : summary ? summary.canceled ? "Scan canceled" : "Scan complete" : "Awaiting scan"}</small></div>
        <div><span>Matched to installed apps</span><strong>{matched}</strong><small>Exact name or install path</small></div>
        <div><span>Inspected storage</span><strong>{formatBytes(total)}</strong><small>Excludes inaccessible entries</small></div>
      </section>
      {running && <div className="progress"><div className="progress-pulse" /><div><strong>Scanning directories…</strong><span title={currentPath}>{currentPath || "Preparing application inventory"}</span></div></div>}
      {summary && summary.skippedEntries > 0 && <div className="notice">{summary.skippedEntries.toLocaleString()} entries were inaccessible or skipped, including reparse points. Sizes may be incomplete.</div>}
      {summary?.warnings.map((warning, index) => <div className="notice" key={index}>{warning}</div>)}
      {summary && <div className="scan-coverage" title={summary.scannedRoots.join("\n")}>Scanned roots: {summary.scannedRoots.map(root => root.split(": ")[0]).join(", ") || "none"}{summary.canceled ? " (partial scan)" : ""}</div>}
      <div className="section-heading"><div><h2>Application data</h2><p>Unmatched means ownership is unknown. It does not mean safe to remove.</p></div></div>
      <div className="toolbar"><div className="tabs"><button className={filter === "all" ? "selected" : ""} onClick={() => setFilter("all")}>All <span>{results.length}</span></button><button className={filter === "matched" ? "selected" : ""} onClick={() => setFilter("matched")}>Installed <span>{matched}</span></button><button className={filter === "former" ? "selected" : ""} onClick={() => setFilter("former")}>Former app data <span>{former}</span></button><button className={filter === "unknown" ? "selected" : ""} onClick={() => setFilter("unknown")}>Unknown <span>{unknown}</span></button></div><input aria-label="Search directories" placeholder="Search directories or applications" value={query} onChange={event => setQuery(event.target.value)} /></div>
      <div className="content-grid"><div className="table-wrap"><table><thead><tr><th>Directory</th><th>Size</th><th>Probable owner</th></tr></thead><tbody>{visible.map(result => <tr key={result.path} className={selectedPath === result.path ? "selected-row" : ""} onClick={() => setSelectedPath(result.path)} onKeyDown={event => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); setSelectedPath(result.path); } }} tabIndex={0} aria-selected={selectedPath === result.path}><td><strong>{shortPath(result.path)}</strong><small title={result.path}>{result.path}</small></td><td>{formatBytes(result.sizeBytes)}</td><td><span className="owner-name">{result.owner?.name ?? "Unresolved"}</span><span className={`badge ${assessment(result).className}`}>{assessment(result).label}</span></td></tr>)}</tbody></table>{visible.length === 0 && <div className="empty">{results.length === 0 ? "Start a scan to inspect application data directories." : "No directories match these filters."}</div>}</div>
      <aside className="details">{selected ? <><div className="details-head"><span>DIRECTORY DETAILS</span><h3>{shortPath(selected.path)}</h3><p>{selected.path}</p></div><div className="detail-grid"><div><span>Size</span><strong>{formatBytes(selected.sizeBytes)}</strong></div><div><span>Files</span><strong>{selected.fileCount.toLocaleString()}</strong></div><div><span>Subfolders</span><strong>{selected.directoryCount.toLocaleString()}</strong></div><div><span>Source</span><strong>{selected.root}</strong></div></div><h4>Ownership assessment</h4><p>{["probable_orphan", "possibly_orphaned"].includes(selected.orphanStatus) ? `Previously associated with ${selected.owner?.name}. That app is absent from the current inventory. This may still contain valuable data.` : selected.owner ? `Associated with installed application ${selected.owner.name}.` : "No reliable owner identified. This directory is not classified as an orphan."}</p><h4>Evidence</h4>{selected.evidence.length ? selected.evidence.map((item, index) => <div className="evidence" key={index}><span>{item.strength}</span><p>{item.description}</p></div>) : <p className="muted">No ownership evidence yet.</p>}{selected.skippedEntries > 0 && <p className="detail-warning">{selected.skippedEntries} entries were skipped; the displayed size may be incomplete.</p>}<div className="detail-foot">Read only · No cleanup actions available</div></> : <div className="detail-empty"><div>◎</div><h3>Select a directory</h3><p>Review the evidence behind each ownership assessment.</p></div>}</aside></div>
    </main>
  </div>;
}
