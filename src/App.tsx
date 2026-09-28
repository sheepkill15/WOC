import { useCallback, useEffect, useState } from "react";
import { useCleaner } from "./store";
import { formatAge, formatBytes } from "./format";
import { Icon, Notice } from "./ui";
import { Overview } from "./views/Overview";
import { Cleanup } from "./views/Cleanup";
import { Uninstalled } from "./views/Uninstalled";
import { Inventory } from "./views/Inventory";
import { References } from "./views/References";
import { Applications } from "./views/Applications";
import { Quarantine } from "./views/Quarantine";
import { Rules } from "./views/Rules";
import { FolderAnalyzer } from "./views/FolderAnalyzer";
import { SettingsView, type Theme } from "./views/SettingsView";

export type Route = "overview" | "cleanup" | "uninstalled" | "inventory" | "references" | "apps" | "quarantine" | "rules" | "analyzer" | "settings";
const routes: Route[] = ["overview", "cleanup", "uninstalled", "inventory", "references", "apps", "quarantine", "rules", "analyzer", "settings"];

function routeFromHash(): Route {
  const value = window.location.hash.replace(/^#\/?/, "") as Route;
  return routes.includes(value) ? value : "overview";
}

function readTheme(): Theme {
  try { const value = localStorage.getItem("orphan-cleaner-theme"); return value === "light" || value === "dark" ? value : "system"; } catch { return "system"; }
}

export default function App() {
  const cleaner = useCleaner();
  const { backend, backendError, running, runningMode, progressPath, results, savedAt, summary, candidates, removed, references, quarantine, apps, rules, toasts, scanError, inventoryWarnings } = cleaner;
  const [route, setRoute] = useState<Route>(routeFromHash);
  const [focusPath, setFocusPath] = useState<string | null>(null);
  const [theme, setThemeState] = useState<Theme>(readTheme);
  const [modeMenu, setModeMenu] = useState(false);
  const connected = backend === "tauri" || backend === "agent";

  useEffect(() => {
    const onHash = () => setRoute(routeFromHash());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);
  useEffect(() => {
    if (theme === "system") document.documentElement.removeAttribute("data-theme"); else document.documentElement.setAttribute("data-theme", theme);
  }, [theme]);
  const setTheme = (value: Theme) => { setThemeState(value); try { localStorage.setItem("orphan-cleaner-theme", value); } catch { /* storage unavailable */ } };
  const navigate = useCallback((next: Route) => { window.location.hash = `/${next}`; setRoute(next); document.querySelector(".main")?.scrollTo({ top: 0 }); }, []);
  const openFolder = useCallback((path: string) => { setFocusPath(path); navigate("inventory"); }, [navigate]);
  const clearFocus = useCallback(() => setFocusPath(null), []);

  const deadCount = references?.references.filter(reference => reference.status === "dead").length ?? 0;
  const highGroups = candidates?.groups.filter(group => group.priority === "high").length ?? 0;
  const nav: { section?: string; route: Route; label: string; icon: string; badge?: string | number; tone?: string }[] = [
    { route: "overview", label: "Overview", icon: "overview" },
    { route: "cleanup", label: "Cleanup", icon: "cleanup", badge: candidates?.recommendedBytes ? formatBytes(candidates.recommendedBytes) : highGroups || undefined, tone: "accent" },
    { route: "uninstalled", label: "Uninstalled apps", icon: "uninstalled", badge: removed?.applications.length || undefined, tone: "warn" },
    { section: "Explore", route: "inventory", label: "All folders", icon: "folders", badge: results.length || undefined },
    { route: "references", label: "References", icon: "references", badge: deadCount || undefined, tone: deadCount ? "warn" : undefined },
    { route: "apps", label: "Installed apps", icon: "apps", badge: apps.length || undefined },
    { section: "Safety", route: "quarantine", label: "Quarantine", icon: "quarantine", badge: quarantine?.items.length || undefined },
    { route: "rules", label: "Ignore rules", icon: "rules", badge: rules.length || undefined },
    { section: "Tools", route: "analyzer", label: "Folder analyzer", icon: "analyzer" },
    { route: "settings", label: "Settings", icon: "settings" },
  ];

  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-mark"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><circle cx="12" cy="12" r="8" /><circle cx="12" cy="12" r="3" /><path d="M12 2v3M12 19v3M2 12h3M19 12h3" /></svg></div>
        <div><strong>Orphan Cleaner</strong><span>Ownership-aware cleanup</span></div>
      </div>
      <nav className="nav">
        {nav.map(item => <div key={item.route}>
          {item.section && <div className="nav-label">{item.section}</div>}
          <button className={`nav-item ${route === item.route ? "active" : ""}`} onClick={() => navigate(item.route)} aria-current={route === item.route ? "page" : undefined}>
            <Icon name={item.icon} size={17} /><span>{item.label}</span>
            {item.badge !== undefined && <span className={`nav-badge ${item.tone ? `tone-${item.tone}` : ""}`}>{item.badge}</span>}
          </button>
        </div>)}
      </nav>
      <div className="scan-card">
        {running ? <>
          <div className="scan-card-head"><span className="pulse" /><strong>{runningMode === "deep" ? "Deep scan" : "Quick scan"} running</strong></div>
          <div className="scan-progress"><span /></div>
          <small title={progressPath}>{progressPath || "Preparing…"}</small>
          <small>{results.length.toLocaleString()} folders inspected</small>
          <button className="secondary full" onClick={() => void cleaner.cancelScan()}><Icon name="stop" size={14} /> Cancel</button>
        </> : <>
          <div className="scan-card-head"><span className={`status-dot ${connected ? "on" : backend === "connecting" ? "wait" : "off"}`} />
            <strong>{connected ? (backend === "agent" ? "Local agent" : "Ready") : backend === "connecting" ? "Connecting…" : "Backend offline"}</strong></div>
          <small>{savedAt ? `Last scan ${formatAge(savedAt)}${summary?.mode ? ` · ${summary.mode}` : ""}` : "No saved scan yet"}</small>
          <div className="split-button">
            <button className="primary" disabled={!connected} onClick={() => void cleaner.startScan()}><Icon name="refresh" size={14} /> {savedAt ? "Scan again" : "Start scan"}</button>
            <button className="primary caret" disabled={!connected} aria-label="Choose scan mode" onClick={() => setModeMenu(value => !value)}><Icon name="chevron" size={14} /></button>
            {modeMenu && <div className="mode-menu" onMouseLeave={() => setModeMenu(false)}>
              <button onClick={() => { setModeMenu(false); void cleaner.startScan("quick"); }}><strong>Quick scan</strong><span>AppData, ProgramData, references</span></button>
              <button onClick={() => { setModeMenu(false); void cleaner.startScan("deep"); }}><strong>Deep scan</strong><span>+ Program Files, dev caches, executables</span></button>
            </div>}
          </div>
        </>}
      </div>
    </aside>
    <main className="main">
      {backend === "unavailable" && <Notice tone="error" action={<button className="secondary" onClick={cleaner.reconnect}>Reconnect</button>}>
        <strong>The Windows cleaner backend is not reachable.</strong> {backendError} In the browser, start the local agent with <code>npm run agent</code>. The Folder analyzer works without it.
      </Notice>}
      {scanError && <Notice tone="warn">{scanError}</Notice>}
      {inventoryWarnings.length > 0 && route === "overview" && <Notice tone="warn">{inventoryWarnings.join(" ")} History-based conclusions are paused until the inventory is complete.</Notice>}
      {route === "overview" && <Overview navigate={navigate} />}
      {route === "cleanup" && <Cleanup />}
      {route === "uninstalled" && <Uninstalled openFolder={openFolder} />}
      {route === "inventory" && <Inventory focusPath={focusPath} clearFocus={clearFocus} />}
      {route === "references" && <References />}
      {route === "apps" && <Applications openFolder={openFolder} />}
      {route === "quarantine" && <Quarantine navigate={navigate} />}
      {route === "rules" && <Rules />}
      {route === "analyzer" && <FolderAnalyzer connected={connected} />}
      {route === "settings" && <SettingsView theme={theme} setTheme={setTheme} />}
    </main>
    <div className="toasts" aria-live="polite">
      {toasts.map(toast => <div key={toast.id} className={`toast toast-${toast.tone}`}>
        <Icon name={toast.tone === "error" ? "alert" : toast.tone === "success" ? "check" : "info"} size={16} /><span>{toast.text}</span>
        <button className="icon-button" onClick={() => cleaner.dismissToast(toast.id)} aria-label="Dismiss"><Icon name="close" size={14} /></button>
      </div>)}
    </div>
  </div>;
}
