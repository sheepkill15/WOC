import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { call, connectBackend, disconnectBackend, listenBackend, type BackendKind } from "./backend";
import type {
  AppInfo, Application, CandidateReport, CleanupOutcome, CleanupPlan, DefinitionsStatus, DiagnosticsExport, DirectoryResult,
  HistoryReport, IgnoreRule, Inventory, PostUninstallReport, PublicDataStatus, QuarantineReport, ReferenceInventory,
  RemovedReport, SavedScan, ScanFinishedEvent, ScanSummary, Settings,
} from "./types";

export type BackendState = BackendKind | "connecting" | "unavailable";
export type Toast = { id: number; tone: "info" | "success" | "error"; text: string };

type CleanerState = {
  backend: BackendState;
  backendError: string;
  appInfo: AppInfo | null;
  apps: Application[];
  inventoryWarnings: string[];
  results: DirectoryResult[];
  references: ReferenceInventory | null;
  summary: ScanSummary | null;
  savedAt: number | null;
  running: boolean;
  runningMode: string | null;
  progressPath: string;
  scanError: string;
  history: HistoryReport | null;
  candidates: CandidateReport | null;
  removed: RemovedReport | null;
  postUninstall: PostUninstallReport | null;
  quarantine: QuarantineReport | null;
  rules: IgnoreRule[];
  settings: Settings | null;
  publicData: PublicDataStatus | null;
  definitions: DefinitionsStatus | null;
  toasts: Toast[];
};

type CleanerActions = {
  reconnect(): void;
  startScan(mode?: "quick" | "deep"): Promise<void>;
  cancelScan(): Promise<void>;
  runPostUninstall(): Promise<void>;
  refreshAfterChange(): Promise<void>;
  refreshQuarantine(): Promise<void>;
  addRule(kind: IgnoreRule["kind"], value: string, label: string): Promise<void>;
  removeRule(id: number): Promise<void>;
  planCleanup(paths: string[]): Promise<CleanupPlan>;
  executeCleanup(paths: string[], acknowledgeWarnings: boolean): Promise<CleanupOutcome>;
  restore(id: number): Promise<void>;
  purge(id: number): Promise<void>;
  saveSettings(settings: Settings): Promise<void>;
  updatePublicData(): Promise<void>;
  exportDiagnostics(): Promise<DiagnosticsExport | null>;
  openPath(path: string): Promise<void>;
  notify(text: string, tone?: Toast["tone"]): void;
  dismissToast(id: number): void;
};

const CleanerContext = createContext<(CleanerState & CleanerActions) | null>(null);

export function useCleaner() {
  const value = useContext(CleanerContext);
  if (!value) throw new Error("useCleaner must be used inside CleanerProvider");
  return value;
}

function message(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
}

export function CleanerProvider({ children }: { children: ReactNode }) {
  const [backend, setBackend] = useState<BackendState>("connecting");
  const [backendError, setBackendError] = useState("");
  const [appInfo, setAppInfo] = useState<AppInfo | null>(null);
  const [apps, setApps] = useState<Application[]>([]);
  const [inventoryWarnings, setInventoryWarnings] = useState<string[]>([]);
  const [results, setResults] = useState<DirectoryResult[]>([]);
  const [references, setReferences] = useState<ReferenceInventory | null>(null);
  const [summary, setSummary] = useState<ScanSummary | null>(null);
  const [savedAt, setSavedAt] = useState<number | null>(null);
  const [running, setRunning] = useState(false);
  const [runningMode, setRunningMode] = useState<string | null>(null);
  const [progressPath, setProgressPath] = useState("");
  const [scanError, setScanError] = useState("");
  const [history, setHistory] = useState<HistoryReport | null>(null);
  const [candidates, setCandidates] = useState<CandidateReport | null>(null);
  const [removed, setRemoved] = useState<RemovedReport | null>(null);
  const [postUninstall, setPostUninstall] = useState<PostUninstallReport | null>(null);
  const [quarantine, setQuarantine] = useState<QuarantineReport | null>(null);
  const [rules, setRules] = useState<IgnoreRule[]>([]);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [publicData, setPublicData] = useState<PublicDataStatus | null>(null);
  const [definitions, setDefinitions] = useState<DefinitionsStatus | null>(null);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [nonce, setNonce] = useState(0);
  const buffer = useRef<DirectoryResult[]>([]);
  const toastId = useRef(0);

  const notify = useCallback((text: string, tone: Toast["tone"] = "info") => {
    const id = ++toastId.current;
    setToasts(previous => [...previous.slice(-3), { id, tone, text }]);
    window.setTimeout(() => setToasts(previous => previous.filter(toast => toast.id !== id)), tone === "error" ? 9000 : 5000);
  }, []);
  const dismissToast = useCallback((id: number) => setToasts(previous => previous.filter(toast => toast.id !== id)), []);

  const showSaved = useCallback((scan: SavedScan) => {
    setApps(scan.inventory.applications);
    setInventoryWarnings(scan.inventory.warnings);
    setResults(scan.results);
    setSummary(scan.summary);
    setSavedAt(scan.capturedAtUnix);
    setReferences(scan.references ?? null);
  }, []);

  const loadDerived = useCallback(async () => {
    const [historyReport, candidateReport, ruleList] = await Promise.all([
      call<HistoryReport>("load_history_report"),
      call<CandidateReport>("load_candidates"),
      call<IgnoreRule[]>("list_ignore_rules"),
    ]);
    setHistory(historyReport);
    setCandidates(candidateReport);
    setRules(ruleList);
  }, []);

  const refreshQuarantine = useCallback(async () => {
    try { setQuarantine(await call<QuarantineReport>("list_quarantine")); }
    catch (cause) { notify(`Quarantine could not be loaded: ${message(cause)}`, "error"); }
  }, [notify]);

  useEffect(() => {
    let mounted = true;
    const unlisteners: Array<() => void> = [];
    const flush = window.setInterval(() => {
      if (buffer.current.length && mounted) {
        const batch = buffer.current;
        buffer.current = [];
        setResults(previous => [...previous, ...batch]);
      }
    }, 300);
    async function connect() {
      try {
        const connection = await connectBackend();
        if (!mounted) return;
        setBackend(connection.kind);
        setBackendError("");
        setRunning(connection.running);
        const register = (unlisten: () => void) => { if (mounted) unlisteners.push(unlisten); else unlisten(); };
        register(await listenBackend<DirectoryResult>("scan-result", payload => { buffer.current.push(payload); }));
        register(await listenBackend<{ path: string }>("scan-progress", payload => { if (mounted) setProgressPath(payload.path); }));
        register(await listenBackend<Inventory>("scan-inventory", payload => {
          if (mounted) { setApps(payload.applications); setInventoryWarnings(payload.warnings); }
        }));
        register(await listenBackend<ReferenceInventory>("scan-references", payload => { if (mounted) setReferences(payload); }));
        register(await listenBackend<ScanFinishedEvent>("scan-finished", payload => {
          if (!mounted) return;
          const batch = buffer.current;
          buffer.current = [];
          if (batch.length) setResults(previous => [...previous, ...batch]);
          setSummary(payload.summary);
          setRunning(false);
          setRunningMode(null);
          setProgressPath("");
          if (payload.saveError) setScanError(payload.saveError);
          if (payload.summary.canceled) notify("Scan canceled. The previous saved scan is still available.");
          else if (payload.savedAtUnix) notify(`Scan complete: ${payload.summary.directories.toLocaleString()} folders inspected.`, "success");
          void Promise.all([call<SavedScan | null>("load_latest_scan"), loadDerived(), call<RemovedReport>("detect_removed_applications")])
            .then(([scan, , removedReport]) => {
              if (!mounted) return;
              if (scan && (payload.savedAtUnix || payload.summary.canceled)) showSaved(scan);
              setRemoved(removedReport);
            })
            .catch(cause => { if (mounted) setScanError(message(cause)); });
        }));
        const [info, loadedSettings, status, definitionStatus] = await Promise.all([
          call<AppInfo>("app_info"),
          call<Settings>("get_settings").catch(() => null),
          call<PublicDataStatus>("public_data_status").catch(() => null),
          call<DefinitionsStatus>("definitions_status").catch(() => null),
        ]);
        if (!mounted) return;
        setAppInfo(info);
        setSettings(loadedSettings);
        setPublicData(status);
        setDefinitions(definitionStatus);
        let saved: SavedScan | null = null;
        try { saved = await call<SavedScan | null>("load_latest_scan"); }
        catch (cause) { if (mounted) setScanError(`Saved scan could not be loaded: ${message(cause)}`); }
        if (saved) {
          if (mounted) showSaved(saved);
          await loadDerived().catch(cause => { if (mounted) setScanError(`Saved analysis could not be loaded: ${message(cause)}`); });
          if (loadedSettings?.checkRemovedOnLaunch !== false) {
            void call<RemovedReport>("detect_removed_applications").then(report => { if (mounted) setRemoved(report); }).catch(() => {});
          }
        } else {
          const inventory = await call<Inventory>("installed_applications");
          if (mounted) { setApps(inventory.applications); setInventoryWarnings(inventory.warnings); }
          const ruleList = await call<IgnoreRule[]>("list_ignore_rules").catch(() => []);
          if (mounted) setRules(ruleList);
        }
        void call<QuarantineReport>("list_quarantine").then(report => { if (mounted) setQuarantine(report); }).catch(() => {});
      } catch (cause) {
        if (mounted) { setBackend("unavailable"); setBackendError(message(cause)); }
      }
    }
    void connect();
    return () => { mounted = false; window.clearInterval(flush); unlisteners.forEach(unlisten => unlisten()); disconnectBackend(); };
  }, [nonce, loadDerived, showSaved, notify]);

  const actions: CleanerActions = useMemo(() => ({
    reconnect() { setBackend("connecting"); setBackendError(""); setNonce(value => value + 1); },
    async startScan(mode) {
      setScanError("");
      buffer.current = [];
      setResults([]); setSummary(null); setSavedAt(null); setProgressPath(""); setRunning(true); setRunningMode(mode ?? settings?.defaultScanMode ?? "quick");
      try { await call("start_scan", mode ? { mode } : {}); }
      catch (cause) {
        setScanError(message(cause)); setRunning(false); setRunningMode(null);
        const saved = await call<SavedScan | null>("load_latest_scan").catch(() => null);
        if (saved) showSaved(saved);
      }
    },
    async cancelScan() {
      try { await call("cancel_scan"); } catch (cause) { notify(message(cause), "error"); }
    },
    async runPostUninstall() {
      try {
        const report = await call<PostUninstallReport>("post_uninstall_scan");
        setPostUninstall(report);
        setRemoved(report.removed);
        notify(report.results.length ? `Post-uninstall check measured ${report.results.length} remaining folder(s).` : "No remaining folders were found for removed applications.", "success");
      } catch (cause) { notify(message(cause), "error"); }
    },
    async refreshAfterChange() {
      await Promise.all([loadDerived(), refreshQuarantine()]).catch(cause => notify(message(cause), "error"));
    },
    refreshQuarantine,
    async addRule(kind, value, label) {
      try {
        await call("add_ignore_rule", { kind, value, label });
        await loadDerived();
        notify(kind === "once" ? `Hidden until the next scan: ${label}` : `Rule added: ${label}`, "success");
      } catch (cause) { notify(message(cause), "error"); }
    },
    async removeRule(id) {
      try { await call("remove_ignore_rule", { id }); await loadDerived(); }
      catch (cause) { notify(message(cause), "error"); }
    },
    planCleanup: paths => call<CleanupPlan>("plan_cleanup", { paths }),
    async executeCleanup(paths, acknowledgeWarnings) {
      const outcome = await call<CleanupOutcome>("execute_cleanup", { paths, acknowledgeWarnings });
      await Promise.all([loadDerived(), refreshQuarantine()]).catch(() => {});
      return outcome;
    },
    async restore(id) {
      try { await call("restore_quarantine", { id }); notify("Restored to its original location.", "success"); await Promise.all([refreshQuarantine(), loadDerived()]); }
      catch (cause) { notify(message(cause), "error"); }
    },
    async purge(id) {
      try { await call("purge_quarantine", { id }); notify("Permanently deleted.", "success"); await refreshQuarantine(); }
      catch (cause) { notify(message(cause), "error"); }
    },
    async saveSettings(next) {
      try { setSettings(await call<Settings>("update_settings", { settings: next })); notify("Settings saved.", "success"); await refreshQuarantine(); }
      catch (cause) { notify(message(cause), "error"); }
    },
    async updatePublicData() {
      try {
        const status = await call<PublicDataStatus>("update_public_data");
        setPublicData(status);
        notify(status.gameDirectories || status.cleanerDirectories ? "Folder data updated. Run a scan to apply it." : "No folder data could be downloaded. Scans still work without it.", status.warnings.length ? "error" : "success");
      } catch (cause) { notify(`Folder data update failed: ${message(cause)}`, "error"); }
    },
    async exportDiagnostics() {
      try {
        const exported = await call<DiagnosticsExport>("export_diagnostics");
        notify(`Diagnostics saved to ${exported.path}`, "success");
        return exported;
      } catch (cause) { notify(`Diagnostics export failed: ${message(cause)}`, "error"); return null; }
    },
    async openPath(path) {
      try { await call("open_path", { path }); } catch (cause) { notify(message(cause), "error"); }
    },
    notify,
    dismissToast,
  }), [loadDerived, refreshQuarantine, notify, dismissToast, settings, showSaved]);

  const value = {
    backend, backendError, appInfo, apps, inventoryWarnings, results, references, summary, savedAt, running, runningMode, progressPath,
    scanError, history, candidates, removed, postUninstall, quarantine, rules, settings, publicData, definitions, toasts, ...actions,
  };
  return <CleanerContext.Provider value={value}>{children}</CleanerContext.Provider>;
}
