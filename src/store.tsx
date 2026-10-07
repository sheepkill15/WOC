import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { call, connectBackend, disconnectBackend, listenBackend, type BackendKind } from "./backend";
import { mergeScanResults, needsScanSync } from "./scanSync";
import { resultsAfterCleanup, sameApp } from "./applicationCatalog";
import type {
  AppInfo, Application, CandidateReport, CleanupOutcome, CleanupPlan, DefinitionsStatus, DiagnosticsExport, DirectoryResult,
  HistoryReport, IgnoreRule, Inventory, PostUninstallReport, PublicDataStatus, QuarantineReport, ReferenceInventory,
  RemovedReport, SavedScan, ScanFinishedEvent, ScanSummary, ScanState, ScanStatus, Settings,
  FolderLink, UninstallReview,
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
  folderLinks: FolderLink[];
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
  planCleanup(paths: string[], manualCleanup: boolean, uninstallToken?: string): Promise<CleanupPlan>;
  executeCleanup(plan: CleanupPlan, acknowledgeWarnings: boolean, uninstallToken?: string): Promise<CleanupOutcome>;
  restore(id: number): Promise<void>;
  purge(id: number): Promise<void>;
  saveSettings(settings: Settings): Promise<void>;
  updatePublicData(): Promise<void>;
  exportDiagnostics(): Promise<DiagnosticsExport | null>;
  openPath(path: string): Promise<void>;
  connectFolder(path: string, applicationId: string | null): Promise<void>;
  planUninstall(applicationId: string): Promise<UninstallReview>;
  launchUninstall(token: string): Promise<void>;
  finishUninstall(token: string): Promise<string[]>;
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
  const [folderLinks, setFolderLinks] = useState<FolderLink[]>([]);
  const [nonce, setNonce] = useState(0);
  const buffer = useRef<DirectoryResult[]>([]);
  const scanStatus = useRef<ScanStatus>({ runId: 0, running: false, resultCount: 0 });
  const syncEpoch = useRef(0);
  const streamedPaths = useRef(new Set<string>());
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
    const [historyReport, candidateReport, ruleList, links] = await Promise.all([
      call<HistoryReport>("load_history_report"),
      call<CandidateReport>("load_candidates"),
      call<IgnoreRule[]>("list_ignore_rules"),
      call<FolderLink[]>("list_folder_links"),
    ]);
    setHistory(historyReport);
    setCandidates(candidateReport);
    setRules(ruleList);
    setFolderLinks(links);
  }, []);

  const refreshQuarantine = useCallback(async () => {
    try { setQuarantine(await call<QuarantineReport>("list_quarantine")); }
    catch (cause) { notify(`Quarantine could not be loaded: ${message(cause)}`, "error"); }
  }, [notify]);

  useEffect(() => {
    let mounted = true;
    const unlisteners: Array<() => void> = [];
    let syncing = false;
    let syncAgain = false;
    let completedRun = 0;
    let notifiedRun = 0;
    const flush = window.setInterval(() => {
      if (buffer.current.length && mounted) {
        const batch = buffer.current;
        buffer.current = [];
        setResults(previous => mergeScanResults(previous, batch));
      }
    }, 300);
    async function synchronize() {
      if (!mounted) return;
      if (syncing) { syncAgain = true; return; }
      syncing = true;
      const epoch = syncEpoch.current;
      try {
        const snapshot = await call<ScanState>("scan_state");
        if (!mounted || epoch !== syncEpoch.current) return;
        const sameRun = snapshot.runId === scanStatus.current.runId;
        const incomingPaths = [...snapshot.results, ...buffer.current].map(result => result.path.toLowerCase());
        streamedPaths.current = new Set(sameRun && snapshot.running ? [...streamedPaths.current, ...incomingPaths] : incomingPaths);
        scanStatus.current = { runId: snapshot.runId, running: snapshot.running, resultCount: streamedPaths.current.size };
        setRunning(snapshot.running);
        setRunningMode(snapshot.running ? snapshot.mode : null);
        setProgressPath(snapshot.progressPath);
        if (snapshot.runId > 0) {
          // Keep arrivals newer than this snapshot; merging by path avoids replay duplicates.
          const pending = buffer.current;
          buffer.current = [];
          setResults(previous => {
            const merged = mergeScanResults(sameRun && snapshot.running ? mergeScanResults(previous, snapshot.results) : snapshot.results, pending);
            return merged;
          });
          if (snapshot.inventory) { setApps(snapshot.inventory.applications); setInventoryWarnings(snapshot.inventory.warnings); }
          if (snapshot.references) setReferences(snapshot.references);
          if (snapshot.running) { setSummary(null); setSavedAt(null); setScanError(""); }
          if (snapshot.finished) {
            setSummary(snapshot.finished.summary);
            setScanError(snapshot.finished.saveError ?? "");
            if (completedRun !== snapshot.runId) {
              const finished = snapshot.finished;
              if (notifiedRun !== snapshot.runId) {
                notifiedRun = snapshot.runId;
                if (finished.summary.canceled) notify("Scan canceled. The previous saved scan is still available.");
                else if (finished.savedAtUnix) notify(`Scan complete: ${finished.summary.directories.toLocaleString()} folders inspected.`, "success");
              }
              const [saved, , removedReport] = await Promise.all([call<SavedScan | null>("load_latest_scan"), loadDerived(), call<RemovedReport>("detect_removed_applications")]);
              if (!mounted || epoch !== syncEpoch.current || scanStatus.current.runId !== snapshot.runId) return;
              if (saved && (finished.savedAtUnix || finished.summary.canceled)) showSaved(saved);
              setRemoved(removedReport);
              setPublicData(await call<PublicDataStatus>("public_data_status"));
              completedRun = snapshot.runId;
            }
          }
        }
      } catch (cause) {
        if (mounted) setScanError(`Scan state could not be synchronized: ${message(cause)}. Reconnecting automatically…`);
      } finally {
        syncing = false;
        if (syncAgain && mounted) { syncAgain = false; void synchronize(); }
      }
    }
    const reconcile = window.setInterval(() => {
      if (!mounted) return;
      void call<ScanStatus>("scan_status").then(status => {
        if (mounted && (needsScanSync(status, scanStatus.current) || (!status.running && status.runId > 0 && completedRun !== status.runId))) void synchronize();
      }).catch(() => { /* The next poll or SSE reconnect retries state reconciliation. */ });
    }, 2000);
    async function connect() {
      try {
        const connection = await connectBackend();
        if (!mounted) return;
        setBackend(connection.kind);
        setBackendError("");
        setRunning(connection.running);
        const register = (unlisten: () => void) => { if (mounted) unlisteners.push(unlisten); else unlisten(); };
        register(await listenBackend<{ runId: number; mode: "quick" | "deep" }>("scan-started", payload => {
          if (!mounted) return;
          syncEpoch.current++;
          scanStatus.current = { runId: payload.runId, running: true, resultCount: 0 };
          streamedPaths.current = new Set();
          buffer.current = [];
          setResults([]); setSummary(null); setSavedAt(null); setScanError(""); setRunning(true); setRunningMode(payload.mode);
        }));
        register(await listenBackend<DirectoryResult>("scan-result", payload => {
          if (mounted) {
            buffer.current.push(payload);
            streamedPaths.current.add(payload.path.toLowerCase());
            scanStatus.current.resultCount = streamedPaths.current.size;
          }
        }));
        register(await listenBackend<{ path: string }>("scan-progress", payload => { if (mounted) setProgressPath(payload.path); }));
        register(await listenBackend<Inventory>("scan-inventory", payload => {
          if (mounted) { setApps(payload.applications); setInventoryWarnings(payload.warnings); }
        }));
        register(await listenBackend<ReferenceInventory>("scan-references", payload => { if (mounted) setReferences(payload); }));
        register(await listenBackend<ScanFinishedEvent>("scan-finished", () => { void synchronize(); }));
        register(await listenBackend<object>("scan-resync", () => { void synchronize(); }));
        register(await listenBackend<object>("backend-reconnected", () => { void synchronize(); }));
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
        const [currentInventory, links] = await Promise.all([call<Inventory>("installed_applications"), call<FolderLink[]>("list_folder_links")]);
        if (mounted) { setApps(currentInventory.applications); setInventoryWarnings(currentInventory.warnings); setFolderLinks(links); }
        void call<QuarantineReport>("list_quarantine").then(report => { if (mounted) setQuarantine(report); }).catch(() => {});
        await synchronize();
      } catch (cause) {
        if (mounted) { setBackend("unavailable"); setBackendError(message(cause)); }
      }
    }
    void connect();
    return () => { mounted = false; syncEpoch.current++; window.clearInterval(flush); window.clearInterval(reconcile); unlisteners.forEach(unlisten => unlisten()); disconnectBackend(); };
  }, [nonce, loadDerived, showSaved, notify]);

  const actions: CleanerActions = useMemo(() => ({
    async connectFolder(path, applicationId) {
      await call("connect_folder", { path, applicationId });
      const saved = await call<SavedScan | null>("load_latest_scan");
      if (saved) setResults(saved.results);
      await loadDerived();
      notify(applicationId ? "Folder connected. Future scans will remember it." : "Manual connection removed.", "success");
    },
    planUninstall: applicationId => call<UninstallReview>("plan_uninstall", { applicationId }),
    launchUninstall: token => call<void>("launch_uninstall", { token }),
    async finishUninstall(token) {
      const outcome = await call<{ paths: string[]; inventory: Inventory }>("finish_uninstall", { token });
      setApps(outcome.inventory.applications); setInventoryWarnings(outcome.inventory.warnings);
      setResults(previous => previous.map(result => result.owner && !outcome.inventory.applications.some(app => sameApp(app, result.owner!))
        ? { ...result, orphanStatus: "probable_orphan", evidence: [...result.evidence, { kind: "historical_owner", strength: "strong", description: "The application's uninstall was verified against Windows." }] } : result));
      return outcome.paths;
    },
    reconnect() { setBackend("connecting"); setBackendError(""); setNonce(value => value + 1); },
    async startScan(mode) {
      syncEpoch.current++;
      setScanError("");
      buffer.current = [];
      streamedPaths.current = new Set();
      setResults([]); setSummary(null); setSavedAt(null); setProgressPath(""); setRunning(true); setRunningMode(mode ?? settings?.defaultScanMode ?? "quick");
      try { await call("start_scan", mode ? { mode } : {}); }
      catch (cause) {
        setScanError(message(cause)); setRunning(false); setRunningMode(null);
        scanStatus.current = { ...scanStatus.current, running: false };
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
    planCleanup: (paths, manualCleanup, uninstallToken) => call<CleanupPlan>("plan_cleanup", { paths, manualCleanup, uninstallToken }),
    async executeCleanup(plan, acknowledgeWarnings, uninstallToken) {
      const outcome = await call<CleanupOutcome>("execute_cleanup", { paths: plan.items.map(item => item.path), manualCleanup: plan.manualCleanup, planToken: plan.planToken, acknowledgeWarnings, uninstallToken });
      setResults(previous => resultsAfterCleanup(previous, outcome.items));
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
    scanError, history, candidates, removed, postUninstall, quarantine, rules, settings, publicData, definitions, toasts, folderLinks, ...actions,
  };
  return <CleanerContext.Provider value={value}>{children}</CleanerContext.Provider>;
}
