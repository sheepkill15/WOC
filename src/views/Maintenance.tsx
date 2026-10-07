import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { call } from "../backend";
import { useCleaner } from "../store";
import { formatDate } from "../format";
import { canDisableStartup, maintenanceKinds, maintenanceRows, startupLabel, type MaintenanceReport, type MaintenanceBackup, type MaintenanceEntry, type MaintenanceOutcome } from "../maintenance";
import { Badge, Checkbox, Empty, Icon, Modal, Notice, PageHeader, Stat } from "../ui";

type Review = { action: "disable" | "clean"; token: string; entries: MaintenanceEntry[] } | { action: "restore"; backup: MaintenanceBackup };

export function StartupItems() { return <Maintenance startup />; }
export function RegistryCleaner() { return <Maintenance startup={false} />; }

function Maintenance({ startup }: { startup: boolean }) {
  const { backend, running, notify } = useCleaner();
  const connected = backend === "tauri" || backend === "agent";
  const [report, setReport] = useState<MaintenanceReport | null>(null);
  const [backups, setBackups] = useState<MaintenanceBackup[]>([]);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [tab, setTab] = useState(startup ? "all" : "problems");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [review, setReview] = useState<Review | null>(null);
  const [outcomes, setOutcomes] = useState<MaintenanceOutcome[]>([]);
  const generation = useRef(0);
  const refresh = useCallback(async () => {
    const version = ++generation.current;
    setLoading(true); setError(""); setSelected(new Set());
    try {
      const [scan, saved] = await Promise.all([call<MaintenanceReport>("scan_maintenance"), call<MaintenanceBackup[]>("maintenance_backups")]);
      if (version === generation.current) { setReport(scan); setBackups(saved); }
    } catch (cause) { if (version === generation.current) setError(String(cause instanceof Error ? cause.message : cause)); }
    finally { if (version === generation.current) setLoading(false); }
  }, []);
  useEffect(() => { if (connected) void refresh(); return () => { generation.current++; }; }, [connected, refresh]);
  const rows = useMemo(() => maintenanceRows(report, backups, startup), [report, backups, startup]);
  const disabled = rows.filter(row => row.backup || row.entry.startupState === "windows_disabled").length;
  const problems = rows.filter(row => !row.backup && row.entry.canClean).length;
  const saved = backups.filter(item => item.action === (startup ? "disable" : "clean"));
  const pending = saved.filter(item => item.status === "removed" || item.status === "pending");
  const visible = rows.filter(row => {
    if (tab === "problems" && !row.entry.canClean) return false;
    if (tab === "disabled" && !row.backup && row.entry.startupState !== "windows_disabled") return false;
    if (tab === "enabled" && (row.backup || row.entry.startupState === "windows_disabled")) return false;
    return `${row.entry.name} ${row.entry.command} ${row.entry.location} ${row.entry.owner ?? ""}`.toLowerCase().includes(query.toLowerCase());
  });
  const canAct = connected && !running && !busy && !loading;
  const eligible = visible.filter(row => !row.backup && (startup ? canDisableStartup(row.entry) : row.entry.canClean));
  const selectedEntries = rows.filter(row => !row.backup && selected.has(row.entry.id)).map(row => row.entry);
  const setFilter = (value: string) => { setTab(value); setSelected(new Set()); };
  const request = (entries: MaintenanceEntry[]) => { if (report) { setError(""); setReview({ action: startup ? "disable" : "clean", token: report.token, entries }); } };
  const openWindowsSettings = () => void call("open_startup_settings").catch(cause => notify(String(cause), "error"));

  async function execute() {
    if (!review) return;
    setBusy(true); setError(""); setOutcomes([]);
    try {
      if (review.action === "restore") {
        await call("restore_maintenance", { id: review.backup.id });
        notify(startup ? "Startup entry restored. Windows may still keep it disabled in Startup settings." : "Registry value restored.", "success");
      } else {
        const results = await call<MaintenanceOutcome[]>("apply_maintenance", { token: review.token, ids: review.entries.map(entry => entry.id), action: review.action });
        setOutcomes(results);
        const succeeded = results.filter(item => item.success).length;
        notify(`${succeeded} of ${results.length} ${startup ? "startup entries disabled" : "registry values removed"}.`, succeeded === results.length ? "success" : "info");
      }
      setReview(null); await refresh();
    } catch (cause) { setError(cause instanceof Error ? cause.message : String(cause)); }
    finally { setBusy(false); }
  }

  const close = () => { if (!busy) setReview(null); };
  const failed = outcomes.filter(item => !item.success);
  return <div className="page page-wide">
    <PageHeader title={startup ? "Startup items" : "Registry cleaner"}
      description={startup ? "Choose what starts when you sign in. Disable entries here and restore them whenever you need them."
        : "Review startup and application-path registry values that point to missing programs. Every removal has a restorable backup."}
      actions={<>
        {startup && <button className="secondary" disabled={!connected || busy} onClick={openWindowsSettings}>Windows Startup settings <Icon name="open" size={14} /></button>}
        <button className="secondary" disabled={!connected || loading || busy} onClick={() => void refresh()}><Icon name="refresh" size={14} />{loading ? "Checking…" : "Refresh"}</button>
      </>} />
    {error && <Notice tone="error">{error}</Notice>}
    {failed.length > 0 && <Notice tone="warn">{failed.map((item, index) => <p key={index}><strong>{item.name}:</strong> {item.error}</p>)}</Notice>}
    {report?.warnings.map((warning, index) => <Notice key={index} tone="warn">{warning}</Notice>)}
    {report && <div className="stats three">
      <Stat label={startup ? "Startup entries" : "Values checked"} value={rows.length} />
      <Stat label={startup ? "Disabled" : "Missing program targets"} value={startup ? disabled : problems} tone={startup ? "muted" : problems ? "warn" : "good"} />
      <Stat label="Restorable backups" value={pending.length} onClick={() => setFilter("backups")} />
    </div>}
    <p className="muted small maintenance-scope">{startup ? "Includes Run, RunOnce and the current-user / all-users Startup folders. Packaged apps and other startup mechanisms can be managed in Windows Startup settings. RunOnce entries may finish an installation."
      : "Checks Run, RunOnce and App Paths. Only exact missing targets on available fixed drives are offered for cleanup. Windows targets, ambiguous commands and inaccessible paths are excluded."}
      {report && <> Last checked {formatDate(report.capturedAtUnix)}.</>}
    </p>
    <div className="toolbar">
      <div className="tabs">
        {(startup ? [["all", "All", rows.length], ["disabled", "Disabled", disabled], ["backups", "Backups", saved.length]] : [["problems", "Missing targets", problems], ["all", "All checked", rows.length], ["backups", "Backups", saved.length]]).map(([value, label, count]) =>
          <button key={value} className={tab === value ? "selected" : ""} onClick={() => setFilter(String(value))}>{label}<span>{count}</span></button>)}
      </div>
      <div className="search"><Icon name="analyzer" size={15} /><input aria-label={startup ? "Search startup items" : "Search registry values"} placeholder="Search name, application or location" value={query} onChange={event => { setQuery(event.target.value); setSelected(new Set()); }} /></div>
    </div>
    {tab === "backups" ? <>
      <Notice>Backups are kept until restored and are separate from folder quarantine. Restore never replaces a different value or file. An interrupted change stays available for recovery.</Notice>
      <div className="table-wrap"><table>
        <thead><tr><th>Entry</th><th>Changed</th><th>Status</th><th /></tr></thead>
        <tbody>{saved.filter(item => `${item.entry.name} ${item.entry.location}`.toLowerCase().includes(query.toLowerCase())).map(item => <tr key={item.id}>
          <td className="maintenance-location"><strong>{item.entry.name}</strong><small>{item.entry.location}</small>{item.detail && <small className="text-warn">{item.detail}</small>}</td>
          <td>{formatDate(item.createdAtUnix)}</td><td><Badge tone={item.status === "restored" ? "good" : item.status === "failed" ? "warn" : "muted"}>{item.status === "removed" ? startup ? "Disabled" : "Removed" : item.status === "pending" ? "Recovery available" : item.status === "restored" ? "Restored" : "Failed — no change"}</Badge></td>
          <td>{(item.status === "removed" || item.status === "pending") && <button className="secondary" disabled={!canAct} onClick={() => { setError(""); setReview({ action: "restore", backup: item }); }}><Icon name="restore" size={14} /> Restore</button>}</td>
        </tr>)}</tbody>
      </table>{saved.length === 0 && <Empty icon="restore" title="No backups yet">A backup is saved automatically before each change.</Empty>}</div>
    </> : <div className="table-wrap"><table className={`maintenance-table ${startup ? "startup-table" : "registry-table"}`}>
      <thead><tr><th><Checkbox label="Select all visible entries" checked={eligible.length > 0 && eligible.every(row => selected.has(row.entry.id))} disabled={!canAct || !eligible.length} onChange={value => setSelected(value ? new Set(eligible.map(row => row.entry.id)) : new Set())} /></th><th>Name &amp; application</th><th>{startup ? "Starts from" : "Registry location"}</th><th>Target</th><th>Status</th><th /></tr></thead>
      <tbody>{visible.map(row => <tr key={row.backup ? `backup:${row.backup.id}` : row.entry.id}>
        <td>{!row.backup && (startup ? canDisableStartup(row.entry) : row.entry.canClean) && <Checkbox label={`Select ${row.entry.name}`} disabled={!canAct} checked={selected.has(row.entry.id)} onChange={value => setSelected(previous => { const next = new Set(previous); if (value) next.add(row.entry.id); else next.delete(row.entry.id); return next; })} />}</td>
        <td className="maintenance-name"><strong>{row.entry.name}</strong>{row.entry.owner && <small className="block muted">{row.entry.owner}</small>}{row.entry.machineWide && <small className="block muted">All users</small>}<div className="maintenance-compact-details"><small>{row.entry.location}</small><small>{row.entry.targetPath ?? row.entry.command}</small>{!startup && <small>{row.entry.reason}</small>}</div></td>
        <td className="maintenance-location"><span>{maintenanceKinds[row.entry.kind]}</span><small>{row.entry.location}</small></td>
        <td className="maintenance-target"><span>{row.entry.targetPath ?? row.entry.command}</span>{row.entry.command !== row.entry.targetPath && row.entry.targetPath && <small>{row.entry.command}</small>}{!startup && <small>{row.entry.reason}</small>}</td>
        <td>{startup ? <><Badge tone={row.backup || row.entry.startupState === "windows_disabled" ? "muted" : "info"}>{startupLabel(row)}</Badge>{!row.backup && row.entry.targetStatus === "missing" && <small className="block text-warn">Missing target</small>}</> : <Badge tone={row.entry.canClean ? "warn" : row.entry.targetStatus === "ok" ? "good" : "muted"}>{row.entry.canClean ? "Missing" : row.entry.targetStatus === "ok" ? "Working" : "Excluded"}</Badge>}</td>
        <td className="cell-actions">{row.backup ? <button className="secondary" disabled={!canAct} onClick={() => { setError(""); setReview({ action: "restore", backup: row.backup! }); }}>Restore</button>
          : startup && row.entry.startupState === "windows_disabled" ? <button className="ghost" disabled={!connected || busy} onClick={openWindowsSettings}>Enable in Windows <Icon name="open" size={12} /></button>
          : startup && canDisableStartup(row.entry) ? <button className="secondary" disabled={!canAct} onClick={() => request([row.entry])}>Disable</button>
          : !startup && row.entry.canClean ? <button className="secondary" disabled={!canAct} onClick={() => request([row.entry])}>Review</button> : null}</td>
      </tr>)}</tbody>
    </table>{visible.length === 0 && <Empty icon={loading ? "refresh" : "check"} title={loading ? "Checking Windows…" : !report ? "Connect the Windows backend" : startup ? "No startup entries match" : tab === "problems" ? "No confirmed missing targets" : "No values match"}>
      {loading ? "Reading startup and application registrations." : !report ? "These tools require the desktop app or local agent." : "Refresh to check Windows again, or try another filter."}
    </Empty>}</div>}
    {selectedEntries.length > 0 && tab !== "backups" && <div className="selection-bar visible">
      <div><strong>{selectedEntries.length} selected</strong><span>{startup ? "Disable with a backup you can restore." : "Review the exact values before removing them."}</span></div>
      <button className="ghost" disabled={busy} onClick={() => setSelected(new Set())}>Clear</button>
      <button className="primary" disabled={!canAct} onClick={() => request(selectedEntries)}>Review {startup ? "startup changes" : "cleanup"}</button>
    </div>}
    {review && <Modal wide title={review.action === "restore" ? "Restore this entry?" : review.action === "disable" ? "Disable startup entries?" : "Remove missing program references?"} onClose={close} footer={<>
      <button className="ghost" disabled={busy} onClick={close}>Cancel</button><button className="primary" disabled={busy || running} onClick={() => void execute()}>{busy ? "Saving changes…" : review.action === "restore" ? "Restore" : review.action === "disable" ? "Back up & disable" : "Back up & remove"}</button>
    </>}>
      {error && <Notice tone="error">{error}</Notice>}
      <p>{review.action === "restore" ? "The original registry value or startup file will be restored if its location is still available. A different value or file will never be overwritten."
        : review.action === "disable" ? "These entries will be backed up, then removed from their startup locations. Changes take effect at the next sign-in. Installed applications and their data stay in place."
        : "Only the listed registry values will be removed. A backup is saved first, and each target is checked again before removal."}</p>
      {review.action === "restore" && startup && <p className="muted">Restoring a registration does not change any separate disable setting in Windows Startup settings. Restoring RunOnce may run its command at the next sign-in.</p>}
      <ul className="maintenance-review">{(review.action === "restore" ? [review.backup.entry] : review.entries).map(entry => <li key={entry.id}><strong>{entry.name}</strong><small>{entry.location}</small><code>{entry.command}</code>{entry.kind === "run_once" && <Badge tone="warn">One-time setup entry</Badge>}</li>)}</ul>
      {(review.action === "restore" ? review.backup.entry.machineWide : review.entries.some(entry => entry.machineWide)) && <Notice>All-users entries may require running the cleaner as administrator. Permission errors are reported for each entry.</Notice>}
    </Modal>}
  </div>;
}
