import { useMemo, type ReactNode } from "react";
import { useCleaner } from "../store";
import { formatAge, formatBytes, formatCount, formatDate, formatDuration, rootLabels, statusBadge, type StatusGroup } from "../format";
import { Icon, Notice, PageHeader, Section, SizeBar } from "../ui";
import type { Route } from "../App";

const groupMeta: Record<StatusGroup, { label: string; tone: "good" | "info" | "warn" | "accent" | "muted" }> = {
  matched: { label: "Installed apps", tone: "good" },
  known: { label: "Known & personal data", tone: "info" },
  former: { label: "Leftovers", tone: "warn" },
  unregistered: { label: "Unregistered apps", tone: "accent" },
  unknown: { label: "Unknown owner", tone: "muted" },
};

type Step = { title: string; body: ReactNode; action: ReactNode; secondary?: ReactNode };
type Task = { id: string; title: string; body: string; value?: string; done?: boolean; route: Route; label: string };

export function Overview({ navigate }: { navigate: (route: Route) => void }) {
  const { results, summary, savedAt, candidates, removed, history, references, quarantine, running, progressPath, startScan, cancelScan, runPostUninstall, backend, settings } = useCleaner();
  const connected = backend === "tauri" || backend === "agent";
  const topLevel = useMemo(() => results.filter(result => !result.parentPath), [results]);
  const byGroup = useMemo(() => {
    const totals: Record<StatusGroup, number> = { matched: 0, known: 0, former: 0, unregistered: 0, unknown: 0 };
    for (const result of topLevel) totals[statusBadge(result).group] += result.sizeBytes;
    return totals;
  }, [topLevel]);
  const byRoot = useMemo(() => {
    const totals = new Map<string, number>();
    for (const result of topLevel) totals.set(result.root, (totals.get(result.root) ?? 0) + result.sizeBytes);
    return [...totals.entries()].sort((left, right) => right[1] - left[1]);
  }, [topLevel]);
  const total = topLevel.reduce((sum, result) => sum + result.sizeBytes, 0);
  const deadReferences = references?.references.filter(reference => reference.status === "dead").length ?? 0;
  const removedApps = removed?.applications ?? [];
  const groups = candidates?.groups ?? [];
  const highGroups = groups.filter(group => group.priority === "high").length;
  const reviewGroups = groups.filter(group => group.priority === "review").length;
  const recommendedBytes = candidates?.recommendedBytes ?? 0;
  const reviewBytes = candidates?.reviewBytes ?? 0;
  const leftoverApps = history?.applications ?? [];
  const quarantineItems = quarantine?.items.length ?? 0;
  const downloadRoots = topLevel.filter(result => result.root === "Downloads" || result.root === "OtherDownloads");
  const downloadBytes = downloadRoots.reduce((sum, result) => sum + result.sizeBytes, 0);

  if (!results.length && !running) {
    return <div className="page">
      <PageHeader title="Start with a scan" description="Orphan Cleaner looks at application data on this PC, works out which program owns each folder, and shows you what was left behind. Nothing is removed until you review it." />
      <ul className="onboarding">
        <li><div><strong>Quick scan</strong><span>AppData, ProgramData, Downloads on fixed drives, Public files, installed apps and system references. Time depends on the size of Downloads.</span></div>
          <button className="primary" disabled={!connected} onClick={() => void startScan("quick")}>Start quick scan</button></li>
        <li><div><strong>Deep scan</strong><span>Also the user profile, Documents and other personal folders, Program Files on fixed drives, registered installs outside standard roots, top-level temp folders, developer caches and program metadata. Takes longer.</span></div>
          <button className="secondary" disabled={!connected} onClick={() => void startScan("deep")}>Start deep scan</button></li>
      </ul>
      <Section title="How it stays safe">
        <ul className="principles">
          <li><Icon name="shield" /><strong>Unknown is not junk</strong><span>Folders without a clear owner are never recommended for removal.</span></li>
          <li><Icon name="uninstalled" /><strong>History makes it certain</strong><span>Scan again after uninstalling an app: remembered ownership is the strongest evidence.</span></li>
          <li><Icon name="quarantine" /><strong>Everything is reversible</strong><span>Cleaning moves items to quarantine first, so you can restore them.</span></li>
        </ul>
      </Section>
    </div>;
  }

  // Exactly one recommended next action, in order of how much it matters right now.
  let step: Step;
  let stepTask: string | null = null;
  if (running) {
    step = { title: "Scan in progress", body: <>Results fill in as folders are inspected{progressPath ? <> — now in <code>{progressPath}</code></> : ""}. You can browse them while you wait.</>,
      action: <button className="secondary" onClick={() => navigate("inventory")}>Watch results</button>,
      secondary: <button className="ghost" onClick={() => void cancelScan()}>Cancel scan</button> };
  } else if (removedApps.length > 0) {
    step = { title: `Check what ${formatCount(removedApps.length, "removed app")} left behind`,
      body: <>{removedApps.slice(0, 3).map(item => item.application.name).join(", ")}{removedApps.length > 3 ? " and others" : ""} disappeared since the last scan. About {formatBytes(removedApps.reduce((sum, item) => sum + item.remainingBytes, 0))} of their data was still there. The check only re-measures those folders.</>,
      action: <button className="primary" disabled={!connected} onClick={() => { void runPostUninstall(); navigate("uninstalled"); }}>Check leftovers</button> };
  } else if (recommendedBytes > 0) {
    stepTask = "cleanup";
    step = { title: `Free up ${formatBytes(recommendedBytes)}`,
      body: <>{formatCount(highGroups, "group")} have strong evidence that nothing uses them anymore. Only data that can be recreated is ticked for you. Check it and click <b>Review &amp; clean</b>.</>,
      action: <button className="primary" onClick={() => navigate("cleanup")}>Review cleanup</button> };
  } else if (reviewGroups > 0) {
    stepTask = "cleanup";
    step = { title: `Decide on ${formatCount(reviewGroups, "group")} (${formatBytes(reviewBytes)})`,
      body: "None of it is certain enough to tick automatically. Open each group, read why it was flagged, and tick only what you know you don't need.",
      action: <button className="primary" onClick={() => navigate("cleanup")}>Start reviewing</button> };
  } else if (deadReferences > 0) {
    stepTask = "references";
    step = { title: `Remove ${formatCount(deadReferences, "dead reference")}`,
      body: "Startup entries, tasks or shortcuts point to programs that no longer exist.",
      action: <button className="primary" onClick={() => navigate("references")}>Review references</button> };
  } else {
    step = { title: "Nothing to clean right now",
      body: "No leftovers with enough evidence were found. After you uninstall software, scan again: that is when leftovers are easiest to identify.",
      action: <button className="primary" disabled={!connected} onClick={() => void startScan()}>Scan again</button> };
  }

  const tasks: Task[] = [
    ...(downloadBytes > 0 ? [{ id: "downloads", route: "inventory" as Route, label: "Review",
      title: `${formatBytes(downloadBytes)} in Downloads`,
      body: `${formatCount(downloadRoots.length, "location")} found automatically. Browse archives, installers and other files you may have forgotten; nothing here is selected for cleanup.`,
      value: formatBytes(downloadBytes) }] : []),
    { id: "cleanup", route: "cleanup", label: "Open",
      title: recommendedBytes > 0 ? `${formatBytes(recommendedBytes)} recommended for cleanup` : reviewGroups ? `${formatCount(reviewGroups, "group")} waiting for your decision` : "No cleanup candidates",
      body: recommendedBytes > 0 && reviewGroups ? `Plus ${formatCount(reviewGroups, "group")} (${formatBytes(reviewBytes)}) that need your decision` : "Leftovers, old versions and caches grouped by application",
      value: formatBytes(recommendedBytes + reviewBytes), done: !recommendedBytes && !reviewGroups },
    { id: "uninstalled", route: "uninstalled", label: "Open",
      title: leftoverApps.length ? `${formatCount(leftoverApps.length, "uninstalled app")} still ${leftoverApps.length === 1 ? "has" : "have"} data here` : "No data from uninstalled apps",
      body: leftoverApps.length ? "Found by comparing with earlier scans" : "Scan again after uninstalling software to catch its leftovers",
      value: leftoverApps.length ? formatBytes(leftoverApps.reduce((sum, item) => sum + item.remainingBytes, 0)) : undefined, done: !leftoverApps.length },
    { id: "references", route: "references", label: "Open",
      title: deadReferences ? `${formatCount(deadReferences, "startup entry or shortcut", "startup entries or shortcuts")} point to missing programs` : "All startup entries and shortcuts work",
      body: "Startup, scheduled tasks, services, shortcuts", value: deadReferences ? String(deadReferences) : undefined, done: !deadReferences },
    { id: "quarantine", route: "quarantine", label: "Open",
      title: quarantineItems ? `${formatCount(quarantineItems, "item")} in quarantine` : "Quarantine is empty",
      body: quarantineItems ? "Restore what you miss, or delete permanently to free the space" : "Cleaned items wait here until you delete them permanently",
      value: quarantineItems ? formatBytes(quarantine?.totalBytes ?? 0) : undefined, done: !quarantineItems },
  ];

  return <div className="page">
    <PageHeader title="Overview" description={savedAt ? `Last scan ${formatAge(savedAt)} · ${formatCount(results.length, "folder")} · ${formatBytes(total)} inspected` : running ? "First scan in progress" : "Current results"} />

    <div className="next-step">
      <div>
        <span className="next-step-label">Next step</span>
        <h2>{step.title}</h2>
        <p>{step.body}</p>
      </div>
      <div className="next-step-actions">{step.secondary}{step.action}</div>
    </div>

    <Section title="Everything else">
      <ul className="task-list">
        {tasks.filter(task => task.id !== stepTask).map(task => <li key={task.id} className={task.done ? "done" : undefined}>
          <div><strong>{task.title}</strong><span>{task.body}</span></div>
          <b>{task.value ?? ""}</b>
          <button className={task.done ? "ghost" : "secondary"} onClick={() => navigate(task.route)}>{task.label}</button>
        </li>)}
      </ul>
    </Section>

    <div className="two-column">
      <Section title="Who owns the storage">
        <SizeBar segments={(Object.keys(groupMeta) as StatusGroup[]).map(group => ({ value: byGroup[group], tone: groupMeta[group].tone, label: `${groupMeta[group].label}: ${formatBytes(byGroup[group])}` }))} />
        <ul className="legend">
          {(Object.keys(groupMeta) as StatusGroup[]).map(group => <li key={group}><span className={`dot bg-${groupMeta[group].tone}`} />{groupMeta[group].label}<b>{formatBytes(byGroup[group])}</b></li>)}
        </ul>
      </Section>
      <Section title="Where it is" actions={<button className="link small" onClick={() => navigate("inventory")}>All folders</button>}>
        <ul className="root-list">
          {byRoot.map(([root, size]) => <li key={root}>
            <span>{rootLabels[root] ?? root}</span>
            <div className="root-bar"><span style={{ width: `${total ? Math.max(2, size / total * 100) : 0}%` }} /></div>
            <b>{formatBytes(size)}</b>
          </li>)}
        </ul>
      </Section>
    </div>
    {summary && <div className="scan-meta">
      <span>Mode: <b>{summary.mode === "deep" ? "Deep" : "Quick"}</b></span>
      {summary.durationMs ? <span>Took <b>{formatDuration(summary.durationMs)}</b></span> : null}
      {savedAt && <span>Saved <b>{formatDate(savedAt)}</b></span>}
      {summary.skippedEntries > 0 && <span className="text-warn">{summary.skippedEntries.toLocaleString()} unreadable entries</span>}
      {settings?.defaultScanMode === "quick" && summary.mode !== "deep" && <button className="link" onClick={() => void startScan("deep")} disabled={!connected || running}>Run a deep scan for more</button>}
    </div>}
    {summary && summary.warnings.length > 0 && <Section title="Scan notes">{summary.warnings.map((warning, index) => <Notice key={index}>{warning}</Notice>)}</Section>}
  </div>;
}
