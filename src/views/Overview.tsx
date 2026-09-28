import { useMemo } from "react";
import { useCleaner } from "../store";
import { formatAge, formatBytes, formatCount, formatDate, formatDuration, rootLabels, statusBadge, type StatusGroup } from "../format";
import { Badge, Empty, Icon, Notice, PageHeader, Section, SizeBar, Stat } from "../ui";
import type { Route } from "../App";

const groupMeta: Record<StatusGroup, { label: string; tone: "good" | "info" | "warn" | "accent" | "muted" }> = {
  matched: { label: "Installed apps", tone: "good" },
  known: { label: "Windows & known data", tone: "info" },
  former: { label: "Leftovers", tone: "warn" },
  unregistered: { label: "Unregistered apps", tone: "accent" },
  unknown: { label: "Unknown owner", tone: "muted" },
};

export function Overview({ navigate }: { navigate: (route: Route) => void }) {
  const { results, summary, savedAt, candidates, removed, apps, references, quarantine, running, startScan, runPostUninstall, backend, settings } = useCleaner();
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
  const topGroups = (candidates?.groups ?? []).filter(group => group.priority !== "info").slice(0, 6);
  const removedApps = removed?.applications ?? [];

  if (!results.length && !running) {
    return <div className="page">
      <PageHeader eyebrow="Welcome" title="Find storage that nothing owns anymore" description="Orphan Cleaner links application data to installed software, remembers what it saw, and explains every conclusion. Nothing is removed without your review." />
      <div className="onboarding">
        <button className="mode-card" disabled={!connected} onClick={() => void startScan("quick")}>
          <Icon name="bolt" size={22} />
          <strong>Quick scan</strong>
          <span>AppData and ProgramData, installed apps, startup entries, services, tasks and shortcuts. Usually under a minute.</span>
        </button>
        <button className="mode-card" disabled={!connected} onClick={() => void startScan("deep")}>
          <Icon name="analyzer" size={22} />
          <strong>Deep scan</strong>
          <span>Adds Program Files, developer caches in your profile (Gradle, Maven, Cargo, npm…) and executable metadata for unregistered apps.</span>
        </button>
      </div>
      <div className="principles">
        <div><Icon name="shield" /><strong>Unknown is not junk</strong><span>Folders without a clear owner stay unknown and are never recommended.</span></div>
        <div><Icon name="uninstalled" /><strong>History makes it certain</strong><span>Scan again after uninstalling apps: remembered ownership gives the strongest evidence.</span></div>
        <div><Icon name="quarantine" /><strong>Everything is reversible</strong><span>Cleanup moves items to quarantine first; restore them with one click.</span></div>
      </div>
    </div>;
  }

  return <div className="page">
    <PageHeader eyebrow={savedAt ? `Last complete scan ${formatAge(savedAt)}` : running ? "Scanning" : "Current results"} title="Overview"
      description="What remains on this PC, who owns it, and what can safely go." />

    {removedApps.length > 0 && <Notice tone="warn" action={<button className="secondary" disabled={!connected} onClick={() => void runPostUninstall()}>Check leftovers</button>}>
      <strong>{formatCount(removedApps.length, "application")} removed since the last scan</strong> ({removedApps.slice(0, 3).map(item => item.application.name).join(", ")}{removedApps.length > 3 ? "…" : ""}). About {formatBytes(removedApps.reduce((sum, item) => sum + item.remainingBytes, 0))} of their data was still present. A post-uninstall check re-measures only those folders.
    </Notice>}

    <div className="hero">
      <div className="hero-main">
        <span className="stat-label">Recommended cleanup</span>
        <strong className="hero-value">{formatBytes(candidates?.recommendedBytes ?? 0)}</strong>
        <p>{candidates?.groups.filter(group => group.priority === "high").length ?? 0} high-confidence groups · {formatBytes(candidates?.reviewBytes ?? 0)} more to review</p>
        <div className="hero-actions">
          <button className="primary" onClick={() => navigate("cleanup")}>Review cleanup <Icon name="chevron" size={15} /></button>
          {removedApps.length === 0 && <button className="ghost" onClick={() => navigate("uninstalled")}>Uninstalled apps</button>}
        </div>
      </div>
      <div className="hero-side">
        <span className="stat-label">Inspected storage by ownership</span>
        <SizeBar segments={(Object.keys(groupMeta) as StatusGroup[]).map(group => ({ value: byGroup[group], tone: groupMeta[group].tone, label: `${groupMeta[group].label}: ${formatBytes(byGroup[group])}` }))} />
        <ul className="legend">
          {(Object.keys(groupMeta) as StatusGroup[]).map(group => <li key={group}><span className={`dot bg-${groupMeta[group].tone}`} />{groupMeta[group].label}<b>{formatBytes(byGroup[group])}</b></li>)}
        </ul>
      </div>
    </div>

    <div className="stats">
      <Stat label="Installed apps" value={apps.length.toLocaleString()} hint="Registry and MSIX packages" onClick={() => navigate("apps")} />
      <Stat label="Folders inspected" value={results.length.toLocaleString()} hint={formatBytes(total)} onClick={() => navigate("inventory")} />
      <Stat label="Dead references" value={deadReferences.toLocaleString()} tone={deadReferences ? "warn" : undefined} hint="Startup, tasks, services, shortcuts" onClick={() => navigate("references")} />
      <Stat label="In quarantine" value={formatBytes(quarantine?.totalBytes ?? 0)} hint={formatCount(quarantine?.items.length ?? 0, "item")} onClick={() => navigate("quarantine")} />
    </div>

    <div className="two-column">
      <Section title="Top candidates" description="Grouped by application. Open Cleanup to choose exactly what goes." actions={<button className="ghost" onClick={() => navigate("cleanup")}>View all</button>}>
        {topGroups.length ? <ul className="candidate-mini">
          {topGroups.map(group => <li key={group.id}><button onClick={() => navigate("cleanup")}>
            <div><strong>{group.title}</strong><span>{group.summary}</span></div>
            <div className="candidate-mini-side"><b>{formatBytes(group.reclaimableBytes || group.totalBytes)}</b><Badge tone={group.priority === "high" ? "warn" : "muted"}>{group.priority === "high" ? "High confidence" : "Review"}</Badge></div>
          </button></li>)}
        </ul> : <Empty icon="check" title="No cleanup candidates">No leftovers with enough evidence were found. Scan again after uninstalling software to catch its leftovers.</Empty>}
      </Section>
      <Section title="Where the storage is">
        <ul className="root-list">
          {byRoot.map(([root, size]) => <li key={root}>
            <span>{rootLabels[root] ?? root}</span>
            <div className="root-bar"><span style={{ width: `${total ? Math.max(2, size / total * 100) : 0}%` }} /></div>
            <b>{formatBytes(size)}</b>
          </li>)}
        </ul>
        {summary && <div className="scan-meta">
          <span>Mode: <b>{summary.mode === "deep" ? "Deep" : "Quick"}</b></span>
          {summary.durationMs ? <span>Took <b>{formatDuration(summary.durationMs)}</b></span> : null}
          {savedAt && <span>Saved <b>{formatDate(savedAt)}</b></span>}
          {summary.skippedEntries > 0 && <span className="text-warn">{summary.skippedEntries.toLocaleString()} unreadable entries</span>}
          {settings?.defaultScanMode === "quick" && summary.mode !== "deep" && <button className="link" onClick={() => void startScan("deep")} disabled={!connected || running}>Run a deep scan</button>}
        </div>}
      </Section>
    </div>
    {summary && summary.warnings.length > 0 && <Section title="Scan notes">{summary.warnings.map((warning, index) => <Notice key={index}>{warning}</Notice>)}</Section>}
  </div>;
}
