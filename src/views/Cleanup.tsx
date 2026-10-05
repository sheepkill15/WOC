import { useEffect, useMemo, useRef, useState } from "react";
import { useCleaner } from "../store";
import { baseName, confidenceLabels, confidenceTone, formatAge, formatBytes, formatCount, kindLabels, rootLabels, safetyLabels, safetyTone } from "../format";
import type { CandidateGroup, CandidateItem } from "../types";
import { Badge, Checkbox, Empty, Icon, Notice, PageHeader, SizeBar } from "../ui";
import { ReasonList } from "../DirectoryDetails";
import { CleanupDialog } from "../CleanupDialog";
import { remainingCleanupSelection } from "../cleanupSelection";

const kindLabel: Record<string, string> = {
  uninstalled: "Uninstalled app", old_version: "Old version", possible_leftover: "Possible leftover", unregistered: "Unregistered app",
  regenerable_cache: "App cache", tool_cache: "Developer cache", unknown_large: "Unknown",
};

function defaultSelection(groups: CandidateGroup[]): Set<string> {
  const selected = new Set<string>();
  for (const group of groups) {
    for (const item of group.items) {
      if (item.defaultSelected) selected.add(item.path);
      else item.content.filter(content => content.defaultSelected).forEach(content => selected.add(content.path));
    }
  }
  return selected;
}

function itemSelectedBytes(item: CandidateItem, selected: Set<string>): number {
  if (selected.has(item.path)) return item.sizeBytes;
  return item.content.filter(content => selected.has(content.path)).reduce((sum, content) => sum + content.sizeBytes, 0);
}

function GroupCard({ group, selected, setSelected, expanded, onToggle }: {
  group: CandidateGroup; selected: Set<string>; setSelected: (updater: (previous: Set<string>) => Set<string>) => void; expanded: boolean; onToggle: () => void;
}) {
  const { openPath, addRule } = useCleaner();
  const selectedBytes = group.items.reduce((sum, item) => sum + itemSelectedBytes(item, selected), 0);
  const selectablePaths = group.items.flatMap(item => item.selectableWhole ? [item.path] : item.content.filter(content => content.selectable).map(content => content.path));
  const anySelected = selectedBytes > 0 || group.items.some(item => selected.has(item.path) || item.content.some(content => selected.has(content.path)));
  const recommended = defaultSelection([group]);
  const coveredByWhole = (path: string) => group.items.some(item => selected.has(item.path) && path.toLowerCase().startsWith(`${item.path.toLowerCase()}\\`));
  const allSelected = selectablePaths.length > 0 && selectablePaths.every(path => selected.has(path) || coveredByWhole(path));
  const setMany = (paths: string[], value: boolean) => setSelected(previous => {
    const next = new Set(previous);
    for (const path of paths) { if (value) next.add(path); else next.delete(path); }
    return next;
  });
  const groupPaths = group.items.flatMap(item => [item.path, ...item.content.map(content => content.path)]);

  return <article className={`group-card priority-${group.priority} ${expanded ? "expanded" : ""}`}>
    <header className="group-head" onClick={onToggle}>
      <Checkbox label={`Select ${group.title}`} checked={allSelected} indeterminate={anySelected && !allSelected} disabled={selectablePaths.length === 0}
        onChange={value => { if (value) setMany(recommended.size && !anySelected ? [...recommended] : selectablePaths, true); else setMany(groupPaths, false); }} />
      <div className="group-title">
        <div className="group-title-row"><h3>{group.title}</h3><Badge tone="muted">{kindLabel[group.kind] ?? group.kind}</Badge></div>
        <p>{group.summary}</p>
      </div>
      <div className="group-metrics">
        <div><span>Size</span><b>{formatBytes(group.totalBytes)}</b></div>
        <div><span>Selected</span><b className={selectedBytes ? "text-accent" : undefined}>{formatBytes(selectedBytes)}</b></div>
        <div className="group-badges">
          <Badge tone={confidenceTone(group.confidence)} title="Orphan confidence">{confidenceLabels[group.confidence] ?? group.confidence}</Badge>
          <Badge tone={safetyTone(group.safety)} title="Most restrictive content safety">{safetyLabels[group.safety] ?? group.safety}</Badge>
        </div>
      </div>
      <span className={`chevron ${expanded ? "open" : ""}`}><Icon name="chevron" size={16} /></span>
    </header>
    {expanded && <div className="group-body">
      <p className="group-hint">{selectablePaths.length === 0 ? "Shown for information. Nothing here can be selected." : "Why it's listed:"}</p>
      <ReasonList reasons={group.reasons} />
      {group.items.map(item => {
        const wholeSelected = selected.has(item.path);
        const safetyTotals = item.content.reduce<Record<string, number>>((totals, content) => ({ ...totals, [content.safety]: (totals[content.safety] ?? 0) + content.sizeBytes }), {});
        return <div className="candidate-item" key={item.path}>
          <div className="candidate-item-head">
            <Checkbox label={`Select whole folder ${item.path}`} checked={wholeSelected} disabled={!item.selectableWhole}
              onChange={value => setMany([item.path], value)} />
            <div className="candidate-path">
              <strong title={item.path}>{baseName(item.path)}</strong>
              <span title={item.path}>{rootLabels[item.root] ?? item.root} · {item.path}</span>
            </div>
            <span className="muted small">changed {formatAge(item.newestModifiedUnix)}</span>
            <b>{formatBytes(item.sizeBytes)}</b>
            <button className="icon-button" title="Open folder" onClick={() => void openPath(item.path)}><Icon name="open" size={15} /></button>
          </div>
          {!item.selectableWhole && group.kind !== "unknown_large" && <p className="muted small indent">Only individual subfolders can be selected here{group.kind === "regenerable_cache" ? " because the application is installed" : ""}.</p>}
          {item.content.length > 0 && <>
            <div className="indent"><SizeBar segments={(["safe", "likely_safe", "review", "unknown", "preserve"] as const).map(safety => ({ value: safetyTotals[safety] ?? 0, tone: safetyTone(safety), label: `${safetyLabels[safety]} ${formatBytes(safetyTotals[safety] ?? 0)}` }))} /></div>
            <ul className="content-list indent">
              {item.content.map(content => <li key={content.path} title={content.reason} className={wholeSelected ? "covered" : undefined}>
                {content.selectable ? <Checkbox label={`Select ${content.name}`} checked={wholeSelected || selected.has(content.path)} disabled={wholeSelected} onChange={value => setMany([content.path], value)} /> : <span className="checkbox-spacer" />}
                <span className="content-name">{content.name}</span>
                <span className="content-kind">{kindLabels[content.kind] ?? content.kind}</span>
                <span className="content-size">{formatBytes(content.sizeBytes)}</span>
                <Badge tone={safetyTone(content.safety)}>{safetyLabels[content.safety] ?? content.safety}</Badge>
              </li>)}
            </ul>
          </>}
        </div>;
      })}
      <div className="group-actions">
        {recommended.size > 0 && <button className="ghost" onClick={() => setMany([...recommended], true)}>Select recommended</button>}
        {selectablePaths.length > 0 && <button className="ghost" onClick={() => setMany(selectablePaths, true)}>Select everything</button>}
        {anySelected && <button className="ghost" onClick={() => setMany(groupPaths, false)}>Clear</button>}
        <span className="spacer" />
        <button className="ghost" onClick={() => void addRule("once", group.items[0]?.path ?? "", `${group.title} (this scan)`)} disabled={group.items.length !== 1}>Ignore once</button>
        {group.ownerName && <button className="ghost" onClick={() => void addRule("application", group.ownerName!, group.ownerName!)}>Always keep {group.ownerName}</button>}
        {group.items.length === 1 && <button className="ghost" onClick={() => void addRule("path", group.items[0].path, group.items[0].path)}>Always ignore folder</button>}
      </div>
    </div>}
  </article>;
}

export function Cleanup() {
  const { candidates, rules, removeRule, backend, running, quarantine } = useCleaner();
  const [selected, setSelectedState] = useState<Set<string>>(new Set());
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [dialogPaths, setDialogPaths] = useState<string[] | null>(null);
  const [manualPath, setManualPath] = useState("");
  const [manualDialog, setManualDialog] = useState(false);
  const [filter, setFilter] = useState<"all" | "high" | "review" | "info">("all");
  const initializedFor = useRef<number | null | undefined>(undefined);
  const connected = backend === "tauri" || backend === "agent";

  useEffect(() => {
    if (!candidates) return;
    if (initializedFor.current !== candidates.scanAtUnix) {
      initializedFor.current = candidates.scanAtUnix;
      setSelectedState(defaultSelection(candidates.groups.filter(group => group.priority === "high")));
      setExpanded(new Set(candidates.groups.filter(group => group.priority === "high").slice(0, 2).map(group => group.id)));
    } else {
      // Drop selections that disappeared (quarantined or ignored).
      const valid = new Set(candidates.groups.flatMap(group => group.items.flatMap(item => [item.path, ...item.content.map(content => content.path)])));
      setSelectedState(previous => new Set([...previous].filter(path => valid.has(path))));
    }
  }, [candidates]);

  const groups = useMemo(() => (candidates?.groups ?? []).filter(group => filter === "all" || group.priority === filter), [candidates, filter]);
  const allItems = useMemo(() => (candidates?.groups ?? []).flatMap(group => group.items), [candidates]);
  const selectedBytes = allItems.reduce((sum, item) => sum + itemSelectedBytes(item, selected), 0);
  const selectedPaths = [...selected];
  const counts = { high: 0, review: 0, info: 0 };
  for (const group of candidates?.groups ?? []) counts[group.priority]++;
  const setSelected = (updater: (previous: Set<string>) => Set<string>) => setSelectedState(updater);

  const manualForm = <form className="manual-cleanup" onSubmit={event => {
    event.preventDefault();
    if (manualPath.trim()) { setManualDialog(true); setDialogPaths([manualPath.trim()]); }
  }}>
    <label className="field"><span>Clean a file or folder manually</span>
      <input aria-label="Manual cleanup path" placeholder="C:\\Users\\you\\Downloads\\Unneeded folder" value={manualPath} onChange={event => setManualPath(event.target.value)} />
    </label>
    <p className="muted small">Enter a full local path, including personal folders or paths outside the scan. You'll review the risks and quarantine location before anything moves.</p>
    <button className="secondary" disabled={!connected || running || !manualPath.trim()}>Review manual cleanup</button>
  </form>;
  const dialog = dialogPaths && <CleanupDialog manual={manualDialog} paths={dialogPaths} onClose={() => setDialogPaths(null)} onDone={outcome => {
    setSelectedState(previous => remainingCleanupSelection(previous, outcome));
  }} />;

  if (!candidates || candidates.scanAtUnix === null) {
    return <div className="page"><PageHeader title="Cleanup" description="Folders that were left behind or can be recreated, grouped by application." />
      {manualForm}
      <Empty icon="cleanup" title="No saved scan yet">Run a scan for recommended candidates, or enter a path above for manual cleanup.</Empty>{dialog}</div>;
  }

  return <div className="page with-selection-bar">
    <PageHeader title="Cleanup"
      description={counts.high > 0
        ? <>Recommended items are already ticked; they only contain data that can be recreated. Open a group to see why it's listed, tick anything else you don't need, then click <b>Review &amp; clean</b>.</>
        : <>Nothing is certain enough to tick for you. Open a group to see why it's listed, tick what you know you don't need, then click <b>Review &amp; clean</b>.</>} />
    {running && <Notice>A scan is running. Candidates below are from the previous saved scan.</Notice>}
    {manualForm}
    <div className="filter-row">
      <div className="segmented">
        {([["all", "All", candidates.groups.length], ["high", "Recommended", counts.high], ["review", "Needs your decision", counts.review], ["info", "Information only", counts.info]] as const).map(([key, label, count]) =>
          <button key={key} className={filter === key ? "active" : ""} onClick={() => setFilter(key)}>{label}<span>{count}</span></button>)}
      </div>
      <div className="filter-actions">
        <button className="ghost" onClick={() => setExpanded(new Set(groups.map(group => group.id)))}>Expand all</button>
        <button className="ghost" onClick={() => setExpanded(new Set())}>Collapse all</button>
      </div>
    </div>
    {groups.length === 0 ? <Empty icon="check" title="Nothing here">No candidates in this category. {candidates.ignoredPaths ? `${formatCount(candidates.ignoredPaths, "folder")} hidden by ignore rules.` : ""}</Empty>
      : <div className="group-list">{groups.map(group => <GroupCard key={group.id} group={group} selected={selected} setSelected={setSelected}
        expanded={expanded.has(group.id)} onToggle={() => setExpanded(previous => { const next = new Set(previous); if (next.has(group.id)) next.delete(group.id); else next.add(group.id); return next; })} />)}</div>}

    {candidates.ignoredGroups.length > 0 && <details className="ignored-section">
      <summary>{formatCount(candidates.ignoredGroups.length, "group")} kept by your rules</summary>
      <ul>{candidates.ignoredGroups.map(group => {
        const rule = rules.find(candidate => candidate.kind === "application" && candidate.label === group.ignoredBy);
        return <li key={group.id}><span><b>{group.title}</b> · {formatBytes(group.totalBytes)} · kept by “{group.ignoredBy}”</span>{rule && <button className="ghost" onClick={() => void removeRule(rule.id)}>Stop keeping</button>}</li>;
      })}</ul>
    </details>}
    {(candidates.ignoredPaths > 0 || candidates.quarantinedPaths > 0) && <p className="muted small">{candidates.ignoredPaths > 0 && `${formatCount(candidates.ignoredPaths, "folder")} hidden by ignore rules. `}{candidates.quarantinedPaths > 0 && `${formatCount(candidates.quarantinedPaths, "folder")} already cleaned since this scan.`}</p>}

    <div className={`selection-bar visible ${selected.size ? "" : "idle"}`}>
      {selected.size ? <div><strong>{formatCount(selected.size, "item")} selected · {formatBytes(selectedBytes)}</strong><span>Next you'll see a plan. Nothing moves until you confirm, and everything goes to quarantine{quarantine?.retentionDays ? ` for ${quarantine.retentionDays} days` : ""}.</span></div>
        : <div><strong>Tick the folders you want to remove</strong><span>Selected items are moved to quarantine, not deleted, so you can restore them.</span></div>}
      {selected.size > 0 && <button className="ghost" onClick={() => setSelectedState(new Set())}>Clear selection</button>}
      <button className="primary" disabled={!connected || running || selected.size === 0} onClick={() => { setManualDialog(false); setDialogPaths(selectedPaths); }}>Review &amp; clean</button>
    </div>
    {dialog}
  </div>;
}
