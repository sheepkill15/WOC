import { useEffect, useMemo, useState } from "react";
import { useCleaner } from "../store";
import { formatAge, formatBytes, ownerLabel, rootLabels, safetyLabels, safetyTone, shortPath, statusBadge, type StatusGroup } from "../format";
import { Badge, Empty, Icon, PageHeader } from "../ui";
import { DirectoryDetails } from "../DirectoryDetails";

type SortKey = "size" | "name" | "age";

export function Inventory({ focusPath, clearFocus }: { focusPath: string | null; clearFocus: () => void }) {
  const { results, running, progressPath, summary, rules, quarantine } = useCleaner();
  const [group, setGroup] = useState<"all" | StatusGroup>("all");
  const [root, setRoot] = useState("all");
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<SortKey>("size");
  const [selectedPath, setSelectedPath] = useState<string | null>(null);

  useEffect(() => {
    if (focusPath) { setSelectedPath(focusPath); setGroup("all"); setQuery(""); setRoot("all"); clearFocus(); }
  }, [focusPath, clearFocus]);

  const ignored = useMemo(() => rules.filter(rule => rule.kind === "path").map(rule => rule.value.toLowerCase()), [rules]);
  const quarantined = useMemo(() => new Set((quarantine?.items ?? []).map(item => item.originalPath.toLowerCase())), [quarantine]);
  const roots = useMemo(() => [...new Set(results.map(result => result.root))], [results]);
  const counts = useMemo(() => {
    const totals: Record<string, number> = { all: results.length, matched: 0, known: 0, former: 0, unregistered: 0, unknown: 0 };
    for (const result of results) totals[statusBadge(result).group]++;
    return totals;
  }, [results]);
  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return results.filter(result => {
      if (group !== "all" && statusBadge(result).group !== group) return false;
      if (root !== "all" && result.root !== root) return false;
      if (!needle) return true;
      return `${result.path} ${ownerLabel(result)}`.toLowerCase().includes(needle);
    }).sort((left, right) => sort === "size" ? right.sizeBytes - left.sizeBytes
      : sort === "age" ? (left.newestModifiedUnix ?? 0) - (right.newestModifiedUnix ?? 0)
      : left.path.localeCompare(right.path));
  }, [results, group, root, query, sort]);
  const selected = results.find(result => result.path === selectedPath) ?? null;

  const tabs: [typeof group, string][] = [["all", "All"], ["matched", "Installed"], ["former", "Leftovers"], ["unregistered", "Unregistered"], ["known", "Known / Windows"], ["unknown", "Unknown"]];

  return <div className="page page-wide">
    <PageHeader eyebrow={summary ? `${summary.mode === "deep" ? "Deep" : "Quick"} scan` : undefined} title="All folders"
      description="Every inspected folder with its probable owner. Unknown means no reliable owner was found — not that it is safe to remove." />
    {running && <div className="progress-line"><span className="spinner" /><span title={progressPath}>{progressPath || "Preparing…"}</span><b>{results.length.toLocaleString()} folders so far</b></div>}
    <div className="toolbar">
      <div className="tabs">{tabs.map(([key, label]) => <button key={key} className={group === key ? "selected" : ""} onClick={() => setGroup(key)}>{label}<span>{counts[key]}</span></button>)}</div>
      <div className="toolbar-controls">
        <select value={root} onChange={event => setRoot(event.target.value)} aria-label="Location">
          <option value="all">All locations</option>
          {roots.map(value => <option key={value} value={value}>{rootLabels[value] ?? value}</option>)}
        </select>
        <select value={sort} onChange={event => setSort(event.target.value as SortKey)} aria-label="Sort">
          <option value="size">Largest first</option><option value="age">Oldest change first</option><option value="name">By path</option>
        </select>
        <div className="search"><Icon name="analyzer" size={15} /><input aria-label="Search folders" placeholder="Search folders or owners" value={query} onChange={event => setQuery(event.target.value)} /></div>
      </div>
    </div>
    <div className={`content-grid ${selected ? "has-details" : ""}`}>
      <div className="table-wrap">
        <table>
          <thead><tr><th>Folder</th><th>Size</th><th>Owner</th><th>Status</th><th>Safety</th><th>Changed</th></tr></thead>
          <tbody>{visible.slice(0, 1500).map(result => {
            const badge = statusBadge(result);
            const lower = result.path.toLowerCase();
            const isIgnored = ignored.some(value => lower === value || lower.startsWith(`${value}\\`));
            return <tr key={result.path} className={selectedPath === result.path ? "selected-row" : ""} onClick={() => setSelectedPath(result.path)}
              onKeyDown={event => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); setSelectedPath(result.path); } }} tabIndex={0} aria-selected={selectedPath === result.path}>
              <td className="cell-path"><strong>{result.parentPath ? "↳ " : ""}{shortPath(result.path)}</strong><small title={result.path}>{rootLabels[result.root] ?? result.root}</small></td>
              <td className="cell-num">{formatBytes(result.sizeBytes)}</td>
              <td className="cell-owner" title={ownerLabel(result)}>{ownerLabel(result)}</td>
              <td><Badge tone={badge.tone}>{badge.label}</Badge>{isIgnored && <Badge tone="muted">Ignored</Badge>}{quarantined.has(lower) && <Badge tone="accent">Quarantined</Badge>}</td>
              <td>{result.assessment ? <Badge tone={safetyTone(result.assessment.deletionSafety)}>{safetyLabels[result.assessment.deletionSafety]}</Badge> : "—"}</td>
              <td className="cell-muted">{formatAge(result.newestModifiedUnix)}</td>
            </tr>;
          })}</tbody>
        </table>
        {visible.length > 1500 && <p className="muted small table-note">Showing the first 1,500 of {visible.length.toLocaleString()} folders. Refine the search to see more.</p>}
        {visible.length === 0 && <Empty icon="folders" title={results.length ? "No folders match" : "No scan results yet"}>{results.length ? "Try another filter or search." : "Start a scan from the sidebar."}</Empty>}
      </div>
      {selected && <aside className="details-panel"><DirectoryDetails key={selected.path} result={selected} onClose={() => setSelectedPath(null)} /></aside>}
    </div>
  </div>;
}
