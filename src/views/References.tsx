import { useMemo, useState } from "react";
import { useCleaner } from "../store";
import { formatCount, referenceKindLabels } from "../format";
import { Badge, Checkbox, Empty, Icon, Notice, PageHeader } from "../ui";
import { CleanupDialog } from "../CleanupDialog";

export function References() {
  const { references, openPath, notify, backend, quarantine } = useCleaner();
  const [status, setStatus] = useState<"dead" | "all" | "ok">("dead");
  const [kind, setKind] = useState("all");
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [dialog, setDialog] = useState<string[] | null>(null);
  const connected = backend === "tauri" || backend === "agent";
  const list = references?.references ?? [];
  const quarantined = useMemo(() => new Set((quarantine?.items ?? []).map(item => item.originalPath.toLowerCase())), [quarantine]);
  const kinds = useMemo(() => [...new Set(list.map(reference => reference.kind))], [list]);
  const visible = useMemo(() => list.filter(reference => (status === "all" || reference.status === status)
    && (kind === "all" || reference.kind === kind)
    && `${reference.name} ${reference.command} ${reference.owner?.name ?? ""}`.toLowerCase().includes(query.toLowerCase())
    && !quarantined.has(reference.location.toLowerCase())), [list, status, kind, query, quarantined]);
  const deadCount = list.filter(reference => reference.status === "dead").length;

  async function copy(text: string) {
    try { await navigator.clipboard.writeText(text); notify("Copied to clipboard.", "success"); } catch { notify("Clipboard is unavailable.", "error"); }
  }

  return <div className="page page-wide">
    <PageHeader eyebrow="Startup · tasks · services · shortcuts · handlers" title="System references"
      description="Places where Windows launches or registers programs. A reference whose program is missing points to software that was removed — and often to data it left behind." />
    {!references && <Empty icon="references" title="No references collected yet">References are collected during each scan.</Empty>}
    {references && <>
      {references.warnings.map((warning, index) => <Notice key={index} tone="warn">{warning}</Notice>)}
      <Notice>Dead Start Menu and Startup shortcuts can be moved to quarantine. Registry entries, services and tasks are shown with their exact location so you can remove them in their own tools; this version does not edit the registry.</Notice>
      <div className="toolbar">
        <div className="tabs">
          {([["dead", `Missing target`, deadCount], ["ok", "Working", list.filter(reference => reference.status === "ok").length], ["all", "All", list.length]] as const).map(([key, label, count]) =>
            <button key={key} className={status === key ? "selected" : ""} onClick={() => setStatus(key)}>{label}<span>{count}</span></button>)}
        </div>
        <div className="toolbar-controls">
          <select value={kind} onChange={event => setKind(event.target.value)} aria-label="Reference type">
            <option value="all">All types</option>
            {kinds.map(value => <option key={value} value={value}>{referenceKindLabels[value] ?? value}</option>)}
          </select>
          <div className="search"><Icon name="analyzer" size={15} /><input placeholder="Search name or command" value={query} onChange={event => setQuery(event.target.value)} aria-label="Search references" /></div>
        </div>
      </div>
      <div className="table-wrap">
        <table>
          <thead><tr><th /><th>Name</th><th>Type</th><th>Target</th><th>Owner</th><th>Status</th><th /></tr></thead>
          <tbody>{visible.slice(0, 1000).map(reference => {
            const canClean = connected && reference.fileBacked && reference.status === "dead";
            return <tr key={reference.id}>
              <td>{canClean ? <Checkbox label={`Select ${reference.name}`} checked={selected.has(reference.location)} onChange={value => setSelected(previous => { const next = new Set(previous); if (value) next.add(reference.location); else next.delete(reference.location); return next; })} /> : null}</td>
              <td className="cell-path"><strong>{reference.name}</strong><small title={reference.location}>{reference.location}</small></td>
              <td>{referenceKindLabels[reference.kind] ?? reference.kind}{reference.machineWide && <small className="block muted">All users</small>}</td>
              <td className="cell-command" title={reference.command}>{reference.targetPath ?? reference.command}</td>
              <td className="cell-owner">{reference.owner?.name ?? <span className="muted">—</span>}</td>
              <td><Badge tone={reference.status === "dead" ? "warn" : reference.status === "ok" ? "good" : "muted"}>{reference.status === "dead" ? "Missing" : reference.status === "ok" ? "OK" : "Unresolved"}</Badge></td>
              <td className="cell-actions">
                <button className="icon-button" title="Copy location" onClick={() => void copy(reference.location)}><Icon name="references" size={15} /></button>
                {reference.fileBacked && <button className="icon-button" title="Show shortcut" onClick={() => void openPath(reference.location)}><Icon name="open" size={15} /></button>}
              </td>
            </tr>;
          })}</tbody>
        </table>
        {visible.length === 0 && <Empty icon="check" title={status === "dead" ? "No dead references" : "Nothing matches"}>{status === "dead" ? "Every startup entry, task, service and shortcut points to an existing program." : "Try another filter."}</Empty>}
      </div>
      <div className={`selection-bar ${selected.size ? "visible" : ""}`}>
        <div><strong>{formatCount(selected.size, "shortcut")} selected</strong><span>Dead shortcuts are moved to quarantine</span></div>
        <button className="ghost" onClick={() => setSelected(new Set())}>Clear</button>
        <button className="primary" disabled={!selected.size} onClick={() => setDialog([...selected])}>Review &amp; clean</button>
      </div>
      {dialog && <CleanupDialog paths={dialog} onClose={() => setDialog(null)} onDone={() => setSelected(new Set())} />}
    </>}
  </div>;
}
