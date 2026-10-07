import { useMemo, useState } from "react";
import { useCleaner } from "./store";
import {
  actionLabels, baseName, confidenceLabels, confidenceTone, evidenceStrengthOrder, formatAge, formatBytes, formatCount, formatDate,
  kindLabels, ownerLabel, rootLabels, safetyLabels, safetyTone, statusBadge,
} from "./format";
import type { DirectoryResult } from "./types";
import { Badge, Checkbox, Icon, SizeBar } from "./ui";
import { CleanupDialog } from "./CleanupDialog";
import { remainingCleanupSelection } from "./cleanupSelection";
import { FolderLinkDialog } from "./FolderLinkDialog";

export function ReasonList({ reasons }: { reasons: { tone: string; text: string }[] }) {
  if (!reasons.length) return null;
  return <ul className="reasons">
    {reasons.map((reason, index) => <li key={index} className={`reason reason-${reason.tone}`}>
      <Icon name={reason.tone === "positive" ? "check" : reason.tone === "negative" ? "close" : "info"} size={14} />
      <span>{reason.text}</span>
    </li>)}
  </ul>;
}

export function DirectoryDetails({ result, onClose }: { result: DirectoryResult; onClose?: () => void }) {
  const { openPath, addRule, backend, running } = useCleaner();
  const [selection, setSelection] = useState<Set<string>>(new Set());
  const [cleanupPaths, setCleanupPaths] = useState<string[] | null>(null);
  const [connecting, setConnecting] = useState(false);
  const badge = statusBadge(result);
  const assessment = result.assessment;
  const items = result.content?.items ?? [];
  const owner = ownerLabel(result);
  const bySafety = useMemo(() => {
    const totals: Record<string, number> = {};
    for (const item of items) totals[item.safety] = (totals[item.safety] ?? 0) + item.sizeBytes;
    return totals;
  }, [items]);
  const evidence = [...result.evidence].sort((left, right) => (evidenceStrengthOrder[left.strength] ?? 3) - (evidenceStrengthOrder[right.strength] ?? 3));
  const childPath = (name: string) => `${result.path.replace(/\\$/, "")}\\${name}`;
  const toggle = (path: string, value: boolean) => setSelection(previous => {
    const next = new Set(previous);
    if (value) next.add(path); else next.delete(path);
    return next;
  });
  const connected = backend === "tauri" || backend === "agent";

  return <div className="details">
    <div className="details-head">
      <div className="details-title">
        <span className="eyebrow">{rootLabels[result.root] ?? result.root}{result.parentPath ? " · nested" : ""}</span>
        <h3 title={result.path}>{baseName(result.path)}</h3>
        <p className="path" title={result.path}>{result.path}</p>
      </div>
      {onClose && <button className="icon-button" onClick={onClose} aria-label="Close details"><Icon name="close" /></button>}
    </div>
    <div className="details-badges">
      <Badge tone={badge.tone}>{badge.label}</Badge>
      {assessment && <Badge tone={confidenceTone(assessment.orphanConfidence)} title="Orphan confidence">Orphan: {confidenceLabels[assessment.orphanConfidence] ?? assessment.orphanConfidence}</Badge>}
      {assessment && <Badge tone={safetyTone(assessment.deletionSafety)} title="Deletion safety">Safety: {safetyLabels[assessment.deletionSafety] ?? assessment.deletionSafety}</Badge>}
      {assessment && assessment.recommendedAction !== "keep" && <Badge tone="accent">{actionLabels[assessment.recommendedAction]}</Badge>}
    </div>
    <div className="detail-grid">
      <div><span>Size</span><strong>{formatBytes(result.sizeBytes)}</strong></div>
      <div><span>Files</span><strong>{result.fileCount.toLocaleString()}</strong></div>
      <div><span>Owner</span><strong title={owner}>{owner}</strong></div>
      <div><span>Last change</span><strong title={formatDate(result.newestModifiedUnix)}>{formatAge(result.newestModifiedUnix)}</strong></div>
    </div>

    {!result.owner && result.ownership === "shared" && result.orphanStatus === "associated_with_installed" && (result.associatedApplications?.length ?? 0) > 0 && <div className="details-block">
      <h4>Associated applications</h4>
      <ul>{result.associatedApplications!.map(app => <li key={app.id}>{app.name}</li>)}</ul>
      <p className="muted small">This is a shared relationship. No single application owns the whole folder.</p>
    </div>}

    {assessment && assessment.reasons.length > 0 && <div className="details-block">
      <h4>Why</h4>
      <ReasonList reasons={assessment.reasons} />
    </div>}

    {items.length > 0 && <div className="details-block">
      <h4>Contents</h4>
      <SizeBar segments={(["safe", "likely_safe", "review", "unknown", "preserve"] as const).map(safety => ({ value: bySafety[safety] ?? 0, tone: safetyTone(safety), label: `${safetyLabels[safety]}: ${formatBytes(bySafety[safety] ?? 0)}` }))} />
      <ul className="content-list">
        {items.map(item => {
          const path = childPath(item.name);
          const selectable = connected && !running && item.isDirectory;
          return <li key={item.name} title={item.reason}>
            {selectable ? <Checkbox label={`Select ${item.name}`} checked={selection.has(path)} onChange={value => toggle(path, value)} /> : <span className="checkbox-spacer" />}
            <span className="content-name">{item.name}</span>
            <span className="content-kind">{kindLabels[item.kind] ?? item.kind}</span>
            <span className="content-size">{formatBytes(item.sizeBytes)}</span>
            <Badge tone={safetyTone(item.safety)}>{safetyLabels[item.safety] ?? item.safety}</Badge>
          </li>;
        })}
      </ul>
      {result.content && result.content.extensions.length > 0 && <div className="extensions">
        {result.content.extensions.map(extension => <span key={extension.extension} title={formatCount(extension.fileCount, "file")}>.{extension.extension} <b>{formatBytes(extension.sizeBytes)}</b></span>)}
      </div>}
      {result.content && (result.content.executableCount > 0 || result.content.largeFileCount > 0 || result.content.databaseCount > 0) && <p className="muted small">
        {[result.content.executableCount && formatCount(result.content.executableCount, "executable"),
          result.content.databaseCount && formatCount(result.content.databaseCount, "database file"),
          result.content.largeFileCount && `${formatCount(result.content.largeFileCount, "large file")} (${formatBytes(result.content.largeFileBytes)})`].filter(Boolean).join(" · ")}
      </p>}
    </div>}

    {result.executables && result.executables.length > 0 && <div className="details-block">
      <h4>Executable metadata</h4>
      {result.executables.map(executable => <div key={executable.fileName} className="executable">
        <strong>{executable.fileName}</strong>
        <span>{[executable.productName, executable.companyName, executable.productVersion].filter(Boolean).join(" · ") || "No version information"}</span>
      </div>)}
      <p className="muted small">Read from the file's version resource. Files are never run.</p>
    </div>}

    <div className="details-block">
      <h4>Evidence</h4>
      {evidence.length ? evidence.map((item, index) => <div className="evidence" key={index}>
        <span className={`strength strength-${item.strength}`}>{item.strength}</span>
        <p>{item.description}</p>
      </div>) : <p className="muted small">No ownership evidence was found.</p>}
      {result.skippedEntries > 0 && <p className="text-warn small">{formatCount(result.skippedEntries, "entry", "entries")} could not be read; the size may be incomplete.</p>}
    </div>

    <div className="details-actions">
      <button className="secondary" disabled={!connected || running} onClick={() => setConnecting(true)}>Connect to application…</button>
      <button className="secondary" disabled={!connected} onClick={() => void openPath(result.path)}><Icon name="open" size={15} /> Open folder</button>
      {connected && <button className="secondary" disabled={running || selection.size === 0} onClick={() => setCleanupPaths([...selection])}>Clean selected ({selection.size})</button>}
      {connected && <button className="ghost danger-text" disabled={running} onClick={() => setCleanupPaths([result.path])}><Icon name="quarantine" size={15} /> Quarantine folder…</button>}
      <details className="menu">
        <summary className="ghost">Ignore…</summary>
        <div className="menu-panel">
          <button onClick={() => void addRule("once", result.path, baseName(result.path))}>Hide until next scan</button>
          <button onClick={() => void addRule("path", result.path, result.path)}>Always ignore this folder</button>
          {(result.owner || result.ownerHint) && <button onClick={() => void addRule("application", owner, owner)}>Always keep {owner}</button>}
        </div>
      </details>
    </div>
    {cleanupPaths && <CleanupDialog manual paths={cleanupPaths} onClose={() => setCleanupPaths(null)} onDone={outcome => {
      setSelection(previous => remainingCleanupSelection(previous, outcome));
    }} />}
    {connecting && <FolderLinkDialog folder={result} onClose={() => setConnecting(false)} />}
  </div>;
}
