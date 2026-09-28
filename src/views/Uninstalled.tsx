import { useState } from "react";
import { useCleaner } from "../store";
import { baseName, confidenceLabels, confidenceTone, formatBytes, formatCount, formatDate, rootLabels, safetyLabels, safetyTone } from "../format";
import { Badge, Empty, Icon, Modal, Notice, PageHeader, Section } from "../ui";
import { DirectoryDetails } from "../DirectoryDetails";
import type { DirectoryResult } from "../types";

export function Uninstalled({ openFolder }: { openFolder: (path: string) => void }) {
  const { history, removed, postUninstall, runPostUninstall, backend, running } = useCleaner();
  const [checking, setChecking] = useState(false);
  const [detail, setDetail] = useState<DirectoryResult | null>(null);
  const connected = backend === "tauri" || backend === "agent";
  const removedApps = removed?.applications ?? [];

  async function check() {
    setChecking(true);
    try { await runPostUninstall(); } finally { setChecking(false); }
  }

  return <div className="page">
    <PageHeader title="Uninstalled apps"
      description="Apps you uninstalled often leave data behind. Right after uninstalling something, run a post-uninstall check. To remove the leftovers, run a full scan; they then appear in Cleanup."
      actions={<button className="primary" disabled={!connected || checking || running} onClick={() => void check()}><Icon name="refresh" size={15} /> {checking ? "Checking…" : "Post-uninstall check"}</button>} />

    <Section title="Removed since the last scan" description="Compares the current installed-application list with the last saved scan. Fast: only previously linked folders are re-measured.">
      {removed?.warnings.map((warning, index) => <Notice key={index} tone="warn">{warning}</Notice>)}
      {removedApps.length === 0 ? <Empty icon="check" title="No newly removed applications">{removed?.baselineScanAtUnix ? `Compared with the scan from ${formatDate(removed.baselineScanAtUnix)}.` : "Run a full scan first to create a baseline."}</Empty>
        : <ul className="app-rows">{removedApps.map(item => <li key={item.application.id}>
          <div><strong>{item.application.name}</strong>
            <small>{item.application.publisher ?? "Unknown publisher"}{item.application.version ? ` · ${item.application.version}` : ""}</small></div>
          <ul className="mini-paths">{item.directories.slice(0, 4).map(directory => <li key={directory.path}><button className="link" onClick={() => openFolder(directory.path)} title={directory.path}>{rootLabels[directory.root] ?? directory.root}\{baseName(directory.path)}</button><span>{formatBytes(directory.sizeBytes)}</span></li>)}</ul>
          <div className="app-rows-size"><b>{formatBytes(item.remainingBytes)}</b><span>{formatCount(item.directories.length, "folder")}</span></div>
        </li>)}</ul>}
    </Section>

    {postUninstall && <Section title="Post-uninstall check results" description={`Measured ${formatCount(postUninstall.results.length, "folder")} just now. These results are not saved as a scan; run a full scan to update the saved snapshot and the Cleanup page.`}>
      {postUninstall.results.length === 0 ? <Empty icon="check" title="Nothing left behind">No previously linked folders remain for the removed applications.</Empty>
        : <ul className="result-list">{postUninstall.results.map(result => <li key={result.path}><button onClick={() => setDetail(result)}>
          <div><strong>{result.owner?.name ?? result.ownerHint ?? baseName(result.path)}</strong><span title={result.path}>{result.path}</span></div>
          <div className="result-list-side">
            {result.assessment && <Badge tone={confidenceTone(result.assessment.orphanConfidence)}>{confidenceLabels[result.assessment.orphanConfidence]}</Badge>}
            {result.assessment && <Badge tone={safetyTone(result.assessment.deletionSafety)}>{safetyLabels[result.assessment.deletionSafety]}</Badge>}
            <b>{formatBytes(result.sizeBytes)}</b>
          </div>
        </button></li>)}</ul>}
    </Section>}

    <Section title="Previously observed applications" description={history && history.completeScans >= 2 ? `Based on ${formatCount(history.completeScans, "retained scan")}. Historical ownership is evidence, not deletion approval.` : "Needs at least two complete scans. Scan again after uninstalling software."}>
      {!history || history.applications.length === 0 ? <Empty icon="uninstalled" title="No historical leftovers">No remaining folder is linked to an application that disappeared from the retained scans.</Empty>
        : <ul className="app-rows">{history.applications.map(item => <li key={item.application.id}>
          <div><strong>{item.application.name}</strong>
            <small>{item.application.publisher ?? "Unknown publisher"} · {item.lastSeenAtUnix ? `last seen ${formatDate(item.lastSeenAtUnix)}` : "installed before retained history"}</small>
            {item.newlyMissing && <Badge tone="warn">New since previous scan</Badge>}</div>
          <ul className="mini-paths">{item.directories.slice(0, 4).map(directory => <li key={directory.path}><button className="link" onClick={() => openFolder(directory.path)} title={directory.path}>{rootLabels[directory.root] ?? directory.root}\{baseName(directory.path)}</button><span>{formatBytes(directory.sizeBytes)}</span></li>)}</ul>
          <div className="app-rows-size"><b>{formatBytes(item.remainingBytes)}</b><span title={item.confidence === "probable" ? "Linked by the exact folder path in earlier scans" : "Linked by name only"}>{item.confidence === "probable" ? "Strong evidence" : "Name match"}</span></div>
        </li>)}</ul>}
    </Section>
    {detail && <Modal wide title="Folder details" onClose={() => setDetail(null)}><DirectoryDetails result={detail} /></Modal>}
  </div>;
}
