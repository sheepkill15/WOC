import { useEffect, useState } from "react";
import { useCleaner } from "../store";
import { baseName, formatBytes, formatCount, formatDate } from "../format";
import type { QuarantineItem } from "../types";
import { Badge, Empty, Icon, Modal, Notice, PageHeader, Section } from "../ui";

export function Quarantine({ navigate }: { navigate: (route: "settings") => void }) {
  const { quarantine, refreshQuarantine, restore, purge, openPath, backend } = useCleaner();
  const [confirm, setConfirm] = useState<QuarantineItem[] | null>(null);
  const [busy, setBusy] = useState(false);
  const connected = backend === "tauri" || backend === "agent";
  useEffect(() => { if (connected) void refreshQuarantine(); }, [connected, refreshQuarantine]);
  const items = quarantine?.items ?? [];
  const daysLeft = (item: QuarantineItem) => quarantine && quarantine.retentionDays > 0
    ? Math.max(0, Math.ceil((item.createdAtUnix + quarantine.retentionDays * 86400 - Date.now() / 1000) / 86400)) : null;

  async function purgeAll(list: QuarantineItem[]) {
    setBusy(true);
    for (const item of list) await purge(item.id);
    setBusy(false);
    setConfirm(null);
  }

  return <div className="page">
    <PageHeader title="Quarantine" description="Everything you clean waits here, unchanged. Restore anything you miss. The disk space is only freed once items are deleted permanently."
      actions={items.length > 0 && <button className="ghost danger-text" disabled={busy} onClick={() => setConfirm(items)}><Icon name="trash" size={15} /> Delete all permanently</button>} />
    {quarantine && <p className="scan-meta page-meta">
      <span><b>{formatCount(items.length, "item")}</b> holding <b>{formatBytes(quarantine.totalBytes)}</b></span>
      <span>{quarantine.retentionDays ? <>Deleted automatically after <b>{quarantine.retentionDays} days</b></> : "Kept until you delete them"} · <button className="link" onClick={() => navigate("settings")}>Change</button></span>
    </p>}
    {quarantine && quarantine.expiredPurged > 0 && <Notice>{formatCount(quarantine.expiredPurged, "expired item")} were permanently deleted according to the retention setting.</Notice>}
    <Section title="In quarantine">
      {items.length === 0 ? <Empty icon="quarantine" title="Quarantine is empty">Items you clean are moved here first, so every cleanup can be undone.</Empty>
        : <ul className="quarantine-list">{items.map(item => {
          const left = daysLeft(item);
          return <li key={item.id}>
            <div className="quarantine-main">
              <strong title={item.originalPath}>{baseName(item.originalPath)}</strong>
              <span title={item.originalPath}>{item.originalPath}</span>
              <small>{item.owner ? `${item.owner} · ` : ""}{item.itemKind === "shortcut" ? "Shortcut" : item.itemKind === "file" ? "File" : "Folder"} · moved {formatDate(item.createdAtUnix)}{left !== null ? ` · deleted automatically in ${left} day${left === 1 ? "" : "s"}` : ""}</small>
            </div>
            <b>{formatBytes(item.sizeBytes)}</b>
            <div className="quarantine-actions">
              <button className="icon-button" title="Show in quarantine folder" onClick={() => void openPath(item.quarantinePath)}><Icon name="open" size={15} /></button>
              <button className="secondary" disabled={busy} onClick={() => void restore(item.id)}><Icon name="restore" size={15} /> Restore</button>
              <button className="ghost danger-text" disabled={busy} onClick={() => setConfirm([item])}>Delete</button>
            </div>
          </li>;
        })}</ul>}
    </Section>
    {quarantine && quarantine.history.length > 0 && <Section title="Recent history">
      <ul className="history-list">{quarantine.history.map(item => <li key={item.id}>
        <Badge tone={item.status === "restored" ? "good" : "muted"}>{item.status === "restored" ? "Restored" : "Deleted"}</Badge>
        <span title={item.originalPath}>{item.originalPath}</span><small>{formatDate(item.updatedAtUnix)}</small><b>{formatBytes(item.sizeBytes)}</b>
      </li>)}</ul>
    </Section>}
    {quarantine && <p className="muted small">Default quarantine folder: <code>{quarantine.quarantineDirectory}</code>. Items from other drives are quarantined on their original drive; use “Show in quarantine folder” to find them.</p>}
    {confirm && <Modal title="Delete permanently?" onClose={() => setConfirm(null)} footer={<>
      <button className="ghost" onClick={() => setConfirm(null)}>Cancel</button>
      <button className="primary danger" disabled={busy} onClick={() => void purgeAll(confirm)}>{busy ? "Deleting…" : `Delete ${formatCount(confirm.length, "item")}`}</button>
    </>}>
      <p>{formatCount(confirm.length, "item")} ({formatBytes(confirm.reduce((sum, item) => sum + item.sizeBytes, 0))}) will be deleted from disk. This cannot be undone.</p>
      <ul className="plain-list">{confirm.slice(0, 8).map(item => <li key={item.id}>{item.originalPath}</li>)}{confirm.length > 8 && <li>…and {confirm.length - 8} more</li>}</ul>
    </Modal>}
  </div>;
}
