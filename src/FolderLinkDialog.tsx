import { useState } from "react";
import { useCleaner } from "./store";
import { Modal, Notice } from "./ui";
import type { DirectoryResult } from "./types";

export function FolderLinkDialog({ folder, onClose }: { folder: DirectoryResult; onClose: () => void }) {
  const { apps, folderLinks, connectFolder } = useCleaner();
  const existing = folderLinks.find(link => link.path.toLowerCase() === folder.path.toLowerCase());
  const [applicationId, setApplicationId] = useState(existing?.application.id ?? folder.owner?.id ?? "");
  const [query, setQuery] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function save(id: string | null) {
    setBusy(true); setError("");
    try { await connectFolder(folder.path, id); onClose(); }
    catch (cause) { setError(String(cause instanceof Error ? cause.message : cause)); }
    finally { setBusy(false); }
  }
  return <Modal title="Connect folder to an application" onClose={() => { if (!busy) onClose(); }} footer={<>
    {existing && <button className="ghost" disabled={busy} onClick={() => void save(null)}>Remove manual connection</button>}
    <button className="primary" disabled={busy || !apps.some(app => app.id === applicationId)} onClick={() => void save(applicationId)}>{busy ? "Saving…" : "Connect folder"}</button>
  </>}>
    <p className="path">{folder.path}</p>
    <p className="muted small">The connection is remembered across scans. Saved games, documents and other protected contents still require review.</p>
    <input className="full" aria-label="Find application to connect" placeholder="Search applications" value={query} onChange={event => setQuery(event.target.value)} />
    <select className="full link-picker" size={8} aria-label="Application to connect" value={applicationId} onChange={event => setApplicationId(event.target.value)}>
      {apps.filter(app => `${app.name} ${app.publisher ?? ""}`.toLowerCase().includes(query.toLowerCase())).map(app => <option key={app.id} value={app.id}>{app.name}{app.publisher ? ` · ${app.publisher}` : ""}</option>)}
    </select>
    {error && <Notice tone="error">{error}</Notice>}
  </Modal>;
}
