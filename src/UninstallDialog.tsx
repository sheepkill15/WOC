import { useEffect, useState } from "react";
import { useCleaner } from "./store";
import { Modal, Notice } from "./ui";
import { CleanupDialog } from "./CleanupDialog";
import type { Application, UninstallReview } from "./types";

export function UninstallDialog({ application, onClose }: { application: Application; onClose: () => void }) {
  const { planUninstall, launchUninstall, finishUninstall, notify } = useCleaner();
  const [review, setReview] = useState<UninstallReview | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [launched, setLaunched] = useState(false);
  const [paths, setPaths] = useState<string[] | null>(null);
  useEffect(() => {
    let active = true;
    planUninstall(application.id).then(value => { if (active) setReview(value); }).catch(cause => { if (active) setError(String(cause instanceof Error ? cause.message : cause)); });
    return () => { active = false; };
  }, [application.id, planUninstall]);
  async function run() {
    if (!review) return;
    setBusy(true); setError("");
    try {
      if (!launched) { await launchUninstall(review.token); setLaunched(true); }
      else {
        const remaining = await finishUninstall(review.token);
        setPaths(remaining);
        notify(`${application.name} is no longer installed.${remaining.length ? " Review its remaining folders." : " No linked folders remain."}`, "success");
      }
    } catch (cause) { setError(String(cause instanceof Error ? cause.message : cause)); }
    finally { setBusy(false); }
  }
  if (paths?.length && review) return <CleanupDialog manual paths={paths} uninstallToken={review.token} onClose={onClose} />;
  return <Modal wide title={`Uninstall ${application.name}`} onClose={() => { if (!busy) onClose(); }} footer={<>
    <button className="ghost" disabled={busy} onClick={onClose}>{paths ? "Done" : "Close"}</button>
    {!paths && <button className="primary danger" disabled={!review || busy} onClick={() => void run()}>{busy ? "Checking…" : launched ? "Uninstall finished — check remaining folders" : "Run uninstaller"}</button>}
  </>}>
    {error && <Notice tone="error">{error}</Notice>}
    {!review && !error && <p>Finding the uninstaller and linked folders…</p>}
    {review && <>
      <p>{launched ? "Complete the Windows uninstaller, then check below. If it was canceled or the app is still installed, no folders will be moved." : "Run the application's uninstaller, then remove its remaining linked folders through a reviewed quarantine operation."}</p>
      <p className="muted small">{review.plan.source}: <code>{review.plan.executable} {review.plan.arguments}</code></p>
      <h4>Folders to check after uninstall ({review.plan.folders.length})</h4>
      <ul className="uninstall-paths">{review.plan.folders.map(path => <li key={path}>{path}</li>)}</ul>
      {review.plan.excludedFolders.length > 0 && <Notice tone="warn">Shared folders and folders containing unrelated data are excluded.<ul className="uninstall-paths">{review.plan.excludedFolders.map(path => <li key={path}>{path}</li>)}</ul></Notice>}
      {paths && <Notice tone="success">Uninstall verified. No linked folders remain.</Notice>}
    </>}
  </Modal>;
}
