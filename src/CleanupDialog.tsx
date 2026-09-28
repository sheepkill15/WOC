import { useEffect, useState } from "react";
import { useCleaner } from "./store";
import { formatBytes, formatCount, safetyLabels, safetyTone } from "./format";
import type { CleanupOutcome, CleanupPlan } from "./types";
import { Badge, Icon, Modal, Notice } from "./ui";

const statusTone = { ready: "good", warning: "warn", blocked: "danger", redundant: "muted" } as const;
const statusLabel = { ready: "Ready", warning: "Needs confirmation", blocked: "Blocked", redundant: "Already included" } as const;

export function CleanupDialog({ paths, onClose, onDone }: { paths: string[]; onClose: () => void; onDone?: (outcome: CleanupOutcome) => void }) {
  const { planCleanup, executeCleanup, notify } = useCleaner();
  const [plan, setPlan] = useState<CleanupPlan | null>(null);
  const [error, setError] = useState("");
  const [acknowledged, setAcknowledged] = useState(false);
  const [executing, setExecuting] = useState(false);
  const [outcome, setOutcome] = useState<CleanupOutcome | null>(null);

  useEffect(() => {
    let active = true;
    planCleanup(paths).then(result => { if (active) setPlan(result); }).catch(cause => { if (active) setError(String(cause instanceof Error ? cause.message : cause)); });
    return () => { active = false; };
  }, [paths, planCleanup]);

  const actionable = plan ? plan.items.filter(item => item.status === "ready" || (item.status === "warning" && acknowledged)) : [];
  const actionableBytes = actionable.reduce((sum, item) => sum + item.sizeBytes, 0);

  async function run() {
    if (!plan) return;
    setExecuting(true);
    try {
      const result = await executeCleanup(paths, acknowledged);
      setOutcome(result);
      onDone?.(result);
      if (result.movedCount) notify(`Moved ${formatCount(result.movedCount, "item")} (${formatBytes(result.movedBytes)}) to quarantine.`, "success");
    } catch (cause) {
      setError(String(cause instanceof Error ? cause.message : cause));
    } finally {
      setExecuting(false);
    }
  }

  if (outcome) {
    return <Modal title="Cleanup finished" onClose={onClose} footer={<button className="primary" onClick={onClose}>Done</button>}>
      <Notice tone={outcome.failedCount ? "warn" : "success"}>
        {outcome.movedCount ? `${formatCount(outcome.movedCount, "item")} (${formatBytes(outcome.movedBytes)}) moved to quarantine. Restore them any time from the Quarantine page.` : "Nothing was moved."}
        {outcome.failedCount > 0 && ` ${formatCount(outcome.failedCount, "item")} could not be moved.`}
      </Notice>
      <ul className="plan-list">
        {outcome.items.map(item => <li key={item.path} className="plan-item">
          <div className="plan-item-head"><Badge tone={item.moved ? "good" : "danger"}>{item.moved ? "Moved" : "Not moved"}</Badge><strong title={item.path}>{item.path}</strong><span>{formatBytes(item.sizeBytes)}</span></div>
          {!item.moved && <p className="plan-message">{item.message}</p>}
        </li>)}
      </ul>
    </Modal>;
  }

  return <Modal wide title="Review cleanup" onClose={onClose} footer={<>
    <span className="modal-foot-note">Items are moved to quarantine, not deleted.</span>
    <button className="ghost" onClick={onClose}>Cancel</button>
    <button className="primary danger" disabled={!plan || executing || actionable.length === 0} onClick={() => void run()}>
      {executing ? "Moving…" : actionable.length ? `Move ${formatCount(actionable.length, "item")} · ${formatBytes(actionableBytes)}` : "Nothing to move"}
    </button>
  </>}>
    {error && <Notice tone="error">{error}</Notice>}
    {!plan && !error && <div className="loading-row"><span className="spinner" /> Revalidating each item against the current installation…</div>}
    {plan && <>
      <div className="plan-summary">
        <div><span>Selected</span><strong>{formatCount(plan.items.length, "item")}</strong></div>
        <div><span>Ready</span><strong className="text-good">{plan.readyCount}</strong></div>
        <div><span>Need confirmation</span><strong className="text-warn">{plan.warningCount}</strong></div>
        <div><span>Blocked</span><strong className="text-danger">{plan.blockedCount}</strong></div>
        <div><span>Total</span><strong>{formatBytes(plan.totalBytes)}</strong></div>
      </div>
      <p className="muted small">Each path was checked again just now: it still exists, is not a link or junction, is not a protected Windows location, and its owner was re-checked against the current list of installed apps. Nothing outside these paths is touched.</p>
      <ul className="plan-list">
        {plan.items.map(item => <li key={item.path} className={`plan-item status-${item.status}`}>
          <div className="plan-item-head">
            <Badge tone={statusTone[item.status]}>{statusLabel[item.status]}</Badge>
            <strong title={item.path}>{item.path}</strong>
            <span>{item.status === "blocked" || item.status === "redundant" ? "—" : formatBytes(item.sizeBytes)}</span>
          </div>
          <div className="plan-item-meta">
            {item.owner && <span>{item.owner}</span>}
            <span>{item.itemKind === "content" ? "Subfolder" : item.itemKind === "shortcut" ? "Shortcut" : "Folder"}</span>
            {item.safety && <Badge tone={safetyTone(item.safety)}>{safetyLabels[item.safety] ?? item.safety}</Badge>}
            {item.fileCount > 0 && <span>{formatCount(item.fileCount, "file")}</span>}
          </div>
          {item.messages.map((messageText, index) => <p key={index} className="plan-message"><Icon name={item.status === "blocked" ? "close" : "alert"} size={13} /> {messageText}</p>)}
        </li>)}
      </ul>
      {plan.warningCount > 0 && <label className="ack">
        <input type="checkbox" checked={acknowledged} onChange={event => setAcknowledged(event.target.checked)} />
        <span>I reviewed the {formatCount(plan.warningCount, "warning")} above and want to move those items too. They stay restorable from quarantine.</span>
      </label>}
      <p className="muted small">Quarantine folder: <code>{plan.quarantineDirectory}</code></p>
    </>}
  </Modal>;
}
