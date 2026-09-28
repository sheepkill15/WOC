import { useEffect, type ReactNode } from "react";
import type { Tone } from "./format";

const iconPaths: Record<string, ReactNode> = {
  overview: <><rect x="3" y="3" width="7" height="9" rx="1.5" /><rect x="14" y="3" width="7" height="5" rx="1.5" /><rect x="14" y="12" width="7" height="9" rx="1.5" /><rect x="3" y="16" width="7" height="5" rx="1.5" /></>,
  cleanup: <><path d="M4 20h16" /><path d="M7 20l1.5-7h7L17 20" /><path d="M12 13V4" /><path d="M9.5 6.5L12 4l2.5 2.5" /></>,
  uninstalled: <><path d="M21 8l-9-5-9 5 9 5 9-5z" /><path d="M3 8v8l9 5 9-5V8" /><path d="M15 15l4 4M19 15l-4 4" /></>,
  folders: <><path d="M3 6.5A1.5 1.5 0 0 1 4.5 5H9l2 2h8.5A1.5 1.5 0 0 1 21 8.5v9a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 17.5z" /></>,
  references: <><path d="M10 14a4 4 0 0 0 5.66 0l3-3a4 4 0 0 0-5.66-5.66l-1 1" /><path d="M14 10a4 4 0 0 0-5.66 0l-3 3a4 4 0 0 0 5.66 5.66l1-1" /></>,
  apps: <><rect x="3" y="3" width="7" height="7" rx="2" /><rect x="14" y="3" width="7" height="7" rx="2" /><rect x="3" y="14" width="7" height="7" rx="2" /><rect x="14" y="14" width="7" height="7" rx="2" /></>,
  quarantine: <><rect x="3" y="4" width="18" height="5" rx="1.5" /><path d="M5 9v9.5A1.5 1.5 0 0 0 6.5 20h11a1.5 1.5 0 0 0 1.5-1.5V9" /><path d="M10 13h4" /></>,
  rules: <><path d="M3 12s3.5-7 9-7c2 0 3.7.8 5 1.9M21 12s-3.5 7-9 7c-2 0-3.7-.8-5-1.9" /><path d="M4 20L20 4" /></>,
  analyzer: <><circle cx="11" cy="11" r="6.5" /><path d="M20 20l-4.2-4.2" /><path d="M8.5 11h5" /></>,
  settings: <><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z" /></>,
  refresh: <><path d="M20 11a8 8 0 0 0-14.8-3.5L4 9" /><path d="M4 4v5h5" /><path d="M4 13a8 8 0 0 0 14.8 3.5L20 15" /><path d="M20 20v-5h-5" /></>,
  stop: <><rect x="6" y="6" width="12" height="12" rx="2" /></>,
  open: <><path d="M14 4h6v6" /><path d="M20 4l-9 9" /><path d="M19 14v4.5a1.5 1.5 0 0 1-1.5 1.5h-12A1.5 1.5 0 0 1 4 18.5v-12A1.5 1.5 0 0 1 5.5 5H10" /></>,
  check: <><path d="M5 12.5l4.5 4.5L19 7.5" /></>,
  close: <><path d="M6 6l12 12M18 6L6 18" /></>,
  alert: <><path d="M12 4l9 16H3z" /><path d="M12 10v4M12 17.5v.01" /></>,
  info: <><circle cx="12" cy="12" r="9" /><path d="M12 11v5M12 8v.01" /></>,
  chevron: <><path d="M9 6l6 6-6 6" /></>,
  restore: <><path d="M4 12a8 8 0 1 0 2.4-5.7L4 8.5" /><path d="M4 4v4.5h4.5" /></>,
  trash: <><path d="M4 7h16" /><path d="M10 11v6M14 11v6" /><path d="M6 7l1 12.5A1.5 1.5 0 0 0 8.5 21h7a1.5 1.5 0 0 0 1.5-1.5L18 7" /><path d="M9 7V4.5A1.5 1.5 0 0 1 10.5 3h3A1.5 1.5 0 0 1 15 4.5V7" /></>,
  shield: <><path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z" /><path d="M9 12l2 2 4-4" /></>,
  eyeOff: <><path d="M3 3l18 18" /><path d="M10.6 5.1A9.5 9.5 0 0 1 12 5c5.5 0 9 7 9 7a16 16 0 0 1-2.6 3.5M6.6 6.6A16 16 0 0 0 3 12s3.5 7 9 7a9 9 0 0 0 4.4-1.1" /></>,
  sun: <><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" /></>,
  moon: <><path d="M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5z" /></>,
  bolt: <><path d="M13 3L5 14h6l-1 7 8-11h-6z" /></>,
};

export function Icon({ name, size = 18 }: { name: keyof typeof iconPaths | string; size?: number }) {
  return <svg className="icon" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{iconPaths[name] ?? iconPaths.info}</svg>;
}

export function Badge({ tone = "muted", children, title }: { tone?: Tone; children: ReactNode; title?: string }) {
  return <span className={`badge tone-${tone}`} title={title}>{children}</span>;
}

export function Stat({ label, value, hint, tone, onClick }: { label: string; value: ReactNode; hint?: ReactNode; tone?: Tone; onClick?: () => void }) {
  const content = <><span className="stat-label">{label}</span><strong className={tone ? `text-${tone}` : undefined}>{value}</strong>{hint && <small>{hint}</small>}</>;
  return onClick ? <button className="stat stat-button" onClick={onClick}>{content}</button> : <div className="stat">{content}</div>;
}

export function PageHeader({ eyebrow, title, description, actions }: { eyebrow?: string; title: string; description?: ReactNode; actions?: ReactNode }) {
  return <header className="page-header">
    <div>{eyebrow && <div className="eyebrow">{eyebrow}</div>}<h1>{title}</h1>{description && <p>{description}</p>}</div>
    {actions && <div className="page-actions">{actions}</div>}
  </header>;
}

export function Section({ title, description, actions, children }: { title: string; description?: ReactNode; actions?: ReactNode; children: ReactNode }) {
  return <section className="section">
    <div className="section-head"><div><h2>{title}</h2>{description && <p>{description}</p>}</div>{actions}</div>
    {children}
  </section>;
}

export function Empty({ icon = "info", title, children, action }: { icon?: string; title: string; children?: ReactNode; action?: ReactNode }) {
  return <div className="empty"><div className="empty-icon"><Icon name={icon} size={26} /></div><h3>{title}</h3>{children && <p>{children}</p>}{action}</div>;
}

export function Notice({ tone = "info", children, action }: { tone?: "info" | "warn" | "error" | "success"; children: ReactNode; action?: ReactNode }) {
  const icon = tone === "error" || tone === "warn" ? "alert" : tone === "success" ? "check" : "info";
  return <div className={`notice notice-${tone}`}><Icon name={icon} size={16} /><div className="notice-body">{children}</div>{action}</div>;
}

export function Modal({ title, onClose, children, footer, wide }: { title: string; onClose: () => void; children: ReactNode; footer?: ReactNode; wide?: boolean }) {
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => { if (event.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return <div className="modal-backdrop" onMouseDown={event => { if (event.target === event.currentTarget) onClose(); }}>
    <div className={`modal ${wide ? "modal-wide" : ""}`} role="dialog" aria-modal="true" aria-label={title}>
      <div className="modal-head"><h2>{title}</h2><button className="icon-button" onClick={onClose} aria-label="Close"><Icon name="close" /></button></div>
      <div className="modal-body">{children}</div>
      {footer && <div className="modal-foot">{footer}</div>}
    </div>
  </div>;
}

/** Horizontal proportion bar; segments are fractions of the total. */
export function SizeBar({ segments }: { segments: { value: number; tone: Tone; label: string }[] }) {
  const total = segments.reduce((sum, segment) => sum + segment.value, 0);
  if (total <= 0) return <div className="size-bar empty-bar" />;
  return <div className="size-bar" role="img" aria-label={segments.map(segment => segment.label).join(", ")}>
    {segments.filter(segment => segment.value > 0).map((segment, index) => <span key={index} className={`bg-${segment.tone}`} style={{ width: `${Math.max(1.5, segment.value / total * 100)}%` }} title={segment.label} />)}
  </div>;
}

export function Checkbox({ checked, indeterminate, disabled, onChange, label }: { checked: boolean; indeterminate?: boolean; disabled?: boolean; onChange: (value: boolean) => void; label: string }) {
  return <input type="checkbox" className="checkbox" aria-label={label} checked={checked} disabled={disabled}
    ref={element => { if (element) element.indeterminate = Boolean(indeterminate) && !checked; }}
    onChange={event => onChange(event.target.checked)} onClick={event => event.stopPropagation()} />;
}
