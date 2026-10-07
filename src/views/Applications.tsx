import { useMemo, useState } from "react";
import { useCleaner } from "../store";
import { formatBytes, safetyLabels, safetyTone, shortPath } from "../format";
import { Badge, Empty, Icon, Notice, PageHeader } from "../ui";
import { applicationCatalog } from "../applicationCatalog";
import { DirectoryDetails } from "../DirectoryDetails";
import { FolderLinkDialog } from "../FolderLinkDialog";
import { UninstallDialog } from "../UninstallDialog";
import type { Application, DirectoryResult } from "../types";

export function Applications() {
  const { apps, results, inventoryWarnings, backend, running, folderLinks } = useCleaner();
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<"name" | "data">("data");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [link, setLink] = useState<DirectoryResult | null>(null);
  const [uninstall, setUninstall] = useState<Application | null>(null);
  const connected = backend === "tauri" || backend === "agent";
  const catalog = useMemo(() => applicationCatalog(apps, results), [apps, results]);
  const visible = useMemo(() => catalog.entries.filter(entry => `${entry.application.name} ${entry.application.publisher ?? ""} ${entry.folders.map(folder => folder.path).join(" ")}`.toLowerCase().includes(query.toLowerCase()))
    .sort((left, right) => sort === "name" ? left.application.name.localeCompare(right.application.name) : right.bytes - left.bytes || left.application.name.localeCompare(right.application.name)), [catalog, query, sort]);
  const selectedFolder = results.find(folder => folder.path === selected);
  return <div className="page page-wide">
    <PageHeader title="Applications" description="Installed applications, their measured total size, and every detected folder connected to them. Expand an application to review its folders or uninstall it." />
    {inventoryWarnings.map((warning, index) => <Notice key={index} tone="warn">{warning}</Notice>)}
    <div className="toolbar">
      <span className="muted small">{catalog.entries.length} applications · {formatBytes(catalog.entries.reduce((sum, entry) => sum + entry.bytes, 0))} measured</span>
      <div className="toolbar-controls">
        <select value={sort} onChange={event => setSort(event.target.value as "name" | "data")} aria-label="Sort applications"><option value="data">Largest first</option><option value="name">By name</option></select>
        <div className="search"><Icon name="analyzer" size={15} /><input placeholder="Search apps, publishers or folders" value={query} onChange={event => setQuery(event.target.value)} aria-label="Search applications" /></div>
      </div>
    </div>
    <p className="muted small">Totals count nested folders once and exclude separately detected data belonging to other owners. {running ? "Sizes update as the scan runs." : "Scan again to include installation files in older results."} Unreadable entries can make sizes incomplete.</p>
    <div className={`content-grid ${selectedFolder ? "has-details" : ""}`}>
      <div className="application-list">
        {visible.map(({ application: app, folders, bytes }) => <section className="application-card" key={app.id}>
          <button className="application-heading" aria-expanded={expanded === app.id} onClick={() => setExpanded(expanded === app.id ? null : app.id)}>
            <Icon name="chevron" size={16} /><div className="application-name"><strong>{app.name}</strong><small>{[app.publisher, app.version].filter(Boolean).join(" · ") || "Unknown publisher"}</small></div>
            <div className="application-size"><strong>{folders.length ? formatBytes(bytes) : "Not measured"}</strong><small>{folders.length} detected folders</small></div>
          </button>
          {expanded === app.id && <div className="application-body">
            {folders.length ? <ul className="application-folders">{folders.map(folder => <li key={folder.path}>
              <button className="folder-label link" title={folder.path} onClick={() => setSelected(folder.path)}><strong>{shortPath(folder.path)}</strong><small>{folder.path}</small></button>
              <span>{formatBytes(folder.sizeBytes)}</span>
              <Badge tone={safetyTone(folder.assessment?.deletionSafety || "unknown")}>{safetyLabels[folder.assessment?.deletionSafety || "unknown"]}</Badge>
              <button className="ghost" disabled={!connected || running} onClick={() => setLink(folder)}>{folderLinks.some(link => link.path.toLowerCase() === folder.path.toLowerCase()) ? "Manual connection" : "Connect…"}</button>
            </li>)}</ul> : <p className="muted small">No folders measured yet. Run a scan to discover the installation and application data.</p>}
            <div className="application-actions"><button className="secondary danger-text" disabled={!connected || running} onClick={() => setUninstall(app)}><Icon name="uninstalled" size={15} /> Uninstall and remove folders…</button></div>
          </div>}
        </section>)}
        {visible.length === 0 && <Empty icon="apps" title="No applications">{apps.length ? "Nothing matches the search." : "Connect the Windows backend to read installed applications."}</Empty>}
      </div>
      {selectedFolder && <aside className="details-panel"><DirectoryDetails key={selectedFolder.path} result={selectedFolder} onClose={() => setSelected(null)} /></aside>}
    </div>
    {link && <FolderLinkDialog folder={link} onClose={() => setLink(null)} />}
    {uninstall && <UninstallDialog application={uninstall} onClose={() => setUninstall(null)} />}
  </div>;
}
