import { useMemo, useState } from "react";
import { useCleaner } from "../store";
import { formatBytes } from "../format";
import { Badge, Empty, Icon, Notice, PageHeader } from "../ui";

export function Applications({ openFolder }: { openFolder: (path: string) => void }) {
  const { apps, results, inventoryWarnings, openPath, backend, references } = useCleaner();
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<"name" | "data">("data");
  const connected = backend === "tauri" || backend === "agent";
  const linked = useMemo(() => {
    const map = new Map<string, { bytes: number; paths: string[] }>();
    for (const result of results) {
      if (!result.owner || result.orphanStatus !== "not_orphaned") continue;
      const entry = map.get(result.owner.id) ?? { bytes: 0, paths: [] };
      if (!result.parentPath) entry.bytes += result.sizeBytes;
      entry.paths.push(result.path);
      map.set(result.owner.id, entry);
    }
    return map;
  }, [results]);
  const referenceCounts = useMemo(() => {
    const map = new Map<string, number>();
    for (const reference of references?.references ?? []) if (reference.owner) map.set(reference.owner.id, (map.get(reference.owner.id) ?? 0) + 1);
    return map;
  }, [references]);
  const visible = useMemo(() => apps.filter(app => `${app.name} ${app.publisher ?? ""}`.toLowerCase().includes(query.toLowerCase()))
    .sort((left, right) => sort === "name" ? left.name.localeCompare(right.name) : (linked.get(right.id)?.bytes ?? 0) - (linked.get(left.id)?.bytes ?? 0)), [apps, query, sort, linked]);

  return <div className="page page-wide">
    <PageHeader title="Installed apps" description="For reference only: everything Windows lists as installed, with the data folders linked to each. Click a size to see those folders." />
    {inventoryWarnings.map((warning, index) => <Notice key={index} tone="warn">{warning}</Notice>)}
    <div className="toolbar">
      <div className="tabs"><button className="selected">Applications<span>{apps.length}</span></button></div>
      <div className="toolbar-controls">
        <select value={sort} onChange={event => setSort(event.target.value as "name" | "data")} aria-label="Sort"><option value="data">Most linked data</option><option value="name">By name</option></select>
        <div className="search"><Icon name="analyzer" size={15} /><input placeholder="Search apps or publishers" value={query} onChange={event => setQuery(event.target.value)} aria-label="Search applications" /></div>
      </div>
    </div>
    <div className="table-wrap">
      <table>
        <thead><tr><th>Application</th><th>Version</th><th>Linked data</th><th>References</th><th>Source</th><th /></tr></thead>
        <tbody>{visible.map(app => {
          const data = linked.get(app.id);
          return <tr key={app.id}>
            <td className="cell-path"><strong>{app.name}</strong><small>{app.publisher ?? "Unknown publisher"}</small></td>
            <td className="cell-muted">{app.version ?? "—"}</td>
            <td>{data ? <button className="link" onClick={() => openFolder(data.paths[0])}>{formatBytes(data.bytes)} · {data.paths.length} folder{data.paths.length === 1 ? "" : "s"}</button> : <span className="muted">—</span>}</td>
            <td className="cell-muted">{referenceCounts.get(app.id) ?? 0}</td>
            <td>{app.packageFamilyName ? <Badge tone="info">MSIX</Badge> : <Badge tone="muted">{app.sources[0]?.split(" ")[0] ?? "Registry"}</Badge>}</td>
            <td className="cell-actions">{app.installLocation && <button className="icon-button" title={`Open ${app.installLocation}`} disabled={!connected} onClick={() => void openPath(app.installLocation!)}><Icon name="open" size={15} /></button>}</td>
          </tr>;
        })}</tbody>
      </table>
      {visible.length === 0 && <Empty icon="apps" title="No applications">{apps.length ? "Nothing matches the search." : "The installed-application inventory is empty."}</Empty>}
    </div>
  </div>;
}
