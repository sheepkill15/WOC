import { useRef, useState } from "react";
import { formatAge, formatBytes, formatCount } from "../format";
import { Badge, Empty, Icon, Notice, PageHeader, Section, Stat } from "../ui";

// Minimal typings for the File System Access API (not in every TypeScript DOM lib).
type FsHandle = FsFileHandle | FsDirectoryHandle;
type FsFileHandle = { kind: "file"; name: string; getFile(): Promise<File> };
type FsDirectoryHandle = { kind: "directory"; name: string; values(): AsyncIterable<FsHandle> };
type PickerWindow = Window & { showDirectoryPicker?: (options?: { mode?: "read" }) => Promise<FsDirectoryHandle> };

type FileRecord = { path: string; size: number; modified: number };
type ArtifactRecord = { path: string; kind: string; size: number; files: number };
type DuplicateGroup = { size: number; paths: string[] };
type Analysis = {
  root: string; files: number; directories: number; bytes: number; truncated: boolean; durationMs: number;
  largest: FileRecord[]; oldest: FileRecord[]; emptyDirectories: string[]; artifacts: ArtifactRecord[];
  extensions: { extension: string; bytes: number; files: number }[]; duplicates: DuplicateGroup[]; duplicateBytes: number;
};

const ARTIFACT_NAMES: Record<string, string> = {
  node_modules: "npm dependencies", ".next": "Next.js build", ".nuxt": "Nuxt build", ".parcel-cache": "Parcel cache", ".turbo": "Turborepo cache",
  ".gradle": "Gradle cache", "__pycache__": "Python bytecode", ".pytest_cache": "pytest cache", ".mypy_cache": "mypy cache", ".venv": "Python virtualenv",
  venv: "Python virtualenv", ".tox": "tox environments", target: "Build output (Rust/Maven)", dist: "Build output", build: "Build output",
  out: "Build output", obj: ".NET intermediate output", bin: ".NET build output", coverage: "Coverage reports", DerivedData: "Xcode build data",
  ".angular": "Angular cache", ".svelte-kit": "SvelteKit build", ".cache": "Tool cache",
};
const MAX_ENTRIES = 400_000;
const MAX_HASH_BYTES = 2 * 1024 * 1024 * 1024;
const MIN_DUPLICATE_SIZE = 1024 * 1024;
const OLD_SECONDS = 365 * 86400;

function pushTop(list: FileRecord[], record: FileRecord, limit: number, better: (a: FileRecord, b: FileRecord) => boolean) {
  if (list.length < limit) { list.push(record); list.sort((a, b) => (better(a, b) ? -1 : 1)); return; }
  if (better(record, list[list.length - 1])) { list[list.length - 1] = record; list.sort((a, b) => (better(a, b) ? -1 : 1)); }
}

async function sha256(file: File): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
  return [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, "0")).join("");
}

export function FolderAnalyzer({ connected }: { connected: boolean }) {
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState("");
  const [error, setError] = useState("");
  const cancel = useRef(false);
  const supported = typeof window !== "undefined" && typeof (window as PickerWindow).showDirectoryPicker === "function";

  async function analyze() {
    setError("");
    let root: FsDirectoryHandle;
    try {
      root = await (window as PickerWindow).showDirectoryPicker!({ mode: "read" });
    } catch (cause) {
      if ((cause as DOMException)?.name !== "AbortError") setError(String(cause));
      return;
    }
    cancel.current = false;
    setRunning(true);
    setAnalysis(null);
    const started = performance.now();
    const largest: FileRecord[] = [];
    const oldest: FileRecord[] = [];
    const emptyDirectories: string[] = [];
    const artifacts: ArtifactRecord[] = [];
    const extensions = new Map<string, { bytes: number; files: number }>();
    const bySize = new Map<number, { path: string; handle: FsFileHandle }[]>();
    let files = 0, directories = 0, bytes = 0, entries = 0, truncated = false;
    const now = Date.now() / 1000;

    // Returns [bytes, files] for the subtree.
    async function walk(directory: FsDirectoryHandle, path: string, artifactOwner: ArtifactRecord | null): Promise<[number, number]> {
      let subtreeBytes = 0, subtreeFiles = 0, children = 0;
      for await (const handle of directory.values()) {
        if (cancel.current) break;
        if (++entries > MAX_ENTRIES) { truncated = true; break; }
        children++;
        const childPath = `${path}\\${handle.name}`;
        if (handle.kind === "directory") {
          directories++;
          const artifactKind = !artifactOwner ? ARTIFACT_NAMES[handle.name] : undefined;
          const artifact = artifactKind ? { path: childPath, kind: artifactKind, size: 0, files: 0 } : null;
          const [childBytes, childFiles] = await walk(handle, childPath, artifact ?? artifactOwner);
          if (artifact) { artifact.size = childBytes; artifact.files = childFiles; if (childBytes > 0) artifacts.push(artifact); }
          subtreeBytes += childBytes; subtreeFiles += childFiles;
        } else {
          let file: File;
          try { file = await handle.getFile(); } catch { continue; }
          files++; subtreeFiles++;
          bytes += file.size; subtreeBytes += file.size;
          const record = { path: childPath, size: file.size, modified: file.lastModified / 1000 };
          pushTop(largest, record, 50, (a, b) => a.size > b.size);
          if (now - record.modified > OLD_SECONDS) pushTop(oldest, record, 50, (a, b) => a.modified < b.modified);
          const dot = handle.name.lastIndexOf(".");
          const extension = dot > 0 ? handle.name.slice(dot + 1).toLowerCase() : "(none)";
          const stat = extensions.get(extension) ?? { bytes: 0, files: 0 };
          stat.bytes += file.size; stat.files++;
          extensions.set(extension, stat);
          if (file.size >= MIN_DUPLICATE_SIZE && !artifactOwner) {
            const list = bySize.get(file.size) ?? [];
            if (list.length < 50) list.push({ path: childPath, handle });
            bySize.set(file.size, list);
          }
          if (files % 500 === 0) setProgress(`${files.toLocaleString()} files · ${formatBytes(bytes)} · ${childPath}`);
        }
      }
      if (children === 0 && emptyDirectories.length < 300) emptyDirectories.push(path);
      return [subtreeBytes, subtreeFiles];
    }

    try {
      await walk(root, root.name, null);
      setProgress("Comparing files with identical sizes…");
      const duplicates: DuplicateGroup[] = [];
      let hashed = 0;
      const candidates = [...bySize.entries()].filter(([, list]) => list.length > 1).sort((a, b) => b[0] * b[1].length - a[0] * a[1].length);
      for (const [size, list] of candidates) {
        if (cancel.current || hashed + size * list.length > MAX_HASH_BYTES) break;
        const byHash = new Map<string, string[]>();
        for (const item of list) {
          try {
            const hash = await sha256(await item.handle.getFile());
            hashed += size;
            byHash.set(hash, [...(byHash.get(hash) ?? []), item.path]);
          } catch { /* unreadable file */ }
        }
        for (const paths of byHash.values()) if (paths.length > 1) duplicates.push({ size, paths });
      }
      artifacts.sort((a, b) => b.size - a.size);
      setAnalysis({
        root: root.name, files, directories, bytes, truncated: truncated || cancel.current, durationMs: performance.now() - started,
        largest, oldest, emptyDirectories, artifacts: artifacts.slice(0, 100),
        extensions: [...extensions.entries()].map(([extension, stat]) => ({ extension, ...stat })).sort((a, b) => b.bytes - a.bytes).slice(0, 12),
        duplicates: duplicates.sort((a, b) => b.size * (b.paths.length - 1) - a.size * (a.paths.length - 1)).slice(0, 50),
        duplicateBytes: duplicates.reduce((sum, group) => sum + group.size * (group.paths.length - 1), 0),
      });
    } catch (cause) {
      setError(`The folder could not be analyzed: ${String(cause)}`);
    } finally {
      setRunning(false);
      setProgress("");
    }
  }

  return <div className="page">
    <PageHeader title="Folder analyzer"
      description="Pick any folder to find large and old files, duplicates, empty folders and regenerable project artifacts such as node_modules or build output. Read-only; files never leave this computer."
      actions={supported && (running
        ? <button className="secondary" onClick={() => { cancel.current = true; }}><Icon name="stop" size={15} /> Stop</button>
        : <button className="primary" onClick={() => void analyze()}><Icon name="folders" size={15} /> Choose folder…</button>)} />
    {!supported && <Notice tone="warn">This browser does not support the File System Access API. Use a Chromium-based browser (Edge, Chrome) or the desktop app.</Notice>}
    {!connected && supported && <Notice>The browser can only read folders you pick, and Windows application folders are off-limits to it. For ownership analysis of AppData, Program Files and system references, run the desktop app or the local agent.</Notice>}
    {error && <Notice tone="error">{error}</Notice>}
    {running && <div className="progress-line"><span className="spinner" /><span>{progress || "Reading folder…"}</span></div>}
    {!analysis && !running && <Empty icon="analyzer" title="No folder analyzed yet">Good candidates: Downloads, a projects folder, or an old backup drive.</Empty>}
    {analysis && <>
      {analysis.truncated && <Notice tone="warn">The analysis stopped early ({MAX_ENTRIES.toLocaleString()}-entry limit or canceled); results cover only part of the folder.</Notice>}
      <div className="stats">
        <Stat label="Total size" value={formatBytes(analysis.bytes)} hint={`${formatCount(analysis.files, "file")} · ${formatCount(analysis.directories, "folder")}`} />
        <Stat label="Project artifacts" value={formatBytes(analysis.artifacts.reduce((sum, item) => sum + item.size, 0))} hint={formatCount(analysis.artifacts.length, "folder")} />
        <Stat label="Duplicate copies" value={formatBytes(analysis.duplicateBytes)} hint={formatCount(analysis.duplicates.length, "group")} />
        <Stat label="Empty folders" value={analysis.emptyDirectories.length.toLocaleString()} hint={`Analyzed in ${(analysis.durationMs / 1000).toFixed(1)} s`} />
      </div>
      <div className="two-column">
        <Section title="Largest files">
          <ul className="file-list">{analysis.largest.slice(0, 20).map(file => <li key={file.path}><span title={file.path}>{file.path}</span><b>{formatBytes(file.size)}</b></li>)}</ul>
        </Section>
        <Section title="File types">
          <ul className="file-list">{analysis.extensions.map(item => <li key={item.extension}><span>.{item.extension} <small className="muted">{formatCount(item.files, "file")}</small></span><b>{formatBytes(item.bytes)}</b></li>)}</ul>
        </Section>
      </div>
      <Section title="Regenerable project artifacts" description="Dependencies and build output that tools recreate. Check that the project still builds before removing them.">
        {analysis.artifacts.length ? <ul className="file-list">{analysis.artifacts.slice(0, 40).map(item => <li key={item.path}><span title={item.path}>{item.path} <Badge tone="info">{item.kind}</Badge></span><b>{formatBytes(item.size)}</b></li>)}</ul> : <p className="muted">None found.</p>}
      </Section>
      <Section title="Duplicate files" description="Identical content (SHA-256) at different paths, 1 MB and larger. Keep at least one copy.">
        {analysis.duplicates.length ? <ul className="dup-list">{analysis.duplicates.slice(0, 25).map((group, index) => <li key={index}>
          <div><b>{formatBytes(group.size)}</b> × {group.paths.length}</div>
          <ul>{group.paths.map(path => <li key={path} title={path}>{path}</li>)}</ul>
        </li>)}</ul> : <p className="muted">No duplicates found.</p>}
      </Section>
      <div className="two-column">
        <Section title="Oldest files" description="Unchanged for more than a year. Age alone is a reason to look, not to delete.">
          {analysis.oldest.length ? <ul className="file-list">{analysis.oldest.slice(0, 20).map(file => <li key={file.path}><span title={file.path}>{file.path}</span><b>{formatAge(file.modified)}</b></li>)}</ul> : <p className="muted">No files older than a year.</p>}
        </Section>
        <Section title="Empty folders">
          {analysis.emptyDirectories.length ? <ul className="file-list">{analysis.emptyDirectories.slice(0, 30).map(path => <li key={path}><span title={path}>{path}</span></li>)}</ul> : <p className="muted">None.</p>}
        </Section>
      </div>
    </>}
  </div>;
}
