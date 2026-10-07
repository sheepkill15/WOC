import type { Application, DirectoryResult } from "./types";

export function pathKey(path: string): string { return path.replaceAll("/", "\\").replace(/\\+$/, "").toLowerCase(); }
export function within(path: string, parent: string): boolean { const key = pathKey(path); const root = pathKey(parent); return key === root || key.startsWith(`${root}\\`); }
export function sameApp(left: Application, right: Application): boolean {
  return left.id.toLowerCase() === right.id.toLowerCase()
    || Boolean(left.packageFamilyName && right.packageFamilyName && left.packageFamilyName.toLowerCase() === right.packageFamilyName.toLowerCase())
    || left.name.toLowerCase().replace(/[^\p{L}\p{N}]/gu, "") === right.name.toLowerCase().replace(/[^\p{L}\p{N}]/gu, "");
}

/** Count a path union; parentPath describes scan display structure, not ownership. */
export function folderBytes(folders: DirectoryResult[]): number {
  return folders.filter(folder => !folders.some(parent => pathKey(folder.path) !== pathKey(parent.path) && within(folder.path, parent.path)))
    .reduce((sum, folder) => sum + folder.sizeBytes, 0);
}

export function applicationCatalog(apps: Application[], results: DirectoryResult[]) {
  const unique = [...new Map(results.map(result => [pathKey(result.path), result])).values()];
  const entries = [...new Map(apps.map(app => [app.id.toLowerCase(), app])).values()].map(application => ({ application, folders: [] as DirectoryResult[], bytes: 0 }));
  const stray: DirectoryResult[] = [];
  for (const folder of unique) {
    const entry = folder.owner && !["probable_orphan", "possibly_orphaned"].includes(folder.orphanStatus) && folder.ownership !== "shared"
      ? entries.find(entry => sameApp(entry.application, folder.owner!)) : undefined;
    if (entry) entry.folders.push(folder); else stray.push(folder);
  }
  for (const entry of entries) {
    // A linked parent may contain independently detected folders of another owner.
    entry.bytes = entry.folders.reduce((sum, folder) => {
      const descendants = unique.filter(child => pathKey(child.path) !== pathKey(folder.path) && within(child.path, folder.path));
      return sum + Math.max(0, folder.sizeBytes - folderBytes(descendants));
    }, 0);
    entry.folders.sort((a, b) => b.sizeBytes - a.sizeBytes);
  }
  return { entries, stray };
}

export function formerOwnerText(folder: DirectoryResult): string | null {
  if (folder.owner && ["probable_orphan", "possibly_orphaned"].includes(folder.orphanStatus)) {
    return `This used to belong to ${folder.owner.name}. ${folder.orphanStatus === "probable_orphan" ? "It probably can be removed; review its contents first." : "It may be leftover data; review its contents first."}`;
  }
  if (folder.orphanStatus === "possibly_orphaned" && folder.ownerHint) return `This may have belonged to ${folder.ownerHint}. Review its contents before removal.`;
  return null;
}

export function resultsAfterCleanup(results: DirectoryResult[], moved: { path: string; sizeBytes: number; moved: boolean }[]): DirectoryResult[] {
  const paths = moved.filter(item => item.moved);
  const roots = paths.filter(item => !paths.some(parent => pathKey(item.path) !== pathKey(parent.path) && within(item.path, parent.path)));
  return results.filter(folder => !roots.some(item => within(folder.path, item.path))).map(folder => {
    const removedBytes = roots.filter(item => within(item.path, folder.path)).reduce((sum, item) => sum + item.sizeBytes, 0);
    return removedBytes ? { ...folder, sizeBytes: Math.max(0, folder.sizeBytes - removedBytes) } : folder;
  });
}
