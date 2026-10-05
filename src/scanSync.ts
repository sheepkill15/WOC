import type { DirectoryResult, ScanStatus } from "./types";

export function mergeScanResults(previous: DirectoryResult[], incoming: DirectoryResult[]): DirectoryResult[] {
  const byPath = new Map(previous.map(result => [result.path.toLowerCase(), result]));
  for (const result of incoming) byPath.set(result.path.toLowerCase(), result);
  return [...byPath.values()];
}

export function needsScanSync(remote: ScanStatus, local: ScanStatus): boolean {
  return remote.runId !== local.runId || remote.running !== local.running
    || (remote.running && remote.resultCount !== local.resultCount);
}
