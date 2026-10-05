import type { CleanupOutcome } from "./types";

export function remainingCleanupSelection(selection: Set<string>, outcome: CleanupOutcome): Set<string> {
  const normalize = (path: string) => path.replace(/\//g, "\\").replace(/\\+$/, "").toLowerCase();
  const moved = outcome.items.filter(item => item.moved).map(item => normalize(item.path));
  return new Set([...selection].filter(path => {
    const normalized = normalize(path);
    return !moved.some(parent => normalized === parent || normalized.startsWith(`${parent}\\`));
  }));
}
