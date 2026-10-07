export type MaintenanceEntry = {
  id: string; name: string; kind: "run" | "run_once" | "app_path" | "startup_folder";
  location: string; command: string; targetPath: string | null;
  targetStatus: "ok" | "missing" | "unresolved";
  startupState: "enabled" | "registered" | "windows_disabled" | "unknown" | "once" | "not_applicable";
  machineWide: boolean; owner: string | null; canDisable: boolean; canClean: boolean; reason: string;
};
export type MaintenanceReport = { token: string; entries: MaintenanceEntry[]; warnings: string[]; capturedAtUnix: number };
export type MaintenanceBackup = { id: number; entry: MaintenanceEntry; action: "disable" | "clean"; status: "pending" | "removed" | "failed" | "restored"; createdAtUnix: number; detail: string };
export type MaintenanceOutcome = { name: string; success: boolean; error: string | null };
export type MaintenanceRow = { entry: MaintenanceEntry; backup?: MaintenanceBackup };

export function maintenanceRows(report: MaintenanceReport | null, backups: MaintenanceBackup[], startup: boolean): MaintenanceRow[] {
  const live = (report?.entries ?? []).filter(entry => startup ? entry.kind !== "app_path" : entry.kind !== "startup_folder");
  const rows: MaintenanceRow[] = live.map(entry => ({ entry }));
  if (startup) {
    const ids = new Set(live.map(entry => entry.id));
    const added = new Set<string>();
    for (const backup of backups) {
      if (backup.action === "disable" && backup.status === "removed" && !ids.has(backup.entry.id) && !added.has(backup.entry.id)) {
        rows.push({ entry: backup.entry, backup }); added.add(backup.entry.id);
      }
    }
  }
  return rows.sort((a, b) => a.entry.name.localeCompare(b.entry.name));
}

export const maintenanceKinds = { run: "At sign-in", run_once: "Once at next sign-in", app_path: "Application path", startup_folder: "Startup folder" };
export function canDisableStartup(entry: MaintenanceEntry): boolean { return entry.canDisable && entry.startupState !== "windows_disabled"; }
export function startupLabel(row: MaintenanceRow): string {
  if (row.backup) return "Disabled here";
  switch (row.entry.startupState) {
    case "windows_disabled": return "Disabled in Windows";
    case "unknown": return "State unknown";
    case "once": return "One time";
    default: return "Enabled";
  }
}
