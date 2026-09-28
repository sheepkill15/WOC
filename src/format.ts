import type { DirectoryResult, Safety } from "./types";

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes;
  let index = -1;
  do { value /= 1024; index++; } while (value >= 1024 && index < units.length - 1);
  return `${value.toFixed(value >= 100 ? 0 : value >= 10 ? 1 : 2)} ${units[index]}`;
}

export function formatCount(value: number, singular: string, plural = `${singular}s`): string {
  return `${value.toLocaleString()} ${value === 1 ? singular : plural}`;
}

export function formatDate(unix: number | null | undefined): string {
  if (!unix) return "—";
  return new Date(unix * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function formatAge(unix: number | null | undefined): string {
  if (!unix) return "unknown";
  const seconds = Date.now() / 1000 - unix;
  if (seconds < 90) return "just now";
  const minutes = seconds / 60;
  if (minutes < 60) return `${Math.round(minutes)} min ago`;
  const hours = minutes / 60;
  if (hours < 36) return `${Math.round(hours)} h ago`;
  const days = hours / 24;
  if (days < 60) return `${Math.round(days)} days ago`;
  const months = days / 30.4;
  if (months < 24) return `${Math.round(months)} months ago`;
  return `${(days / 365).toFixed(1)} years ago`;
}

export function formatDuration(ms: number | undefined): string {
  if (!ms) return "";
  if (ms < 1000) return `${ms} ms`;
  const seconds = ms / 1000;
  return seconds < 90 ? `${seconds.toFixed(1)} s` : `${Math.round(seconds / 60)} min`;
}

export function baseName(path: string): string {
  const parts = path.split("\\").filter(Boolean);
  return parts[parts.length - 1] ?? path;
}

export function shortPath(path: string): string {
  return path.split("\\").filter(Boolean).slice(-2).join("\\");
}

export const rootLabels: Record<string, string> = {
  Local: "AppData\\Local", Roaming: "AppData\\Roaming", LocalLow: "AppData\\LocalLow", ProgramData: "ProgramData",
  ProgramFiles: "Program Files", ProgramFilesX86: "Program Files (x86)", UserProfile: "User profile",
  Documents: "Documents", Downloads: "Downloads", Desktop: "Desktop", Pictures: "Pictures",
  Music: "Music", Videos: "Videos", SavedGames: "Saved Games",
  Public: "Public files", OtherDownloads: "Other Downloads", OtherTemp: "Other temp", RegisteredInstall: "Registered install",
};

export function ownerLabel(result: DirectoryResult): string {
  if (result.orphanStatus === "user_files" && !result.owner) return "Personal files";
  return result.owner?.name ?? result.ownerHint ?? (result.ownership === "shared" ? baseName(result.path) : "Unresolved");
}

export type Tone = "good" | "info" | "warn" | "danger" | "muted" | "accent";

export function statusBadge(result: DirectoryResult): { label: string; tone: Tone; group: StatusGroup } {
  if (result.orphanStatus === "user_files") return { label: "Personal files", tone: "info", group: "known" };
  if (result.orphanStatus === "probable_orphan") return { label: "Probable leftover", tone: "warn", group: "former" };
  if (result.evidence.some(item => item.kind === "newer_product_version_installed")) return { label: "Old version", tone: "warn", group: "former" };
  if (result.orphanStatus === "possibly_orphaned") return { label: "Possible leftover", tone: "warn", group: "former" };
  if (result.orphanStatus === "unregistered_application") return { label: "Unregistered app", tone: "accent", group: "unregistered" };
  if (result.orphanStatus === "referenced_by_system") return { label: "In use by system", tone: "good", group: "matched" };
  if (result.orphanStatus === "associated_with_installed") return { label: "Vendor / shared", tone: "good", group: "matched" };
  if (result.orphanStatus === "not_orphaned") return { label: "Installed app", tone: "good", group: "matched" };
  if (result.locationClass === "system") return { label: "Windows", tone: "info", group: "known" };
  if (result.locationClass === "shared_runtime") return { label: "Shared runtime", tone: "info", group: "known" };
  if (result.orphanStatus === "known_application_data") return { label: "Known data", tone: "info", group: "known" };
  return { label: "Unknown", tone: "muted", group: "unknown" };
}

export type StatusGroup = "matched" | "known" | "former" | "unregistered" | "unknown";

export const safetyLabels: Record<string, string> = {
  safe: "Safe", likely_safe: "Likely safe", review: "Review", preserve: "Preserve", unknown: "Unknown",
};

export function safetyTone(safety: Safety | string | undefined): Tone {
  switch (safety) {
    case "safe": return "good";
    case "likely_safe": return "good";
    case "review": return "warn";
    case "preserve": return "danger";
    default: return "muted";
  }
}

export const confidenceLabels: Record<string, string> = {
  confirmed: "Confirmed", very_likely: "Very likely", likely: "Likely", uncertain: "Uncertain",
  not_orphaned: "In use", unknown: "Unknown",
};

export function confidenceTone(confidence: string | undefined): Tone {
  switch (confidence) {
    case "confirmed": case "very_likely": return "warn";
    case "likely": return "accent";
    case "uncertain": return "muted";
    case "not_orphaned": return "good";
    default: return "muted";
  }
}

export const actionLabels: Record<string, string> = {
  clean: "Recommended", clean_selected: "Clean selected parts", review: "Review", keep: "Keep",
};

export const kindLabels: Record<string, string> = {
  cache: "Cache", temporary: "Temporary", log: "Logs", crash_dump: "Crash dumps", update_cache: "Update cache",
  installer_cache: "Installer cache", shader_cache: "Shader cache", thumbnail_cache: "Thumbnails",
  downloaded_asset: "Downloads", generated_data: "Generated", configuration: "Configuration",
  application_state: "App state", session_data: "Session", account_data: "Account", plugin: "Plugins",
  mod: "Mods", save_game: "Save games", database: "Database", project: "Projects", document: "Documents",
  media: "Media", application_binaries: "App files", empty: "Empty", unknown: "Unclassified",
};

export const referenceKindLabels: Record<string, string> = {
  startup_run: "Startup entry", startup_folder: "Startup shortcut", start_menu_shortcut: "Start Menu shortcut",
  service: "Service", scheduled_task: "Scheduled task", url_protocol: "URL protocol", file_handler: "File handler",
  app_path: "App path",
};

export const evidenceStrengthOrder: Record<string, number> = { strong: 0, medium: 1, weak: 2 };

export const categoryOptions = [
  "save_game", "project", "document", "media", "mod", "configuration", "account_data", "plugin", "database", "session_data", "application_state",
];
