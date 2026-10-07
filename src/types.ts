export type Application = {
  id: string; name: string; publisher: string | null; version: string | null; installLocation: string | null;
  displayIconExecutable?: string | null; packageFamilyName: string | null; sources: string[];
};
export type Inventory = { applications: Application[]; warnings: string[] };
export type FolderLink = { path: string; application: Application };
export type UninstallReview = { token: string; plan: { application: Application; executable: string; arguments: string; source: string; folders: string[]; excludedFolders: string[] } };
export type Evidence = { kind: string; description: string; strength: string };
export type Safety = "safe" | "likely_safe" | "review" | "preserve" | "unknown";
export type ContentItem = {
  name: string; isDirectory: boolean; kind: string; safety: Safety; sizeBytes: number; fileCount: number;
  newestModifiedUnix?: number | null; reason: string; source: string;
};
export type ExtensionStat = { extension: string; sizeBytes: number; fileCount: number };
export type ContentProfile = {
  items: ContentItem[]; extensions: ExtensionStat[]; executableCount: number; databaseCount: number;
  largeFileCount: number; largeFileBytes: number; untrackedChildren?: number; categories?: string[];
};
export type ExecutableInfo = { fileName: string; sizeBytes: number; companyName?: string | null; productName?: string | null; fileDescription?: string | null; productVersion?: string | null };
export type Reason = { tone: "positive" | "negative" | "neutral"; text: string };
export type Assessment = {
  orphanConfidence: string; deletionSafety: Safety; ownershipClass: string; recommendedAction: string;
  reclaimableBytes: number; retainedBytes: number; reasons: Reason[];
};
export type DirectoryResult = {
  path: string; root: string; parentPath?: string | null; sizeBytes: number; fileCount: number; directoryCount: number;
  newestModifiedUnix: number | null; oldestModifiedUnix?: number | null; createdUnix?: number | null; skippedEntries: number;
  owner: Application | null; ownerHint?: string | null; ownership: string; orphanStatus: string; evidence: Evidence[];
  locationClass?: string | null; content?: ContentProfile; executables?: ExecutableInfo[]; assessment?: Assessment;
};
export type ScanSummary = {
  mode?: string; complete?: boolean; startedAtUnix?: number; durationMs?: number;
  directories: number; bytes: number; skippedEntries: number; canceled: boolean; scannedRoots: string[]; warnings: string[];
};
export type SystemReference = {
  id: string; kind: string; name: string; location: string; command: string; targetPath?: string | null;
  status: "ok" | "dead" | "unresolved"; owner?: Application | null; fileBacked: boolean; machineWide: boolean;
};
export type ReferenceInventory = { references: SystemReference[]; warnings: string[] };
export type SavedScan = { capturedAtUnix: number; inventory: Inventory; summary: ScanSummary; results: DirectoryResult[]; references?: ReferenceInventory };
export type ScanFinishedEvent = { summary: ScanSummary; savedAtUnix: number | null; saveError: string | null };
export type ScanStatus = { runId: number; running: boolean; resultCount: number };
export type ScanState = Omit<ScanStatus, "resultCount"> & { mode: "quick" | "deep" | null; inventory: Inventory | null; references: ReferenceInventory | null; results: DirectoryResult[]; progressPath: string; finished: ScanFinishedEvent | null };
export type PublicDataStatus = { updatedAtUnix: number | null; gameDirectories: number; cleanerDirectories: number; warnings: string[] };
export type HistoricalDirectory = { path: string; root: string; sizeBytes: number; orphanStatus: string };
export type HistoricalApplication = {
  application: Application; lastSeenAtUnix: number | null; firstMissingAtUnix: number | null;
  newlyMissing: boolean; remainingBytes: number; confidence: "probable" | "possible"; directories: HistoricalDirectory[];
};
export type HistoryReport = { completeScans: number; currentScanAtUnix: number | null; applications: HistoricalApplication[] };
export type RemovedApplication = { application: Application; remainingBytes: number; directories: HistoricalDirectory[] };
export type RemovedReport = { baselineScanAtUnix: number | null; applications: RemovedApplication[]; warnings: string[] };
export type PostUninstallReport = { removed: RemovedReport; results: DirectoryResult[]; summary: ScanSummary };
export type DiagnosticsExport = { path: string; scans: number; directories: number };
export type ContentSelection = { name: string; path: string; kind: string; safety: Safety; sizeBytes: number; selectable: boolean; defaultSelected: boolean; reason: string };
export type CandidateItem = {
  path: string; root: string; sizeBytes: number; newestModifiedUnix: number | null; orphanConfidence: string; deletionSafety: Safety;
  recommendedAction: string; selectableWhole: boolean; defaultSelected: boolean; content: ContentSelection[];
};
export type CandidateGroup = {
  id: string; kind: string; title: string; summary: string; ownerName: string | null; ownerKey: string | null;
  confidence: string; safety: Safety; recommendedAction: string; totalBytes: number; reclaimableBytes: number; retainedBytes: number;
  priority: "high" | "review" | "info"; items: CandidateItem[]; reasons: Reason[]; ignoredBy: string | null;
};
export type CandidateReport = {
  scanAtUnix: number | null; groups: CandidateGroup[]; ignoredGroups: CandidateGroup[]; recommendedBytes: number; reviewBytes: number;
  ignoredPaths: number; quarantinedPaths: number;
};
export type IgnoreRule = { id: number; kind: "path" | "application" | "category" | "once"; value: string; label: string; createdAtUnix: number; scanAtUnix?: number | null };
export type PlanItem = { path: string; itemKind: string; sizeBytes: number; fileCount: number; status: "ready" | "warning" | "blocked" | "redundant"; messages: string[]; owner: string | null; safety: string; reason: string; newestModifiedUnix: number | null; quarantineDirectory: string };
export type CleanupPlan = { items: PlanItem[]; totalBytes: number; readyCount: number; warningCount: number; blockedCount: number; quarantineDirectory: string; scanAtUnix: number | null; manualCleanup: boolean; planToken: string };
export type ExecutedItem = { path: string; moved: boolean; message: string; quarantineId: number | null; sizeBytes: number };
export type CleanupOutcome = { items: ExecutedItem[]; movedCount: number; movedBytes: number; failedCount: number };
export type QuarantineItem = {
  id: number; originalPath: string; quarantinePath: string; sizeBytes: number; fileCount: number; createdAtUnix: number;
  owner: string | null; reason: string; itemKind: string; status: string; updatedAtUnix: number;
};
export type QuarantineReport = { items: QuarantineItem[]; history: QuarantineItem[]; totalBytes: number; retentionDays: number; quarantineDirectory: string; expiredPurged: number };
export type Settings = { quarantineRetentionDays: number; defaultScanMode: "quick" | "deep"; checkRemovedOnLaunch: boolean };
export type AppInfo = { version: string; backend: string; running: boolean; dataDirectory: string; quarantineDirectory: string; definitionsDirectory: string; logFile: string };
export type DefinitionsStatus = { directory: string; builtIn: number; user: number; warnings: string[]; products: { id: string; product: string; source: string; paths: number }[] };
