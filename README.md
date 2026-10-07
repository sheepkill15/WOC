# Windows Orphan Cleaner

Ownership-aware cleanup for Windows 10/11, built from the [product specification](./Windows%20Orphan%20Cleaner%20%E2%80%94%20Product%20and%20Technical%20Specification.md). It links application data to installed software, remembers what it saw, explains every conclusion, and only moves data after you review it. Nothing is deleted directly: cleanup goes to a quarantine you can restore from.

## Run

Requirements: Windows 10/11, Rust, Node.js, npm, and WebView2.

Desktop app:

```powershell
npm install
npm run tauri dev
```

Browser app, backed by the same Rust engine:

```powershell
# Terminal 1: loopback-only Windows agent
npm run agent

# Terminal 2: web UI
npm run dev
```

Then open `http://localhost:1420`. The browser UI and the desktop shell call the same command dispatcher (`src-tauri/src/service.rs`), so both have identical capabilities. The **Folder analyzer** page also works without any backend, using the browser's File System Access API.

The agent binds to `127.0.0.1:47653` and accepts browser requests from `http://localhost:1420` and `http://127.0.0.1:1420` by default. Every command is a `POST /api/invoke/{command}` that requires the `X-Orphan-Cleaner-Client: web-v3` header; scan progress streams over `GET /api/events` (SSE). Transport version 3 adds scan snapshots and reviewed cleanup tokens; rebuild the agent and frontend together. The UI reconciles `scan_status` with `scan_state` after reconnects, dropped events and scan completion, so it can recover without a page reload. For a separately hosted frontend, set `ORPHAN_CLEANER_ALLOWED_ORIGINS` on the agent to an exact comma-separated origin list and set `VITE_CLEANER_AGENT_URL` when building the frontend. The agent refuses non-loopback bind addresses. For isolated testing, `ORPHAN_CLEANER_DATA_DIR` sets an absolute local agent data folder.

Build the standalone release agent with `npm run agent:build`; the executable is written to `target\release\cleaner-agent.exe`.

Run checks:

```powershell
npm run build
npm test
cargo test --workspace
cargo check --workspace --all-targets
```

## What the app does

**Main views.** **Applications** is the default view: each installed application has a measured total and an expandable list of all detected folders. Nested folders count once; separately detected folders of other owners are excluded from the total. **Stray folders** collects folders without a current installed owner, including former-app data with a badge and an explanation of its previous owner. Unknown, shared and Windows-managed data retain their safety labels. Overview, Cleanup, References, Quarantine, Ignore rules, Folder analyzer and Settings remain supporting tools. Light, dark and system themes.

**Manual connections.** Open a folder and choose **Connect to application**, or use **Connect** beside an application's folder. Exact folder links persist in SQLite and apply immediately and on future scans. Removing a manual connection restores the scanner's detected relationship. If the connected app disappears from a complete inventory, its data becomes former-app data. Connections change ownership evidence, never content preservation rules.

**Whole-application uninstall.** Expand an application and choose **Uninstall and remove folders**. Review its Windows registry uninstaller, or a unique direct `uninstall.exe` / `unins*.exe` in its registered installation folder. MSI maintenance commands use `/X`; MSIX apps use Windows package removal. Run the uninstaller, finish its prompts, then check remaining folders. The backend verifies that the app is absent before planning and again before executing cleanup. Remaining exclusive folders move to the existing quarantine after review; shared/system folders and parents containing unrelated detected data are excluded. Installation files not covered by an older scan are also checked. Canceling an uninstaller or an incomplete inventory prevents this cleanup. Some installers require administrator approval, and moving protected folders may still fail for permissions. Restoring quarantined folders does not reinstall the application.

**Startup items.** Read the current-user and all-users Run / RunOnce registry entries and resolved Windows Startup folders without running their commands. Entries show their source, target, associated application when known, and Windows startup status when available. Review a disable action to save the exact registry value type/bytes or ordinary startup file (up to 1 MB) in SQLite before removing it from its startup location. Disabled entries remain listed and can be restored after restarting the app. Separate Windows disable settings are preserved; Windows Startup settings handles packaged apps and other startup mechanisms. RunOnce entries may be installation work, and restoring them may run the command at the next sign-in. Administrator permissions may be required for all-users entries.

**Registry cleaner.** A separate fresh check of Run, RunOnce and App Paths identifies exact missing executable targets on available fixed local drives. Ambiguous unquoted commands, relative targets, inaccessible paths, links, network/removable drives and Windows targets are excluded from cleanup. Review selected values, save their exact contents in SQLite, then remove only those values; keys, siblings, services, COM registrations and file associations remain intact. Values and target existence are checked again before each removal. Startup files are disabled through Startup items, not registry cleanup. This does not promise a performance improvement or a large disk-space saving.

**Startup/registry backups.** Schema v5 records a durable pending backup before changing Windows and retains it separately from folder quarantine, without automatic expiry. The Backups tab offers recovery after interruption as well as normal restoration. Restore rejects different existing values/files; it does not recreate registry keys that an uninstaller has removed. Startup file changes lock the file and its parent directories against replacement and refuse junctions/reparse points. Only disposable test entries/files are changed by validation.

**Scan modes** (spec §29)

- *Quick*: AppData (Local, Roaming, LocalLow), ProgramData, the user's Downloads, Public files, other `Downloads` folders found at the root or one level below the root of fixed drives, and exact registered installation folders, plus the installed-application inventory and system references. It may take longer when installations or Downloads contain many files.
- *Deep*: adds Program Files folders on fixed drives, all top-level user-profile folders except AppData (already covered), Documents, Desktop, Pictures, Music, Videos and Saved Games (including redirected Known Folders), top-level `Temp` folders on fixed drives, and exact registered install folders not already covered by another root, plus executable metadata. Loose files in the profile root and redirected-folder containers are included. Personal folders are never recommended for cleanup; you can still remove them through explicit manual cleanup. Fixed-drive discovery skips removable and network drives.
- *Post-uninstall check*: when applications disappear from the inventory, re-measures only the folders previously linked to them. Offered on launch and on the Uninstalled apps page. Not saved as a snapshot.

Directories are measured on a small worker pool (at most four threads, to limit disk thrashing) and results stream to the UI while the scan runs. Folder measurement does not read file contents. Startup management reads supported startup files to make exact restorable backups.

**Inventory.** Per-user and machine uninstall registry entries in both registry views, plus current-user MSIX/AppX packages. A missing registry key no longer counts as an incomplete inventory (this used to block saving scans on machines without per-user installs).

**Ownership** (spec §10). Unchanged principles: exact install path, MSIX package family, registered executable, exact normalized names, audited nested vendor/version patterns, reverse-domain identifiers, updater/launcher aliases, and known locations. New:

- Version folders whose registration repeats the publisher (`JetBrains Rider 2024.1` → `JetBrains\Rider2024.1`) now match exactly.
- *Executable metadata*: version resources (ProductName, CompanyName, FileDescription, ProductVersion) are parsed straight from the PE file — never loaded or run. An exact ProductName match links a folder; otherwise a folder with executables and no registration is shown as **Unregistered app** (possibly portable), never as leftovers.
- *Application definitions* (spec §22): built-in YAML definitions (Discord, Slack, VS Code, Teams classic, Spotify, Zoom, Notion, Steam, …) refine content types. Add your own `.yaml` files to the `definitions` folder in the app data directory; the Settings page shows the path and format.
- *Shared components and system locations* (spec §19): Windows-managed folders, shared runtimes and SDKs, anti-cheat components and tool caches carry a location class. System and shared-runtime locations are not recommended for cleanup; manual cleanup displays the risks and allows an explicit override.

**System references** (spec §20, §46). Run/RunOnce keys, Startup folders, Start Menu shortcuts (`.lnk` targets parsed without invoking the shell), Win32 services (including svchost `ServiceDll`), non-Microsoft scheduled tasks, URL protocol handlers, per-user file handlers and App Paths. Each reference records its target and whether it still exists. A live reference into a folder marks it as in use and lowers orphan confidence; a dead reference is weak evidence that software was removed and names the probable former owner. Dead Start Menu/Startup shortcuts can be quarantined; registry entries, services and tasks are listed with their exact location but not edited.

**History** (spec §12–13, §45). Each complete scan is saved in SQLite (ten retained). A folder previously linked to an application that has since disappeared becomes a leftover. A name-only relationship becomes a *probable* leftover when the application's registered install folder has also disappeared. Old version folders become *possible old versions* only after an earlier scan linked them to a strictly older installed version.

**Content classification and safety** (spec §16–17). Each measured folder gets a content profile of its immediate subfolders and loose files: category (cache, logs, crash dumps, shader cache, update/installer cache, configuration, session/account data, plug-ins, mods, save games, projects, documents, media, application files, empty…), size, file count and newest change, plus file-extension totals, executable/database counts and large-file totals. Categories come from folder names, dominant extensions, definitions and known locations. User-data markers anywhere below a subfolder (save-game folders, `.sav`, project and preset files, screenshots, backups) escalate it to **Preserve**, including recognized caches containing saves or projects. Ordinary cached images remain regenerable. Category keep rules also cover contents hidden by display grouping or the subfolder reporting limit; skipped entries prevent a whole-folder safe recommendation.

**Assessment** (spec §15, §34). Kept as separate fields: ownership class (exclusive/shared/system/unknown), orphan confidence (confirmed/very likely/likely/uncertain), deletion safety (safe/likely safe/review/preserve/unknown) and recommended action (clean, clean selected parts, review, keep), each with plain-language reasons. Unknown ownership is never recommended; recent writes and live references lower confidence; age alone is only a reason to look.

**Cleanup** (spec §23–27, §44). Candidates are grouped by what they represent: uninstalled-app leftovers, older version data, possible leftovers, unregistered apps, regenerable caches of installed apps, developer tool caches, and large unknown data (information only). Recommended selections include only safe or likely-safe subfolders, unless the whole folder is regenerable and strongly orphaned. Planning and execution remeasure current contents, check keep rules and re-read the application inventory, including ownership of selected subfolders. If the reviewed plan changes, execution requires a new review and moves nothing.

**Manual cleanup.** Use **Quarantine folder** in Folder Details or enter a full file or folder path on Cleanup, even without a saved scan. Manual mode allows personal folders, installed applications, system-managed data, unscanned paths and items protected by keep rules. The plan displays the risks, requires acknowledgement and overrides rules for that operation only. Recommendations remain conservative. Drive roots, network/device paths, ambiguous paths, links/junctions and paths inside or containing the cleaner's own data or quarantine remain unsupported.

Items move with a single rename into a quarantine on their source volume: `%LOCALAPPDATA%\dev.orphancleaner.desktop\Quarantine` on the app-data drive, or `<drive>:\OrphanCleanerQuarantine\<app-data-identity>` on another drive. The review shows each destination. Each item is recorded with its original path, time, owner and reason, and can be restored or permanently deleted. Cleanup, restore and purge check all parent components and hold directory handles against replacement by junctions. Cleaned paths stay excluded from stale scan candidates after purge; restoring clears the exclusion, and a new scan refreshes it. Retention (default 30 days, or manual) is configurable. Locations that need administrator rights report a clear error instead of elevating.

**Ignore rules** (spec §28). Hide once (until the next scan), always ignore a folder, always keep an application, always keep a type of data. Rules apply to both candidates and backend cleanup validation, including a selected ancestor containing kept data. Explicit manual cleanup can override them after review, without removing the rules.

**Folder analyzer** (spec §39). Pick any folder in the browser or desktop webview: largest and oldest files, file types, empty folders, regenerable project artifacts (`node_modules`, build output, virtualenvs, caches) and duplicate files confirmed by SHA-256. Read-only.

**Public folder data.** Every scan automatically checks the [Ludusavi manifest](https://github.com/mtkennerly/ludusavi-manifest) and [Winapp2](https://github.com/MoscaDotTo/Winapp2) for updated path hints, using cached ETags. Download failures retain the last cache and add warnings without preventing an offline scan. Settings also offers *Update folder data*. Ludusavi game paths mark data as Preserve; Winapp2 rules only describe possible cache/log paths. Neither source authorizes removal. Ludusavi's repository is MIT-licensed but compiled partly from PCGamingWiki (CC BY-NC-SA); Winapp2 is CC BY-SA 4.0. Review those terms before redistributing a derived catalog.

**Diagnostics and logging** (spec §41). A rotating log (`logs\cleaner.log`, user-profile paths redacted) records scans and every quarantine, restore and purge. *Export diagnostics* writes a JSON file to Downloads with the retained scans, references, public-data status and recent log lines; profile and app-data prefixes are redacted and executable file names removed. The Settings page lists exactly what it contains.

**Privacy.** Everything runs locally. Nothing about files or applications is uploaded, and no AI model takes part in any decision.

## Ownership validation corpus

`crates/cleaner-core/tests/fixtures/ownership_cases.json` is the reviewed regression corpus for directory ownership. Each case records the observed layout, synthetic installed-application evidence, the expected classification and evidence kinds, plus a rationale. It includes positive matches, shared/vendor data, known locations, possible former data, and negative controls that must remain unknown.

The `ownership_corpus` integration test runs every case through the same `classify_directory` entry point used by the live scanner. Add a case whenever a real machine reveals a correct match, false positive, or unresolved pattern; redact usernames and other personal path components before committing it.

## Code map

| Path | Role |
| --- | --- |
| `crates/cleaner-core/src/lib.rs` | Inventory, ownership resolution, history, scan roots, parallel measurement |
| `crates/cleaner-core/src/content.rs` | Content categories and safety classes |
| `crates/cleaner-core/src/assessment.rs` | Orphan confidence, safety, ownership class, recommendation, reasons |
| `crates/cleaner-core/src/references.rs` | Startup, services, tasks, shortcuts, handlers; `.lnk` parsing |
| `crates/cleaner-core/src/executables.rs` | PE version-resource parser (no loading) |
| `crates/cleaner-core/src/definitions.rs`, `definitions.yaml` | Application definitions |
| `src-tauri/src/service.rs` | Command dispatcher shared by Tauri and the agent |
| `src-tauri/src/scan_job.rs` | Scan pipeline, removed-app detection, post-uninstall check |
| `src-tauri/src/candidates.rs` | Candidate grouping and ignore rules |
| `src-tauri/src/cleanup.rs` | Cleanup plans, quarantine, restore, purge, retention |
| `src-tauri/src/storage.rs` | SQLite schema v5 (scans, folder connections, rules, quarantine, cleanup exclusions, startup/registry backups, actions, settings) |
| `src-tauri/src/maintenance.rs` | Reviewed startup management, missing registry targets, durable backups and restore |
| `src-tauri/src/folder_links.rs`, `src-tauri/src/uninstall.rs` | Persistent ownership connections and reviewed uninstall workflow |
| `src/` | React UI (`store.tsx` state, `views/` pages) |

## Known limits

- Authenticode signer verification is not implemented; executable metadata comes from the version resource only.
- Startup Run/RunOnce and Startup-folder entries can be disabled/restored. Registry cleanup is limited to missing Run/RunOnce and App Paths values; services, scheduled tasks, COM and file associations remain review-only.
- Quarantine uses the source drive; the app must be able to create its managed quarantine directory there.
- ProgramData and Program Files items usually need administrator rights to move; the app reports that instead of elevating.
- The browser Folder analyzer cannot see Windows application folders; use the desktop app or the agent for ownership analysis.
