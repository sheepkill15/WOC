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

The agent binds to `127.0.0.1:47653` and accepts browser requests from `http://localhost:1420` and `http://127.0.0.1:1420` by default. Every command is a `POST /api/invoke/{command}` that requires the `X-Orphan-Cleaner-Client: web-v2` header; scan progress streams over `GET /api/events` (SSE). For a separately hosted frontend, set `ORPHAN_CLEANER_ALLOWED_ORIGINS` on the agent to an exact comma-separated origin list and set `VITE_CLEANER_AGENT_URL` when building the frontend. The agent refuses non-loopback bind addresses.

Build the standalone release agent with `npm run agent:build`; the executable is written to `target\release\cleaner-agent.exe`.

Run checks:

```powershell
npm run build
cargo test --workspace
cargo check --workspace --all-targets
```

## What the app does

**Pages.** Overview · Cleanup · Uninstalled apps · All folders · References · Installed apps · Quarantine · Ignore rules · Folder analyzer · Settings. Light, dark and system themes.

**Scan modes** (spec §29)

- *Quick*: AppData (Local, Roaming, LocalLow) and ProgramData, the installed-application inventory, and system references.
- *Deep*: adds Program Files (64- and 32-bit), developer folders in the user profile (`.gradle`, `.m2`, `.cargo`, `.nuget`, `.npm`, `.android`, conda, …) and executable metadata.
- *Post-uninstall check*: when applications disappear from the inventory, re-measures only the folders previously linked to them. Offered on launch and on the Uninstalled apps page. Not saved as a snapshot.

Directories are measured on a small worker pool (at most four threads, to limit disk thrashing) and results stream to the UI while the scan runs. File contents are never read.

**Inventory.** Per-user and machine uninstall registry entries in both registry views, plus current-user MSIX/AppX packages. A missing registry key no longer counts as an incomplete inventory (this used to block saving scans on machines without per-user installs).

**Ownership** (spec §10). Unchanged principles: exact install path, MSIX package family, registered executable, exact normalized names, audited nested vendor/version patterns, reverse-domain identifiers, updater/launcher aliases, and known locations. New:

- Version folders whose registration repeats the publisher (`JetBrains Rider 2024.1` → `JetBrains\Rider2024.1`) now match exactly.
- *Executable metadata*: version resources (ProductName, CompanyName, FileDescription, ProductVersion) are parsed straight from the PE file — never loaded or run. An exact ProductName match links a folder; otherwise a folder with executables and no registration is shown as **Unregistered app** (possibly portable), never as leftovers.
- *Application definitions* (spec §22): built-in YAML definitions (Discord, Slack, VS Code, Teams classic, Spotify, Zoom, Notion, Steam, …) refine content types. Add your own `.yaml` files to the `definitions` folder in the app data directory; the Settings page shows the path and format.
- *Shared components and system locations* (spec §19): Windows-managed folders, shared runtimes and SDKs, anti-cheat components and tool caches carry a location class. System and shared-runtime locations are never offered for cleanup.

**System references** (spec §20, §46). Run/RunOnce keys, Startup folders, Start Menu shortcuts (`.lnk` targets parsed without invoking the shell), Win32 services (including svchost `ServiceDll`), non-Microsoft scheduled tasks, URL protocol handlers, per-user file handlers and App Paths. Each reference records its target and whether it still exists. A live reference into a folder marks it as in use and lowers orphan confidence; a dead reference is weak evidence that software was removed and names the probable former owner. Dead Start Menu/Startup shortcuts can be quarantined; registry entries, services and tasks are listed with their exact location but not edited.

**History** (spec §12–13, §45). Each complete scan is saved in SQLite (ten retained). A folder previously linked to an application that has since disappeared becomes a leftover. A name-only relationship becomes a *probable* leftover when the application's registered install folder has also disappeared. Old version folders become *possible old versions* only after an earlier scan linked them to a strictly older installed version.

**Content classification and safety** (spec §16–17). Each measured folder gets a content profile of its immediate subfolders and loose files: category (cache, logs, crash dumps, shader cache, update/installer cache, configuration, session/account data, plug-ins, mods, save games, projects, documents, media, application files, empty…), size, file count and newest change, plus file-extension totals, executable/database counts and large-file totals. Categories come from folder names, dominant extensions, definitions and known locations. User-data markers anywhere below a subfolder (save-game folders, `.sav`, project and preset files, screenshots, backups) escalate it to **Preserve** unless it is itself a recognized cache.

**Assessment** (spec §15, §34). Kept as separate fields: ownership class (exclusive/shared/system/unknown), orphan confidence (confirmed/very likely/likely/uncertain), deletion safety (safe/likely safe/review/preserve/unknown) and recommended action (clean, clean selected parts, review, keep), each with plain-language reasons. Unknown ownership is never recommended; recent writes and live references lower confidence; age alone is only a reason to look.

**Cleanup** (spec §23–27, §44). Candidates are grouped by what they represent: uninstalled-app leftovers, older version data, possible leftovers, unregistered apps, regenerable caches of installed apps, developer tool caches, and large unknown data (information only). Recommended selections include only safe or likely-safe subfolders, unless the whole folder is regenerable and strongly orphaned. Before anything moves, the plan revalidates every path: it must have been shown in the latest scan, still exist, not be a link or junction, not be a protected Windows or scan-root location, not be the app's own data, and be on the same drive as the quarantine; ownership is re-checked against a freshly read inventory. Warnings (preserve/review content, installed owners, live references) need explicit acknowledgement. Items are moved with a single rename into `%LOCALAPPDATA%\dev.orphancleaner.desktop\Quarantine`, recorded with original path, time, owner and reason, and can be restored or permanently deleted. Retention (default 30 days, or manual) is configurable. Locations that need administrator rights report a clear error instead of elevating.

**Ignore rules** (spec §28). Hide once (until the next scan), always ignore a folder, always keep an application, always keep a type of data (makes that category unselectable and prevents removing folders containing it whole).

**Folder analyzer** (spec §39). Pick any folder in the browser or desktop webview: largest and oldest files, file types, empty folders, regenerable project artifacts (`node_modules`, build output, virtualenvs, caches) and duplicate files confirmed by SHA-256. Read-only.

**Public folder data.** *Update folder data* downloads read-only path hints from the [Ludusavi manifest](https://github.com/mtkennerly/ludusavi-manifest) and [Winapp2](https://github.com/MoscaDotTo/Winapp2), cached locally with ETags. Ludusavi game paths mark data as Preserve; Winapp2 rules only describe possible cache/log paths. Neither source authorizes removal. Ludusavi's repository is MIT-licensed but compiled partly from PCGamingWiki (CC BY-NC-SA); Winapp2 is CC BY-SA 4.0. Review those terms before redistributing a derived catalog.

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
| `src-tauri/src/storage.rs` | SQLite schema v2 (scans, rules, quarantine, actions, settings) |
| `src/` | React UI (`store.tsx` state, `views/` pages) |

## Known limits

- Authenticode signer verification is not implemented; executable metadata comes from the version resource only.
- Registry entries, services and scheduled tasks are reported but never modified.
- Quarantine requires the same drive as the app data folder; other drives are refused rather than copied.
- ProgramData and Program Files items usually need administrator rights to move; the app reports that instead of elevating.
- The browser Folder analyzer cannot see Windows application folders; use the desktop app or the agent for ownership analysis.
