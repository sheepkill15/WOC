# Windows Orphan Cleaner

Early read-only Windows desktop prototype for the [product specification](./Windows%20Orphan%20Cleaner%20%E2%80%94%20Product%20and%20Technical%20Specification.md).

## Run

Requirements: Windows 10/11, Rust, Node.js, npm, and WebView2.

```powershell
npm install
npm run tauri dev
```

Run checks:

```powershell
npm run build
cargo test -p cleaner-core
cargo check -p windows-orphan-cleaner
```

## Current behavior

- Reads per-user and machine uninstall registry entries in 32-bit and 64-bit views, plus current-user MSIX/AppX packages. If MSIX inventory fails, the UI reports it.
- Finds Local, Roaming, LocalLow, and ProgramData through Windows Known Folder APIs, with a reported environment fallback when needed. It inspects children of Local `Packages` and `Programs` separately, recursively measuring each target without reading file contents.
- Skips reparse points, reports inaccessible entries, supports cancellation, and streams results to the UI.
- Links a directory to an installed app by its normalized product name (including common version and architecture suffixes), registered install path, MSIX package family or product name, or an existing executable named by a registry `DisplayIcon` in that directory. Publisher and install-path component matches are shown as **vendor/shared associations** without assigning a single owner or declaring the contents safe or current.
- Recognizes common Windows and development-tool data locations such as WSL, Temp, installer package caches, npm/pnpm/NuGet/Pub/pip, crash dumps, Direct3D cache, and Electron data. They are labeled **Known data**, without implying they are orphaned or safe to remove.
- **Update folder data** explicitly downloads and caches read-only path hints from the [Ludusavi game manifest](https://github.com/mtkennerly/ludusavi-manifest) and [Winapp2](https://github.com/MoscaDotTo/Winapp2). Later scans match concrete game data prefixes and display source-specific evidence; Winapp2 rules only describe possible cache/log paths. Neither source changes an installed-app match into an orphan claim or authorizes removal. The app works offline with its last cached index, or without either download.
- The public index currently covers only the scan's AppData and ProgramData roots. Game paths in Documents, Steam libraries, and other roots are not scanned. PCGamingWiki is the upstream source for much of Ludusavi and its direct Cargo API currently requires bot-password authentication; the app does not call that API.
- Links `Local\TFT` to installed Teamfight Tactics editions through its known folder alias. A publisher match plus the single `Valheim` child links `LocalLow\IronGate` to the installed game. No executable metadata is read from these data folders.
- Shows `Roaming\Image-Line` and `Local\AION2` as **possible** former app data when no matching registration is found. This is a weak first-run inference: launcher-managed or portable installations may still use them.
- Saves each completed four-root scan in a local SQLite database under the Tauri app-local-data directory. The most recent scan loads automatically on launch; **Refresh scan** is optional. A canceled or incomplete scan leaves the previous saved scan intact. Up to ten complete snapshots are retained for later history work.
- Excludes its own app-local-data directory from scans, so the saved database does not inflate results.
- On later scans, reuses an exact saved path-to-app relationship if the application has disappeared from a complete current inventory. Strong previous relationships are shown as **probable leftovers**; name-only relationships remain **possible leftovers**. Neither implies deletion safety.
- Cannot delete, quarantine, or modify discovered resources.

The folder-data panel links to the sources and their terms. Ludusavi's repository is MIT-licensed but says its manifest is compiled partly from PCGamingWiki, whose content is Attribution–NonCommercial–ShareAlike; review those source terms before redistributing a bundled or derived catalog. Winapp2 is CC BY-SA 4.0. This prototype fetches source files only on request and stores a compact local index.

## Planned next work

Broaden historical observations and build an audited validation corpus before making stronger orphan claims. Nested vendor-directory discovery can follow once top-level ownership is reliable. Cleanup remains out of scope until ownership and classification are reliable.
