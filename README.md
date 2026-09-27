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
- Links a directory to an installed app only by exact normalized product name, registered install path, or MSIX package family name. Everything else remains **unknown**.
- Saves each completed four-root scan in a local SQLite database under the Tauri app-local-data directory. The most recent scan loads automatically on launch; **Refresh scan** is optional. A canceled or incomplete scan leaves the previous saved scan intact. Up to ten complete snapshots are retained for later history work.
- Excludes its own app-local-data directory from scans, so the saved database does not inflate results.
- On later scans, reuses an exact saved path-to-app relationship if the application has disappeared from a complete current inventory. Strong previous relationships are shown as **probable leftovers**; name-only relationships remain **possible leftovers**. Neither implies deletion safety.
- Cannot delete, quarantine, or modify discovered resources.

## Planned next work

Add richer active-application evidence, nested vendor-directory discovery, historical observations, and an audited validation corpus before making orphan claims. Cleanup remains out of scope until ownership and classification are reliable.
