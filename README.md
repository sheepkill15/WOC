# Windows Orphan Cleaner

Early read-only Windows desktop prototype for the [product specification](./Windows%20Orphan%20Cleaner%20%E2%80%94%20Product%20and%20Technical%20Specification.md).

## Run

Requirements: Windows 10/11, Rust, Node.js, npm, and WebView2.

Desktop app:

```powershell
npm install
npm run tauri dev
```

Browser app, backed by the same Rust scanner:

```powershell
# Terminal 1: loopback-only Windows agent
npm run agent

# Terminal 2: web UI
npm run dev
```

Then open `http://localhost:1420`. The browser UI uses the agent for application inventory, scans, cancellation, saved history, public-data updates, and diagnostics export. The scanner and persistence code are shared with the Tauri app rather than reimplemented in TypeScript.

The agent binds to `127.0.0.1:47653` and accepts browser requests from `http://localhost:1420` and `http://127.0.0.1:1420` by default. For a separately hosted frontend, set `ORPHAN_CLEANER_ALLOWED_ORIGINS` on the agent to an exact comma-separated origin list and set `VITE_CLEANER_AGENT_URL` when building the frontend. The agent refuses non-loopback bind addresses.

Build the standalone release agent with `npm run agent:build`; the executable is written to `target\release\cleaner-agent.exe`.

Run checks:

```powershell
npm run build
cargo test --workspace
cargo check --workspace --all-targets
```

## Ownership validation corpus

`crates/cleaner-core/tests/fixtures/ownership_cases.json` is the reviewed regression corpus for directory ownership. Each case records the observed layout, synthetic installed-application evidence, the expected classification and evidence kinds, plus a rationale for the expectation. It includes positive matches, shared/vendor data, known locations, possible former data, and negative controls that must remain unknown.

The `ownership_corpus` integration test runs every case through the same `classify_directory` entry point used by the live scanner. Add a case whenever a real machine reveals a correct match, false positive, or unresolved pattern; redact usernames and other personal path components before committing it.

## Current behavior

- Reads per-user and machine uninstall registry entries in 32-bit and 64-bit views, plus current-user MSIX/AppX packages. If MSIX inventory fails, the UI reports it.
- Runs the same Rust scan job through either Tauri IPC or a loopback HTTP/SSE agent, so the desktop and browser interfaces have the same local capabilities when their backend is running.
- Finds Local, Roaming, LocalLow, and ProgramData through Windows Known Folder APIs, with a reported environment fallback when needed. It inspects children of Local `Packages` and `Programs` separately, recursively measuring each target without reading file contents. It also reports immediate product directories when they exactly reconstruct a dotted MSIX product namespace (for example, `OpenAI\Codex`) or exactly name a registered product inside its publisher container (for example, `Roland Cloud\ZENOLOGY`). Versioned publisher children remain supported: a matching installed version is linked as active, while a first-seen version mismatch stays **Unknown**. Nested sizes are excluded from the aggregate total to avoid double counting.
- Skips reparse points, reports inaccessible entries, supports cancellation, and streams results to the UI.
- Links a directory to an installed app by its normalized product name (including common version and architecture suffixes), registered install path, MSIX package family or product name, or an existing executable named by a registry `DisplayIcon` in that directory. Publisher and install-path component matches are shown as **vendor/shared associations** without assigning a single owner or declaring the contents safe or current.
- Interprets reverse-domain directory identifiers only for recognized namespace prefixes. An exact complete payload such as `com.splice.INSTRUMENT` can identify an installed product; an exact vendor segment such as `com.adobe.dunamis` is only vendor/shared evidence. Placeholder vendors, partial products, and unrecognized prefixes remain Unknown.
- Recognizes audited updater and launcher-component aliases only when removing the explicit suffix leaves the exact normalized name of an installed product. This covers folders such as `anime-relay-updater`, `riot-client-ux`, `Battle.net_components`, and `ParsecPersistent`; suffixes and publisher-only similarities are not sufficient, and an active-product match is not cleanup approval.
- Recognizes common Windows and development-tool data locations such as WSL, Temp, installer package caches, npm/pnpm/NuGet/Pub/pip, crash dumps, Direct3D cache, and Electron data. Windows-managed ProgramData such as SoftwareDistribution, Update Orchestrator state, Windows Health summaries, machine-wide OpenSSH configuration, and `regid.*` software-identification records is also labeled **Known data** with preservation-oriented explanations. These labels do not imply that anything is orphaned or safe to remove.
- **Update folder data** explicitly downloads and caches read-only path hints from the [Ludusavi game manifest](https://github.com/mtkennerly/ludusavi-manifest) and [Winapp2](https://github.com/MoscaDotTo/Winapp2). Later scans match concrete game data prefixes and display source-specific evidence; Winapp2 rules only describe possible cache/log paths. Neither source changes an installed-app match into an orphan claim or authorizes removal. The app works offline with its last cached index, or without either download.
- The public index currently covers only the scan's AppData and ProgramData roots. Game paths in Documents, Steam libraries, and other roots are not scanned. PCGamingWiki is the upstream source for much of Ludusavi and its direct Cargo API currently requires bot-password authentication; the app does not call that API.
- Links `Local\TFT` to installed Teamfight Tactics editions through its known folder alias. A publisher match plus the single `Valheim` child links `LocalLow\IronGate` to the installed game. No executable metadata is read from these data folders.
- Shows `Roaming\Image-Line` and `Local\AION2` as **possible** former app data when no matching registration is found. This is a weak first-run inference: launcher-managed or portable installations may still use them.
- Saves each completed four-root scan in a local SQLite database under the Tauri app-local-data directory. The most recent scan loads automatically on launch; **Refresh scan** is optional. A canceled or incomplete scan leaves the previous saved scan intact. Up to ten complete snapshots are retained for later history work.
- Excludes its own app-local-data directory from scans, so the saved database does not inflate results.
- On later scans, reuses an exact saved path-to-app relationship if the application has disappeared from a complete current inventory. Strong previous relationships are shown as **probable leftovers**; name-only relationships remain **possible leftovers**. Neither implies deletion safety.
- A nested version-specific directory becomes a **possible old version** only when an earlier complete scan linked that exact path to its then-installed version and the current complete inventory contains a strictly newer version of the same publisher and product family. A version mismatch without that history remains Unknown; downgrades and ambiguous version schemes do not produce a leftover claim.
- Groups historically owned directories by applications that disappeared from retained inventories. The report shows remaining size, contributing directory count, the last installed observation, and whether the disappearance is new since the previous complete scan. Clicking a group opens its largest remaining directory; the feature remains read-only.
- Exports an explicitly requested diagnostics JSON file to Downloads. The UI lists its contents before export; user-profile and app-local-data prefixes are redacted, public-data ETags are omitted, and no file contents or individual filenames are collected. Positively matched nested directory paths are included alongside top-level paths.
- Cannot delete, quarantine, or modify discovered resources.

The folder-data panel links to the sources and their terms. Ludusavi's repository is MIT-licensed but says its manifest is compiled partly from PCGamingWiki, whose content is Attribution–NonCommercial–ShareAlike; review those source terms before redistributing a bundled or derived catalog. Winapp2 is CC BY-SA 4.0. This prototype fetches source files only on request and stores a compact local index.

## Planned next work

Keep growing the validation corpus with audited observations from real machines before making stronger orphan claims. Next, audit remaining shared driver and runtime locations such as Synaptics, ASUS, `boost_interprocess`, and Microsoft DevDiv against installed service and driver evidence, while leaving unresolved vendor folders Unknown. Cleanup remains out of scope until ownership and classification are reliable.
