# Windows Orphan Cleaner

## 1. Product Summary

Build a free, transparent Windows cleanup application focused primarily on detecting **orphaned application data**: files, folders, configuration, caches, logs, update remnants, abandoned services, scheduled tasks, startup entries, shortcuts, and other artifacts that belonged to software which is no longer installed or no longer uses them.

Most existing cleaner applications focus on predefined temporary-file locations such as browser caches, `%TEMP%`, log directories, and Windows temporary data. This application should focus on a harder and often more valuable problem:

> Identify data that was once legitimate but has become unnecessary because the application, version, component, account, or installation that created it no longer exists.

The application must not make aggressive deletion decisions when ownership or safety is uncertain.

Instead, it should:

1. Discover potentially unnecessary data.
2. Determine its probable owner.
3. Determine whether that owner still exists.
4. Determine what kind of data it contains.
5. Gather evidence supporting the conclusion.
6. Assign confidence and safety levels.
7. Present ambiguous findings clearly to the user.
8. Let the user decide what to remove.
9. Automatically recommend deletion only for cases where the evidence is strong.

The software should prioritize **accuracy, transparency, and user control** rather than maximizing the amount of reported junk.

---

# 2. Core Philosophy

The program should not behave like traditional "PC cleaner" applications that show alarming numbers of "errors" or classify everything unknown as junk.

Its central principle should be:

> Unknown does not mean unnecessary.

And:

> Orphaned does not necessarily mean safe to delete.

For example:

```text
AppData\Roaming\OldGame
```

may belong to a game that has been uninstalled.

That makes it an orphan.

However, it could contain:

```text
savegames
mods
screenshots
configuration
```

Therefore the program should distinguish between:

```text
Ownership confidence
```

and:

```text
Deletion safety
```

These are separate measurements.

A directory can have:

```text
Owner: OldGame
Owner confidence: 99%
Application installed: No
Orphan confidence: 99%
Deletion safety: Low
```

because it contains user-created or potentially valuable data.

---

# 3. Primary Product Goal

The main goal is to answer:

> "What data remains on this Windows installation that is no longer meaningfully owned by anything?"

This includes more than files.

The program should eventually inspect:

```text
Filesystem
Registry
Installed applications
MSI registrations
MSIX/AppX packages
Windows services
Scheduled tasks
Startup entries
Start Menu shortcuts
File associations
Protocol handlers
Shell extensions
Application update services
Application-specific caches
Application-specific configuration directories
Development tool artifacts
Old application versions
Old runtime versions
Broken executable references
```

The first version does not need to support every one of these, but the architecture should accommodate them.

---

# 4. Important Non-Goals

The application should NOT initially attempt to be:

- a registry optimizer
- a RAM optimizer
- a performance booster
- an antivirus product
- an automatic Windows system-component remover
- a driver cleanup utility
- a Windows servicing cleaner
- an aggressive "one click fix everything" utility

Avoid deleting files from sensitive Windows-managed locations based on generic heuristics.

Examples requiring specialized logic or exclusion:

```text
C:\Windows
C:\Windows\System32
C:\Windows\WinSxS
C:\Windows\Installer
Windows servicing data
driver stores
component stores
boot files
```

The orphan-detection engine should primarily focus on application-related storage.

---

# 5. Initial Platforms

Target:

```text
Windows 10
Windows 11
x64
```

ARM64 support can be added later.

The application should preferably be open source.

---

# 6. Suggested Architecture

Use a web-based frontend with a native Windows backend.

Suggested stack:

```text
Frontend:
React
TypeScript

Desktop shell:
Tauri

Native backend:
Rust

Optional website/browser version:
React PWA
File System Access API
```

The native application is the primary product.

The browser/PWA version may provide limited analysis of folders explicitly selected by the user.

The frontend should remain largely reusable between the browser and native application.

Conceptually:

```text
                 React UI
                    │
              command / IPC
                    │
                    ▼
              Rust Core Engine
                    │
      ┌─────────────┼─────────────┐
      │             │             │
      ▼             ▼             ▼
  Inventory      Scanner       Analyzer
      │             │             │
      └─────────────┼─────────────┘
                    ▼
              Ownership Graph
                    │
                    ▼
             Candidate Engine
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
   Orphan confidence     Safety analysis
          │                   │
          └─────────┬─────────┘
                    ▼
               Cleanup Plan
                    │
                    ▼
                   UI
```

The scanning and classification logic should live in reusable backend modules and should not be tightly coupled to the frontend.

---

# 7. Major Components

The backend should be divided into at least the following conceptual modules.

## 7.1 Application Inventory

Create a normalized inventory of applications and components that currently exist.

Sources should eventually include:

```text
HKLM uninstall entries
HKCU uninstall entries
32-bit uninstall entries
64-bit uninstall entries
MSI registrations
MSIX/AppX packages
installed executables
Windows services
scheduled tasks
startup entries
Start Menu shortcuts
registered file handlers
registered URI/protocol handlers
```

Each application should become a normalized internal entity.

Example:

```json
{
  "id": "app:notion",
  "displayName": "Notion",
  "normalizedName": "notion",
  "publisher": "Notion Labs, Inc.",
  "version": "4.2.0",
  "installLocations": [
    "C:\\Users\\user\\AppData\\Local\\Programs\\Notion"
  ],
  "executables": [
    "Notion.exe"
  ],
  "sources": [
    "HKCU_UNINSTALL"
  ]
}
```

Do not assume there is one reliable canonical source of installed applications.

Combine evidence from several sources.

---

# 8. Entity Normalization

Different components often refer to the same application using different strings.

For example:

```text
JetBrains Rider
Rider
Rider2025.1
JetBrains.Rider
com.jetbrains.rider
```

should potentially map to the same product family.

Similarly:

```text
Adobe Systems Incorporated
Adobe Inc.
Adobe
com.adobe.*
```

may share a vendor identity.

Implement normalized entities for:

```text
Vendor
Product family
Product
Version
Installation
```

Avoid overly aggressive fuzzy matching.

A false ownership match is worse than leaving something unknown.

---

# 9. Filesystem Scanner

The scanner should inspect application-related filesystem locations.

Important locations include:

```text
%LOCALAPPDATA%
%APPDATA%
%USERPROFILE%\AppData\LocalLow
%PROGRAMDATA%
%ProgramFiles%
%ProgramFiles(x86)%
```

Use Windows Known Folder APIs wherever appropriate instead of hard-coded paths.

Initially, the scanner should operate primarily at directory level rather than hashing or inspecting every individual file.

For each directory collect:

```text
path
total size
file count
directory count
creation time
oldest modification
newest modification
top-level children
extensions
large files
presence of executables
presence of databases
presence of recognizable metadata
```

Scanning should be asynchronous and cancelable.

Scanning large directories should not freeze the UI.

---

# 10. Ownership Resolution

For every discovered directory, attempt to determine its owner.

Ownership evidence can include:

### Strong evidence

```text
Exact install path match
MSIX PackageFamilyName match
MSI ProductCode relationship
Executable located inside directory
Known application data path
Historical observation
Explicit application manifest
```

### Medium evidence

```text
Folder name matches product
Folder name matches publisher
Executable metadata
Digital signature publisher
Registry references
Shortcut target
Service path
Scheduled task path
File association
Protocol handler
Updater path
```

### Weak evidence

```text
Similarity of names
Neighbor directory structure
Configuration text references
Log references
Common ecosystem conventions
```

Each evidence item should be stored.

Example:

```json
{
  "path": "C:\\Users\\user\\AppData\\Roaming\\Notion",
  "possibleOwner": "app:notion",
  "evidence": [
    {
      "type": "directory_name_match",
      "weight": 0.7
    },
    {
      "type": "historical_install_path",
      "weight": 1.0
    }
  ]
}
```

The UI should eventually be able to explain the important evidence.

---

# 11. Ownership Graph

Do not model the system only as directories and string matches.

Maintain an internal relationship graph.

Example:

```text
Notion
 ├── executable
 │    └── Notion.exe
 │
 ├── installation
 │    └── AppData\Local\Programs\Notion
 │
 ├── userdata
 │    └── AppData\Roaming\Notion
 │
 ├── cache
 │    └── AppData\Local\Notion
 │
 └── updater
      └── notion-update.exe
```

After uninstall:

```text
Notion [ABSENT]
 │
 ├── AppData\Roaming\Notion   ← still exists
 └── AppData\Local\Notion     ← still exists
```

These remaining relationships become orphan candidates.

The graph does not need to use a graph database.

Normal Rust structs and relational storage are sufficient.

---

# 12. Historical Observation

One of the strongest features should be the ability to remember previously observed ownership.

Example:

Day 1:

```text
Notion installed

Observed:
AppData\Roaming\Notion
AppData\Local\Notion
AppData\Local\Programs\Notion
```

Day 30:

```text
Notion is no longer installed.
```

The program can then perform a targeted scan.

Result:

```text
AppData\Local\Programs\Notion   removed
AppData\Roaming\Notion          still exists
AppData\Local\Notion            still exists
```

This provides very strong evidence that those directories are uninstall leftovers.

Store only metadata necessary for this feature.

Do not duplicate or upload user files.

A lightweight SQLite database is appropriate.

---

# 13. Detecting Removed Applications

Compare the current application inventory against previous inventories.

When an application disappears:

```text
previouslyPresent = true
currentlyPresent = false
```

generate an event:

```text
APPLICATION_REMOVED
```

Then examine previously associated resources.

Example:

```text
Notion removed

Remaining:
AppData\Roaming\Notion       420 MB
AppData\Local\Notion         1.7 GB
Scheduled task               1
Startup entry                0
Registry artifacts           12
```

Present this as:

> Notion appears to have been uninstalled and left approximately 2.1 GB of data behind.

This feature should eventually provide the highest-confidence results.

---

# 14. First-Run Detection

The application must still be useful when it has no historical information.

On first run, infer probable orphaned data by comparing directories against currently installed applications.

Example:

```text
AppData\Roaming\Notion exists

No Notion:
- uninstall registration
- executable
- MSIX package
- service
- scheduled task
- startup item
```

Result:

```text
Probable orphan
```

But confidence should be lower than a historically observed uninstall.

---

# 15. Orphan Confidence

Every candidate should receive an orphan-confidence assessment.

Do not initially over-focus on generating a mathematically perfect percentage.

Internally, a weighted score is fine.

Externally, the UI could use categories:

```text
Confirmed
Very likely
Likely
Uncertain
```

Example:

```text
Confirmed

Application was previously observed.
Its uninstall registration disappeared.
Its installation directory disappeared.
The remaining directory was previously associated with it.
```

versus:

```text
Likely

Directory name strongly matches an application that is not installed.
No active references were found.
```

versus:

```text
Uncertain

No owner was found.
The directory has not changed in two years.
```

"Unknown owner" must never automatically mean "orphan."

---

# 16. Data Classification

After ownership analysis, classify the contents.

Suggested categories:

```text
CACHE
TEMPORARY
LOG
CRASH_DUMP
UPDATE_CACHE
INSTALLER_CACHE
SHADER_CACHE
THUMBNAIL_CACHE
DOWNLOADED_ASSET
GENERATED_DATA

CONFIGURATION
APPLICATION_STATE
SESSION_DATA
ACCOUNT_DATA
PLUGIN
MOD
SAVE_GAME
DATABASE
PROJECT
DOCUMENT
MEDIA
UNKNOWN
```

Classification should use deterministic signals.

Examples:

```text
folder names
file extensions
known structures
known application definitions
SQLite schemas where safely recognizable
manifest files
metadata
known cache conventions
```

Avoid automatically parsing large arbitrary user files.

---

# 17. Deletion Safety

Deletion safety must be independent from orphan confidence.

Suggested safety classes:

```text
SAFE
LIKELY_SAFE
REVIEW
PRESERVE
UNKNOWN
```

Examples:

### SAFE

```text
orphaned application shader cache
orphaned crash dumps
orphaned application logs
known application cache
temporary updater download
```

### LIKELY_SAFE

```text
old downloaded runtime assets
old update packages
generated thumbnails
```

### REVIEW

```text
configuration
account state
plugins
old application settings
unknown SQLite database
```

### PRESERVE

```text
save games
user projects
documents
screenshots
mods
user-created presets
```

### UNKNOWN

Anything that cannot be confidently classified.

---

# 18. Safety Rules

Some rules should be absolute or nearly absolute.

Never automatically delete unknown data from:

```text
Windows system directories
driver stores
Windows Installer cache
WinSxS
boot configuration
system component stores
```

Never automatically delete something merely because:

```text
the directory is old
the folder has no executable
its name does not match an installed app
the directory is large
```

Large or old data is only a reason to inspect it.

---

# 19. Shared Components

The ownership model must support resources that belong to multiple products.

Add an ownership classification such as:

```text
EXCLUSIVE
SHARED
SYSTEM
UNKNOWN
```

Shared components require stricter removal rules.

Examples include:

```text
WebView2
Visual C++ redistributables
.NET runtimes
Java
Python
Node runtimes
DirectX components
Vulkan
CUDA
game anti-cheat software
common launchers
driver components
```

A component should not be classified as orphaned simply because one application using it was removed.

---

# 20. Dead Reference Detection

A valuable secondary feature is detecting references whose target no longer exists.

Examples:

```text
Startup entry
→ C:\Program Files\OldApp\OldApp.exe
→ target missing
```

```text
Scheduled task
→ C:\Users\user\AppData\Local\OldUpdater\update.exe
→ target missing
```

```text
Start Menu shortcut
→ D:\Games\Game.exe
→ target missing
```

```text
Service
→ C:\Program Files\OldVendor\Service.exe
→ target missing
```

Such dead references provide evidence that an application existed previously.

They can also point to nearby leftover data.

---

# 21. Abandoned Application Installations

Detect directories that appear to contain an application installation but no longer have registration in Windows.

Example:

```text
AppData\Local\Programs\OldApp
    OldApp.exe
    updater.exe
    resources\
```

Inspect executable metadata:

```text
CompanyName
ProductName
FileDescription
ProductVersion
Authenticode signer
```

Then compare against the installed application inventory.

Do not automatically classify portable applications as junk.

A directory containing a valid application executable but no uninstall registration may simply be a portable application.

It should normally be shown as:

```text
Possible unregistered/portable application
```

rather than orphaned data.

---

# 22. Known Application Definitions

Support an optional community-maintained definition database.

Example:

```yaml
id: discord
vendor: discord
product: Discord

identifiers:
  executables:
    - Discord.exe

paths:
  - path: "%APPDATA%\\discord\\Cache"
    type: CACHE

  - path: "%APPDATA%\\discord\\Code Cache"
    type: CACHE

  - path: "%APPDATA%\\discord\\GPUCache"
    type: CACHE
```

Definitions should improve confidence but must not be required for the entire application to work.

The unique value of the software is inference.

It must not degrade into only being a giant manually maintained list of paths.

---

# 23. Scan Results UI

The main scan results should emphasize meaningful cleanup candidates.

Example:

```text
Potentially removable                            8.4 GB

High confidence
───────────────────────────────────────────────

Notion leftovers                                2.1 GB
Notion is no longer installed.

JetBrains Rider 2024.1 leftovers                3.4 GB
A newer Rider version is installed.

Old NVIDIA installer files                      1.2 GB


Review
───────────────────────────────────────────────

OldGame data                                  750 MB
OldGame is not installed, but this folder
contains save-game files.

Unknown application data                      960 MB
No active owner was identified.
```

Avoid displaying meaningless counts such as:

```text
34,581 ISSUES FOUND
```

Storage size and actual resource identity matter more.

---

# 24. Candidate Details Screen

Each result should have a detailed explanation.

Example:

```text
JetBrains Rider 2024.1

Size
4.24 GB

Location
C:\Users\User\AppData\Local\JetBrains\Rider2024.1

Status
Very likely orphaned

Why?

✓ JetBrains Rider 2024.1 is not installed
✓ Rider 2026.2 is currently installed
✓ Directory identifies itself as Rider2024.1
✓ No executable references this directory
✓ No scheduled task references this directory
✓ Last modified 318 days ago

Contents

Cache                       3.82 GB     Safe
Logs                         110 MB     Safe
Settings                     190 MB     Review
Plugins                      120 MB     Review
```

Provide actions such as:

```text
Open folder
Select safe files
Select everything
Ignore
Always ignore
Delete
```

---

# 25. User Decisions

Ambiguous findings should be presented to the user rather than hidden.

For example:

```text
This appears to belong to "OldGame".

The application is no longer installed.

The folder contains:
- save games
- configuration
- screenshots

Do you want to keep or remove it?
```

The goal is not to make every decision automatically.

The goal is to give the user enough information to make a good decision.

---

# 26. Cleanup Workflow

Deletion should be performed through a cleanup plan.

Example:

```json
{
  "items": [
    {
      "path": "...\\Notion\\Cache",
      "action": "delete",
      "reason": "orphaned_cache"
    }
  ]
}
```

Before execution:

1. Revalidate that each target still exists.
2. Revalidate important ownership assumptions.
3. Detect whether files are currently in use where practical.
4. Show the total amount to be removed.
5. Ask for confirmation.

Do not silently expand deletion beyond the paths originally displayed to the user.

---

# 27. Recovery

Prefer recoverability.

Possible strategies:

### First version

Move deleted items to a dedicated quarantine directory.

Example:

```text
%LOCALAPPDATA%\OrphanCleaner\Quarantine
```

Record:

```text
original path
quarantine path
deletion timestamp
candidate ID
application owner
```

Allow:

```text
Restore
Delete permanently
```

Automatically clean old quarantine files according to a configurable retention period.

### Later

Investigate whether suitable cases can use the Windows Recycle Bin instead.

---

# 28. Ignore System

Users must be able to mark candidates as:

```text
Ignore once
Always ignore this path
Always keep this application
Always keep this type of data
```

Do not repeatedly nag users about intentionally retained application data.

---

# 29. Scan Modes

Support several modes.

### Quick Scan

Inspect:

```text
AppData
ProgramData
installed applications
known orphan relationships
```

Should finish reasonably quickly.

### Deep Scan

Also inspect:

```text
Program Files
dead references
larger directory structures
old application versions
additional executable metadata
```

### Post-Uninstall Scan

Triggered when a previously known application disappears.

Scan only resources previously associated with that application.

This should be extremely fast and high confidence.

---

# 30. Performance

Scanning AppData can involve hundreds of thousands of files.

Requirements:

- multithread where useful
- avoid reading file contents unnecessarily
- calculate directory sizes incrementally
- cache scan metadata
- support cancellation
- stream scan results to the UI
- do not block the UI
- limit disk thrashing
- avoid hashing every file by default

The user should start seeing findings before the entire scan is complete.

---

# 31. Privilege Model

Run without administrator rights by default.

Most user-level AppData analysis does not require elevation.

When administrator privileges are needed:

```text
ProgramData
system-wide application data
services
some registry keys
system-wide cleanup
```

request elevation only for the action that requires it where practical.

Do not require permanent administrator execution.

---

# 32. Privacy

The cleaner should work locally.

Do not upload:

```text
file names
directory trees
installed application lists
registry contents
configuration
personal documents
```

The core product should not depend on a cloud service.

No LLM is required.

If telemetry is added, it should be optional and contain only non-sensitive aggregate information.

---

# 33. No LLM-Based Decision Making

Do not use an LLM to classify deletion safety.

All important decisions should be:

```text
deterministic
inspectable
reproducible
explainable
```

An unknown case should remain unknown.

Do not attempt to "guess harder" simply to produce more cleanup recommendations.

---

# 34. Internal Candidate Model

A candidate could approximately use this structure:

```ts
interface CleanupCandidate {
  id: string;

  resources: Resource[];

  probableOwner?: ApplicationReference;

  ownershipConfidence:
    | "confirmed"
    | "very_likely"
    | "likely"
    | "uncertain";

  orphanStatus:
    | "confirmed_orphan"
    | "probable_orphan"
    | "possibly_orphaned"
    | "not_orphaned"
    | "unknown";

  dataClassification: DataClassification[];

  deletionSafety:
    | "safe"
    | "likely_safe"
    | "review"
    | "preserve"
    | "unknown";

  evidence: Evidence[];

  sizeBytes: number;

  recommendedAction:
    | "clean"
    | "review"
    | "keep"
    | "ignore";
}
```

The exact implementation may differ.

The important part is keeping:

```text
ownership
orphan status
content classification
deletion safety
recommendation
```

as separate concepts.

---

# 35. Evidence Model

Evidence should be first-class data.

Example:

```ts
interface Evidence {
  type:
    | "historical_owner"
    | "installed_app_match"
    | "missing_installed_app"
    | "directory_name_match"
    | "publisher_match"
    | "executable_metadata"
    | "registry_reference"
    | "scheduled_task_reference"
    | "service_reference"
    | "shortcut_reference"
    | "package_family_match"
    | "known_definition"
    | "last_modified"
    | "content_pattern";

  description: string;

  strength:
    | "strong"
    | "medium"
    | "weak";

  source?: string;
}
```

This allows the UI to explain decisions without duplicating classification logic.

---

# 36. Persistence

Use SQLite for local state.

Suggested tables:

```text
applications
application_installations
resources
ownership_relationships
observations
scan_sessions
cleanup_candidates
cleanup_actions
ignored_items
quarantine_items
```

Do not store unnecessary information about user files.

For example, the program generally does not need to persist every filename encountered.

---

# 37. Application Version Cleanup

Another important target is old application versions.

Example:

```text
JetBrains
├── Rider2024.1
├── Rider2024.3
└── Rider2026.2
```

If only Rider 2026.2 remains installed, older version-specific cache directories are strong candidates.

Likewise:

```text
Android SDK components
IDE caches
browser versions
Electron app versions
game launcher versions
GPU shader caches
development toolchains
```

However, old configuration directories may contain settings the user wants to preserve.

Separate:

```text
generated cache
```

from:

```text
configuration
```

before recommending cleanup.

---

# 38. Developer-Focused Cleanup

Development environments frequently accumulate very large orphaned data.

Eventually inspect common ecosystems such as:

```text
Visual Studio
JetBrains
Android Studio
Gradle
Maven
npm
pnpm
Yarn
NuGet
Rust/Cargo
Python
Docker
WSL
Unity
Unreal Engine
Android SDK
emulators
old SDK versions
build caches
```

Again, distinguish between:

```text
generated/reproducible data
```

and:

```text
projects/source code
```

Never classify an unknown source-code directory as junk.

---

# 39. Browser/PWA Version

The web version should use the File System Access API where available.

The user chooses a folder.

The browser version may perform:

```text
large-file analysis
old-file detection
empty directory detection
duplicate analysis
project artifact detection
node_modules detection
build output detection
selected-folder orphan analysis
```

However, because browsers restrict access to important Windows system and application directories, the browser version should clearly describe itself as limited.

The native Tauri version provides full functionality.

The browser and native versions should reuse as much frontend and analysis code as practical.

---

# 40. Security

Treat all filesystem contents as untrusted input.

Do not execute discovered executables.

Do not load DLLs from scanned directories.

Do not run scripts discovered during scanning.

Executable analysis should inspect metadata without executing them.

Avoid following dangerous or unexpected reparse points blindly.

Handle:

```text
junctions
symbolic links
mount points
reparse points
```

carefully to prevent recursive traversal and accidental scans outside intended directories.

---

# 41. Logging

Implement detailed application logs for debugging.

However, logs should avoid dumping sensitive filenames unnecessarily.

Provide a user-accessible diagnostics export.

The export should clearly show what information it contains.

---

# 42. Initial MVP

The MVP should NOT delete anything.

Its sole goal is proving that ownership inference works.

Build:

### Stage 1: Installed application inventory

Collect:

```text
HKCU uninstall entries
HKLM uninstall entries
32/64-bit variants
MSIX/AppX packages
basic executable/install-path metadata
```

### Stage 2: Filesystem inventory

Scan:

```text
%LOCALAPPDATA%
%APPDATA%
LocalLow
%PROGRAMDATA%
```

Collect directory sizes and basic metadata.

### Stage 3: Ownership matching

For each top-level and relevant nested application directory:

```text
determine probable application owner
determine whether owner is installed
collect evidence
```

### Stage 4: Display results

Create a table similar to:

```text
Directory                     Size     Probable owner       Installed      Confidence

Roaming\Notion                1.8 GB   Notion               No             Very high
Local\Discord                 2.1 GB   Discord              Yes            Confirmed
Local\JetBrains\Rider2024.1   4.2 GB   JetBrains Rider      No             High
Roaming\OldGame               650 MB   OldGame              No             Medium
Local\Microsoft               8.4 GB   Microsoft/shared     Mixed          Unknown
```

There should be no delete button yet.

The purpose of this phase is to measure false positives.

---

# 43. MVP Success Criterion

The most important initial success metric is:

> Can the application accurately explain who owns directories under AppData?

Do not prioritize deletion until this works reliably.

A good MVP should identify:

```text
currently owned application data
probable leftovers
unknown data
shared/vendor data
version-specific leftovers
```

without classifying obviously active software as orphaned.

---

# 44. Second Milestone

After ownership inference is reliable:

Add:

```text
content classification
safe/review/preserve categories
cleanup candidate grouping
ignore rules
quarantine
manual deletion
```

Initially only allow cleanup for explicitly selected items.

---

# 45. Third Milestone

Add historical ownership.

Persist application/resource associations.

Detect when applications disappear.

Then show:

```text
Recently uninstalled applications

Notion
Uninstalled since previous scan.

Remaining data:
2.4 GB
```

This should become one of the application's strongest features.

---

# 46. Fourth Milestone

Add system relationships:

```text
scheduled tasks
startup items
services
shortcuts
protocol handlers
file associations
```

Use these both as cleanup targets and as ownership evidence.

---

# 47. Later Features

Possible future additions:

```text
old runtime detection
application version cleanup
duplicate application installations
unused application discovery
large generated development caches
portable application recognition
Steam/game launcher leftovers
GPU driver installer leftovers
broken shell extensions
abandoned context menu handlers
browser extension leftovers
quarantine restore
community definitions
community false-positive reports
```

---

# 48. Design Principle for Every New Detector

Every detector should answer four questions:

```text
1. What is this resource?

2. Who owns or owned it?

3. Why do we believe it is no longer required?

4. What could the user lose if it is deleted?
```

If the application cannot provide reasonable answers, the resource should not be automatically recommended for deletion.

---

# 49. Example Complete Result

Example:

```text
Notion leftovers
────────────────────────────────────────

Total size
2.34 GB

Probable owner
Notion

Owner status
Not installed

Orphan confidence
Confirmed

Why this was detected
✓ Notion was previously installed
✓ Notion disappeared from installed applications
✓ These directories were previously associated with Notion
✓ No current executable references them

Data

AppData\Local\Notion\Cache
1.43 GB
Cache
Safe to remove

AppData\Local\Notion\GPUCache
322 MB
Generated cache
Safe to remove

AppData\Roaming\Notion\logs
141 MB
Logs
Safe to remove

AppData\Roaming\Notion\Preferences
52 KB
Configuration
Review

AppData\Roaming\Notion\Session Storage
89 MB
Application state
Review

Recommended cleanup
1.89 GB

Possible retained data
89 MB

[Open folder]
[Ignore]
[Select safe items]
[Review all files]
```

That level of explanation should be the target user experience.

---

# 50. Product Identity

The product should differentiate itself through:

```text
ownership-aware cleanup
historical uninstall tracking
explainable detection
conservative safety rules
local processing
free/open-source availability
no scare tactics
no artificial "health score"
no registry-cleaner pseudoscience
```

The user should trust the application because it clearly shows how it reached its conclusions.

The product is not trying to find the largest possible number of deletable files.

It is trying to find **forgotten storage that conventional cleaners fail to understand**.

---

# 51. Guiding Statement for Implementation

When making implementation decisions, follow this priority order:

```text
1. Do not delete important user data.
2. Correctly determine ownership.
3. Explain every recommendation.
4. Prefer uncertainty over false confidence.
5. Detect meaningful orphaned storage.
6. Make scanning fast.
7. Maximize the amount cleaned.
```

False positives are significantly more damaging than missed cleanup opportunities.

The application should become more knowledgeable over time, but it should remain conservative whenever evidence is incomplete.