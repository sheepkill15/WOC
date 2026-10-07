//! Cleanup plans and quarantine (spec §26–27).
//!
//! Recommended cleanup uses the saved scan; explicit manual cleanup accepts any
//! local file or folder and warns about policy risks. Every plan revalidates
//! contents, existence, reparse points, keep rules and current ownership.
//! Execution moves items into quarantine on the same volume with a single rename;
//! nothing is deleted except by an explicit
//! purge (or retention expiry) of a quarantined item.

use cleaner_core::references::path_is_within;
use cleaner_core::{Application, DirectoryResult, content};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::hash::{Hash, Hasher};

use crate::storage::{self, QuarantineItem, SavedScan};
use crate::logging;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanupRequest {
    pub paths: Vec<String>,
    /// Required to execute items whose plan status is "warning".
    #[serde(default)]
    pub acknowledge_warnings: bool,
    #[serde(default)]
    pub manual_cleanup: bool,
    pub plan_token: String,
}

#[derive(Default)]
pub struct PlanOptions<'a> {
    pub rules: &'a [storage::IgnoreRule],
    pub manual_cleanup: bool,
    pub inventory_incomplete: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanItem {
    pub path: String,
    /// directory | content | shortcut
    pub item_kind: String,
    pub size_bytes: u64,
    pub file_count: u64,
    /// ready | warning | blocked | redundant
    pub status: String,
    pub messages: Vec<String>,
    pub owner: Option<String>,
    pub safety: String,
    pub reason: String,
    pub newest_modified_unix: Option<u64>,
    pub quarantine_directory: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanupPlan {
    pub items: Vec<PlanItem>,
    pub total_bytes: u64,
    pub ready_count: usize,
    pub warning_count: usize,
    pub blocked_count: usize,
    pub quarantine_directory: String,
    pub scan_at_unix: Option<u64>,
    pub manual_cleanup: bool,
    pub plan_token: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutedItem {
    pub path: String,
    pub moved: bool,
    pub message: String,
    pub quarantine_id: Option<i64>,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanupOutcome {
    pub items: Vec<ExecutedItem>,
    pub moved_count: usize,
    pub moved_bytes: u64,
    pub failed_count: usize,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuarantineReport {
    pub items: Vec<QuarantineItem>,
    pub history: Vec<QuarantineItem>,
    pub total_bytes: u64,
    pub retention_days: u32,
    pub quarantine_directory: String,
    pub expired_purged: usize,
}

pub fn quarantine_root(app_local_data: &Path) -> PathBuf {
    app_local_data.join("Quarantine")
}

fn database(app_local_data: &Path) -> PathBuf {
    app_local_data.join("scans.sqlite3")
}

fn recovery_note(slot: &Path, name: &str) -> PathBuf {
    slot.join(if name.eq_ignore_ascii_case("ORIGINAL_PATH.txt") { "ORIGINAL_PATH_INFO.txt" } else { "ORIGINAL_PATH.txt" })
}

fn volume_key(path: &Path) -> Option<String> {
    match path.components().next()? {
        Component::Prefix(prefix) => Some(prefix.as_os_str().to_string_lossy().to_ascii_lowercase()),
        _ => None,
    }
}

/// Keep each move on its source volume. The namespace is stable across launches
/// and belongs to this application's data directory, rather than another user.
fn quarantine_for(app_local_data: &Path, source: &Path) -> PathBuf {
    if volume_key(source) == volume_key(app_local_data) {
        return quarantine_root(app_local_data);
    }
    let mut identity = 0xcbf29ce484222325u64;
    for byte in app_local_data.to_string_lossy().to_ascii_lowercase().replace('/', "\\").bytes() {
        identity = (identity ^ u64::from(byte)).wrapping_mul(0x100000001b3);
    }
    source.ancestors().last().unwrap_or(source)
        .join("OrphanCleanerQuarantine").join(format!("{identity:016x}"))
}

fn protected_roots() -> Vec<String> {
    let mut roots = Vec::new();
    for variable in ["SystemRoot", "windir", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ProgramData", "LOCALAPPDATA", "APPDATA", "USERPROFILE", "SystemDrive", "CommonProgramFiles", "CommonProgramFiles(x86)"] {
        if let Ok(value) = std::env::var(variable) {
            let value = value.trim_end_matches('\\').to_owned();
            if !value.is_empty() { roots.push(value); }
        }
    }
    roots
}

fn windows_directory() -> String {
    std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into())
}

/// Basic path hygiene shared by planning and restore.
fn validate_shape(path: &str) -> Result<PathBuf, String> {
    let candidate = PathBuf::from(path);
    if !candidate.is_absolute() { return Err("Only absolute paths can be cleaned.".into()); }
    if candidate.components().any(|component| matches!(component, Component::ParentDir | Component::CurDir)) {
        return Err("Paths with '.' or '..' components are refused.".into());
    }
    if path.starts_with(r"\\") { return Err("Network and device paths are refused.".into()); }
    if candidate.components().count() < 3 { return Err("A drive root cannot be moved into quarantine.".into()); }
    if candidate.components().any(|component| matches!(component, Component::Normal(name) if {
        let name = name.to_string_lossy();
        name.ends_with(['.', ' ']) || name.contains(':')
    })) { return Err("Ambiguous Windows paths and alternate data streams are refused.".into()); }
    Ok(candidate)
}

fn is_protected(path: &str, app_local_data: &Path) -> Option<String> {
    for folder in cleaner_core::protected_folders() {
        let folder = folder.to_string_lossy();
        if path_is_within(&folder, path) {
            return Some(format!("{folder} holds your own files or is a scan root; it and its parents are never cleaned."));
        }
    }
    let trimmed = path.trim_end_matches('\\');
    for root in protected_roots() {
        if trimmed.eq_ignore_ascii_case(&root) {
            return Some(format!("{root} itself is a protected system location."));
        }
    }
    let windows = windows_directory();
    if path_is_within(path, &windows) {
        return Some("Files inside the Windows directory are never cleaned.".into());
    }
    if path_is_within(path, &app_local_data.to_string_lossy()) || path_is_within(&app_local_data.to_string_lossy(), path) {
        return Some("The cleaner's own data folder cannot be cleaned.".into());
    }
    for protected in [r"\WinSxS", r"\Installer", r"\System32", r"\SysWOW64", r"\DriverStore"] {
        if path.to_ascii_lowercase().contains(&protected.to_ascii_lowercase()) && path_is_within(path, &windows) {
            return Some("Windows component stores are never cleaned.".into());
        }
    }
    None
}

enum Located<'a> {
    Directory(&'a DirectoryResult),
    Content(&'a DirectoryResult, &'a cleaner_core::ContentItem),
    Shortcut(&'a cleaner_core::SystemReference),
}

fn same_path(left: &str, right: &str) -> bool {
    path_is_within(left, right) && path_is_within(right, left)
}

fn locate<'a>(scan: &'a SavedScan, path: &str) -> Option<Located<'a>> {
    if let Some(result) = scan.results.iter().find(|result| same_path(&result.path, path)) {
        return Some(Located::Directory(result));
    }
    let candidate = Path::new(path);
    let parent = candidate.parent()?.to_string_lossy().into_owned();
    let name = candidate.file_name()?.to_string_lossy().into_owned();
    if let Some(result) = scan.results.iter().find(|result| same_path(&result.path, &parent)) {
        if let Some(item) = result.content.items.iter().find(|item| item.is_directory && item.name.eq_ignore_ascii_case(&name)) {
            return Some(Located::Content(result, item));
        }
    }
    scan.references.references.iter()
        .find(|reference| reference.file_backed && same_path(&reference.location, path))
        .map(Located::Shortcut)
}

fn warn(item: &mut PlanItem, message: impl Into<String>) {
    if item.status == "ready" { item.status = "warning".into(); }
    item.messages.push(message.into());
}

fn risk(item: &mut PlanItem, message: impl Into<String>, manual: bool) {
    if !manual { item.status = "blocked".into(); }
    warn(item, message);
}

/// Builds a revalidated plan. `current_apps` is the freshly read inventory.
pub fn plan(app_local_data: &Path, scan: Option<&SavedScan>, paths: &[String], current_apps: &[Application], options: &PlanOptions<'_>) -> CleanupPlan {
    let quarantine = quarantine_root(app_local_data);
    let mut items: Vec<PlanItem> = Vec::new();
    let mut unique: Vec<String> = Vec::new();
    for path in paths {
        let trimmed = path.trim().replace('/', "\\").trim_end_matches('\\').to_owned();
        if !trimmed.is_empty() && !unique.iter().any(|existing| existing.eq_ignore_ascii_case(&trimmed)) {
            unique.push(trimmed);
        }
    }
    for path in &unique {
        let mut item = PlanItem {
            path: path.clone(), item_kind: "directory".into(), size_bytes: 0, file_count: 0,
            status: "ready".into(), messages: Vec::new(), owner: None, safety: content::UNKNOWN.into(), reason: String::new(),
            newest_modified_unix: None, quarantine_directory: String::new(),
        };
        let block = |item: &mut PlanItem, message: String| { item.status = "blocked".into(); item.messages.push(message); };

        let shape = validate_shape(path);
        let Ok(candidate) = shape else { block(&mut item, shape.unwrap_err()); items.push(item); continue; };
        let destination_root = quarantine_for(app_local_data, &candidate);
        item.quarantine_directory = destination_root.display().to_string();
        if path_is_within(path, &app_local_data.to_string_lossy()) || path_is_within(&app_local_data.to_string_lossy(), path)
            || path_is_within(path, &destination_root.to_string_lossy()) || path_is_within(&destination_root.to_string_lossy(), path) {
            block(&mut item, "The cleaner's own data and quarantine cannot be moved.".into());
            items.push(item); continue;
        }
        if let Some(message) = is_protected(path, app_local_data) { risk(&mut item, message.replace("never cleaned", "not recommended for cleanup"), options.manual_cleanup); }
        if options.inventory_incomplete { risk(&mut item, "The application inventory is incomplete; ownership cannot be fully checked.", options.manual_cleanup); }
        let located = scan.and_then(|scan| locate(scan, path));
        match &located {
            None => risk(&mut item, "This path was not shown in the latest scan. Manual cleanup is required.", options.manual_cleanup),
            Some(Located::Directory(result)) => {
                if result.evidence.iter().any(|evidence| evidence.kind == "personal_location") || result.location_class.as_deref() == Some("user_data") {
                    risk(&mut item, "This is a personal folder. Moving it removes your own files from their current location.", options.manual_cleanup);
                }
                item.owner = result.owner.as_ref().map(|owner| owner.name.clone()).or_else(|| result.owner_hint.clone());
                item.safety = result.assessment.deletion_safety.clone();
                item.reason = format!("{} ({})", result.orphan_status, result.assessment.orphan_confidence);
                if matches!(result.location_class.as_deref(), Some("system" | "shared_runtime")) {
                    risk(&mut item, "Windows or a shared runtime manages this location. Moving it can break applications or Windows.", options.manual_cleanup);
                }
                // Revalidate ownership against the current inventory.
                let current = cleaner_core::classify_directory(&candidate, &result.root, current_apps);
                if current.orphan_status == "not_orphaned" {
                    let name = current.owner.as_ref().map(|owner| owner.name.as_str()).unwrap_or("an installed application");
                    if matches!(result.orphan_status.as_str(), "probable_orphan" | "possibly_orphaned" | "unknown" | "unregistered_application") {
                        risk(&mut item, format!("This folder now matches {name}, which is currently installed."), options.manual_cleanup);
                    } else {
                        warn(&mut item, format!("{name} is installed and uses this folder. Removing it resets or breaks the application."));
                    }
                } else if matches!(result.orphan_status.as_str(), "not_orphaned" | "associated_with_installed" | "referenced_by_system" | "known_application_data") {
                    warn(&mut item, "This folder is linked to installed software or Windows components.");
                }
                if result.evidence.iter().any(|evidence| evidence.kind == "active_reference") {
                    warn(&mut item, "A startup entry, task, service or shortcut still uses files in this folder.");
                }
                if result.orphan_status == "unknown" {
                    warn(&mut item, "No owner was identified. Unknown does not mean unnecessary.");
                }
            }
            Some(Located::Content(result, content_item)) => {
                if result.evidence.iter().any(|evidence| evidence.kind == "personal_location") || result.location_class.as_deref() == Some("user_data") {
                    risk(&mut item, "This is content in a personal folder. Moving it removes your own files from their current location.", options.manual_cleanup);
                }
                item.item_kind = "content".into();
                item.owner = result.owner.as_ref().map(|owner| owner.name.clone()).or_else(|| result.owner_hint.clone());
                item.safety = content_item.safety.clone();
                item.reason = format!("{} inside {}", content::kind_label(&content_item.kind), result.path);
                if matches!(result.location_class.as_deref(), Some("system" | "shared_runtime")) {
                    risk(&mut item, "Windows or a shared runtime manages the containing location. Moving it can break applications or Windows.", options.manual_cleanup);
                }
                if result.orphan_status == "not_orphaned" {
                    item.messages.push("The application is installed; close it first. It recreates caches when needed.".into());
                }
            }
            Some(Located::Shortcut(reference)) => {
                item.item_kind = "shortcut".into();
                item.owner = Some(reference.name.clone());
                item.safety = content::SAFE.into();
                item.reason = "Shortcut to a missing program".into();
                let allowed = cleaner_core::shortcut_roots().iter().any(|root| path_is_within(path, &root.to_string_lossy()));
                if !allowed { risk(&mut item, "This shortcut is outside Start Menu and Startup folders.", options.manual_cleanup); }
                let target_exists = reference.target_path.as_deref().is_some_and(|target| Path::new(target).exists());
                if target_exists { risk(&mut item, "The shortcut target exists again; it is no longer a dead reference.", options.manual_cleanup); }
            }
        }
        if item.status != "blocked" {
            match fs::symlink_metadata(&candidate) {
                Err(_) => block(&mut item, "The path no longer exists.".into()),
                Ok(metadata) if cleaner_core_reparse(&metadata) => block(&mut item, "Links, junctions and other reparse points are never followed or moved.".into()),
                Ok(_) if ancestor_link(&candidate).is_some() => block(&mut item, format!("A folder above this path ({}) is a link or junction; the path is refused.", ancestor_link(&candidate).map(|link| link.display().to_string()).unwrap_or_default())),
                Ok(metadata) => {
                    if options.manual_cleanup && metadata.is_file() { item.item_kind = "file".into(); }
                    if item.item_kind == "shortcut" && !metadata.is_file() { block(&mut item, "Expected a shortcut file.".into()); }
                    if !matches!(item.item_kind.as_str(), "shortcut" | "file") && !metadata.is_dir() { block(&mut item, "Expected a folder.".into()); }
                }
            }
        }
        if item.status != "blocked" {
            let saved_result = match &located {
                Some(Located::Directory(result) | Located::Content(result, _)) => Some(*result),
                _ => None,
            };
            let root = saved_result.map(|result| result.root.as_str()).unwrap_or("Manual");
            let ownership_path = if item.item_kind == "content" { candidate.parent().unwrap_or(&candidate) } else { &candidate };
            let current = cleaner_core::classify_directory(ownership_path, root, current_apps);
            if let Some(owner) = &current.owner {
                item.owner = Some(owner.name.clone());
                if item.item_kind == "content" && saved_result.is_some_and(|result| result.orphan_status != "not_orphaned") {
                    risk(&mut item, format!("{} is currently installed and uses the containing folder.", owner.name), options.manual_cleanup);
                }
            }
            let mut kinds = Vec::new();
            let fresh_safety;
            if candidate.is_dir() {
                let stats = cleaner_core::inspect_directory(&candidate, &std::sync::atomic::AtomicBool::new(false));
                item.size_bytes = stats.size; item.file_count = stats.files; item.newest_modified_unix = stats.newest;
                fresh_safety = if item.item_kind == "content" {
                    let named = candidate.file_name().and_then(|name| content::kind_for_directory_name(&name.to_string_lossy()));
                    if let Some((kind, _)) = named { kinds.push(kind.to_owned()); }
                    let raw = content::overall_safety(&stats.content);
                    if raw == content::PRESERVE || raw == content::REVIEW || stats.content.executable_count > 0 || stats.skipped > 0 { raw.to_owned() }
                    else { named.map(|(kind, safety)| safety.unwrap_or_else(|| content::safety_for_kind(kind))).unwrap_or(raw).to_owned() }
                } else { content::overall_safety(&stats.content).to_owned() };
                kinds.extend(stats.content.items.iter().map(|content| content.kind.clone()));
                kinds.extend(stats.content.categories.iter().cloned());
                if stats.skipped > 0 { warn(&mut item, format!("{} entries could not be inspected; the size and safety assessment are incomplete.", stats.skipped)); }
            } else {
                let metadata = fs::metadata(&candidate);
                if let Ok(metadata) = metadata {
                    item.size_bytes = metadata.len(); item.file_count = 1;
                    item.newest_modified_unix = metadata.modified().ok().and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok()).map(|time| time.as_secs());
                } else { block(&mut item, "The file could not be inspected.".into()); }
                let kind = candidate.extension().and_then(|extension| content::kind_for_extension(&extension.to_string_lossy().to_ascii_lowercase())).unwrap_or("unknown");
                kinds.push(kind.to_owned());
                fresh_safety = if item.item_kind == "shortcut" { content::SAFE.into() } else { content::safety_for_kind(kind).to_owned() };
            }
            if content::safety_rank(&fresh_safety) > content::safety_rank(&item.safety) || item.safety == content::UNKNOWN { item.safety = fresh_safety; }
            if matches!(item.safety.as_str(), content::PRESERVE | content::REVIEW | content::UNKNOWN) {
                let safety = item.safety.replace('_', " ");
                warn(&mut item, format!("This item is classified {safety}. Review its contents before moving."));
            }
            if let Some(result) = saved_result {
                if item.item_kind == "content" {
                    if let Some(Located::Content(_, content)) = &located { kinds.push(content.kind.clone()); }
                } else {
                    kinds.extend(result.content.items.iter().map(|item| item.kind.clone()));
                    kinds.extend(result.content.categories.iter().cloned());
                }
            }
            for rule in options.rules {
                let applies = match rule.kind.as_str() {
                    "path" => path_is_within(path, &rule.value) || path_is_within(&rule.value, path),
                    "once" => rule.scan_at_unix == scan.map(|scan| scan.captured_at_unix) && (path_is_within(path, &rule.value) || path_is_within(&rule.value, path)),
                    "category" => kinds.iter().any(|kind| kind == &rule.value),
                    "application" => {
                        let key = cleaner_core::normalize_name(&rule.value);
                        item.owner.as_deref().is_some_and(|owner| cleaner_core::normalize_name(owner) == key)
                            || saved_result.and_then(|result| result.owner.as_ref()).is_some_and(|owner| cleaner_core::normalize_name(&owner.name) == key)
                            || saved_result.and_then(|result| result.owner_hint.as_deref()).is_some_and(|owner| cleaner_core::normalize_name(owner) == key)
                            || scan.is_some_and(|scan| scan.results.iter().any(|result| path_is_within(&result.path, path)
                                && result.owner.as_ref().map(|owner| owner.name.as_str()).or(result.owner_hint.as_deref()).is_some_and(|owner| cleaner_core::normalize_name(owner) == key)))
                    }
                    _ => false,
                };
                if applies { risk(&mut item, format!("Your keep rule ‘{}’ applies. Manual cleanup overrides it for this operation only.", rule.label), options.manual_cleanup); }
            }
            if let Err(error) = ensure_no_links(&candidate, false).and_then(|_| ensure_no_links(&destination_root, true)) { block(&mut item, error); }
        }
        if options.manual_cleanup && item.status == "ready" { warn(&mut item, "Manual cleanup: move this path regardless of cleanup recommendations."); }
        items.push(item);
    }
    // A child is redundant only when a selected ancestor is itself going to be moved.
    let actionable: Vec<String> = items.iter().filter(|item| matches!(item.status.as_str(), "ready" | "warning")).map(|item| item.path.clone()).collect();
    for item in &mut items {
        if matches!(item.status.as_str(), "ready" | "warning")
            && actionable.iter().any(|ancestor| !ancestor.eq_ignore_ascii_case(&item.path) && path_is_within(&item.path, ancestor)) {
            item.status = "redundant".into();
            item.messages = vec!["Included in a selected containing folder.".into()];
            item.size_bytes = 0;
        }
    }
    let total_bytes = items.iter().filter(|item| matches!(item.status.as_str(), "ready" | "warning")).map(|item| item.size_bytes).sum();
    let mut plan = CleanupPlan {
        ready_count: items.iter().filter(|item| item.status == "ready").count(),
        warning_count: items.iter().filter(|item| item.status == "warning").count(),
        blocked_count: items.iter().filter(|item| item.status == "blocked").count(),
        items,
        total_bytes,
        quarantine_directory: quarantine.to_string_lossy().into_owned(),
        scan_at_unix: scan.map(|scan| scan.captured_at_unix),
        manual_cleanup: options.manual_cleanup,
        plan_token: String::new(),
    };
    let mut hash = std::collections::hash_map::DefaultHasher::new();
    serde_json::to_string(&plan).unwrap_or_default().hash(&mut hash);
    plan.plan_token = format!("{:016x}", hash.finish());
    plan
}

#[cfg(windows)]
fn cleaner_core_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0 || metadata.file_type().is_symlink()
}

#[cfg(not(windows))]
fn cleaner_core_reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

/// Refuses paths reached through a junction or symbolic link anywhere above them,
/// so a folder swapped for a link after the scan cannot redirect the move.
fn ancestor_link(path: &Path) -> Option<PathBuf> {
    let mut current = path.parent();
    while let Some(ancestor) = current {
        if ancestor.parent().is_none() { break; }
        if let Ok(metadata) = fs::symlink_metadata(ancestor) {
            if cleaner_core_reparse(&metadata) { return Some(ancestor.to_path_buf()); }
        }
        current = ancestor.parent();
    }
    None
}

/// Checks existing components even when the final location has not been created.
/// Errors other than NotFound are never treated as evidence of a safe path.
fn ensure_no_links(path: &Path, allow_missing: bool) -> Result<(), String> {
    for component in path.ancestors() {
        match fs::symlink_metadata(component) {
            Ok(metadata) if cleaner_core_reparse(&metadata) => return Err(format!("{} is a link or junction; the operation was refused.", component.display())),
            Ok(_) => {},
            Err(error) if allow_missing && error.kind() == std::io::ErrorKind::NotFound => {},
            Err(error) => return Err(format!("{} could not be validated: {}", component.display(), describe_io_error(&error))),
        }
    }
    Ok(())
}

/// On Windows, keep directory handles open without FILE_SHARE_DELETE so a
/// checked parent cannot be renamed/replaced by a junction during the operation.
#[cfg(windows)]
pub(crate) fn guard_parents(path: &Path) -> Result<Vec<fs::File>, String> {
    use std::os::windows::fs::OpenOptionsExt;
    let mut guards = Vec::new();
    for parent in path.ancestors().skip(1) {
        match fs::OpenOptions::new().read(true).share_mode(3).custom_flags(0x02200000).open(parent) {
            Ok(file) => {
                let metadata = file.metadata().map_err(|error| describe_io_error(&error))?;
                if cleaner_core_reparse(&metadata) { return Err(format!("{} is a link or junction.", parent.display())); }
                guards.push(file);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
            Err(error) => return Err(format!("{} could not be secured: {}", parent.display(), describe_io_error(&error))),
        }
    }
    Ok(guards)
}

#[cfg(not(windows))]
pub(crate) fn guard_parents(path: &Path) -> Result<Vec<fs::File>, String> {
    ensure_no_links(path.parent().unwrap_or(path), true)?;
    Ok(Vec::new())
}

fn describe_io_error(error: &std::io::Error) -> String {
    match error.raw_os_error() {
        Some(5) => "Access denied. The location needs administrator rights, or a file inside is in use.".into(),
        Some(32) | Some(33) => "A file inside is in use by another program. Close it and try again.".into(),
        Some(17) => "The item is on a different drive than the quarantine folder.".into(),
        _ => error.to_string(),
    }
}

/// Executes a plan: re-plans, then moves each ready (and, when acknowledged, warning) item into quarantine.
pub fn execute(app_local_data: &Path, scan: Option<&SavedScan>, request: &CleanupRequest, current_apps: &[Application], options: &PlanOptions<'_>) -> Result<CleanupOutcome, String> {
    let options = PlanOptions { manual_cleanup: request.manual_cleanup, ..*options };
    let plan = plan(app_local_data, scan, &request.paths, current_apps, &options);
    if plan.plan_token != request.plan_token {
        return Err("The cleanup plan changed since you reviewed it. Review the updated plan and confirm again. Nothing was moved.".into());
    }
    let conn = storage::open_db(&database(app_local_data))?;
    let batch = storage::now_unix();
    let mut outcome = CleanupOutcome { items: Vec::new(), moved_count: 0, moved_bytes: 0, failed_count: 0 };
    for (index, item) in plan.items.iter().enumerate() {
        let allowed = item.status == "ready" || (item.status == "warning" && request.acknowledge_warnings);
        if !allowed {
            if item.status != "redundant" {
                outcome.failed_count += 1;
                let message = if item.status == "warning" { "Not moved: warnings were not acknowledged.".into() } else { item.messages.join(" ") };
                outcome.items.push(ExecutedItem { path: item.path.clone(), moved: false, message, quarantine_id: None, size_bytes: item.size_bytes });
            }
            continue;
        }
        let source = PathBuf::from(&item.path);
        let root = quarantine_for(app_local_data, &source);
        let name = source.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_else(|| "item".into());
        let mut slot = root.join(format!("{batch}-{index}"));
        let mut attempt = 1;
        while slot.exists() {
            slot = root.join(format!("{batch}-{index}-{attempt}"));
            attempt += 1;
        }
        let destination = slot.join(&name);
        // A plain-text note next to each item keeps it recoverable even without the database.
        let secured = (|| -> Result<_, String> {
            let source_guards = guard_parents(&source)?;
            ensure_no_links(&source, false)?;
            let root_guards = guard_parents(&root.join("pending"))?;
            ensure_no_links(&root, true)?;
            fs::create_dir_all(&slot).map_err(|error| format!("Quarantine could not be created: {}", describe_io_error(&error)))?;
            let destination_guards = guard_parents(&destination)?;
            ensure_no_links(&slot, false)?;
            Ok((source_guards, root_guards, destination_guards))
        })();
        let _guards = match secured {
            Ok(guards) => guards,
            Err(message) => {
                outcome.failed_count += 1;
                outcome.items.push(ExecutedItem { path: item.path.clone(), moved: false, message, quarantine_id: None, size_bytes: item.size_bytes });
                continue;
            }
        };
        let result = fs::create_dir_all(&slot)
            .and_then(|_| fs::write(recovery_note(&slot, &name), format!("{}\r\n", item.path)))
            .and_then(|_| fs::rename(&source, &destination));
        match result {
            Ok(()) => {
                let record = QuarantineItem {
                    id: 0,
                    original_path: item.path.clone(),
                    quarantine_path: destination.to_string_lossy().into_owned(),
                    size_bytes: item.size_bytes,
                    file_count: item.file_count,
                    created_at_unix: storage::now_unix(),
                    owner: item.owner.clone(),
                    reason: item.reason.clone(),
                    item_kind: if matches!(item.item_kind.as_str(), "shortcut" | "file") { item.item_kind.clone() } else { "directory".into() },
                    status: "quarantined".into(),
                    updated_at_unix: storage::now_unix(),
                };
                match storage::insert_quarantine(&conn, &record) {
                    Ok(id) => {
                        storage::record_action(&conn, "quarantine", &item.path, "moved", &record.quarantine_path);
                        logging::info(app_local_data, &format!("quarantined {} ({} bytes)", item.path, item.size_bytes));
                        outcome.moved_count += 1;
                        outcome.moved_bytes += item.size_bytes;
                        outcome.items.push(ExecutedItem { path: item.path.clone(), moved: true, message: "Moved to quarantine.".into(), quarantine_id: Some(id), size_bytes: item.size_bytes });
                    }
                    Err(error) => {
                        // Keep the data recoverable: move it back if the record could not be written.
                        let restored = fs::rename(&destination, &source).is_ok();
                        if restored { let _ = fs::remove_file(recovery_note(&slot, &name)); let _ = fs::remove_dir(&slot); }
                        outcome.failed_count += 1;
                        outcome.items.push(ExecutedItem { path: item.path.clone(), moved: false, message: format!("Quarantine record failed ({error}); {}.", if restored { "the item was put back" } else { "the item remains in the quarantine folder" }), quarantine_id: None, size_bytes: item.size_bytes });
                    }
                }
            }
            Err(error) => {
                let _ = fs::remove_file(recovery_note(&slot, &name));
                let _ = fs::remove_dir(&slot);
                let message = describe_io_error(&error);
                storage::record_action(&conn, "quarantine", &item.path, "failed", &message);
                logging::warn(app_local_data, &format!("quarantine failed for {}: {message}", item.path));
                outcome.failed_count += 1;
                outcome.items.push(ExecutedItem { path: item.path.clone(), moved: false, message, quarantine_id: None, size_bytes: item.size_bytes });
            }
        }
        drop(_guards);
        if !destination.exists() {
            let _ = fs::remove_file(recovery_note(&slot, &name));
            let _ = fs::remove_dir(&slot);
        }
    }
    // Children that were only skipped because an ancestor was selected must report
    // failure when that ancestor did not move.
    for item in plan.items.iter().filter(|item| item.status == "redundant") {
        let covered = outcome.items.iter().any(|done| done.moved && path_is_within(&item.path, &done.path));
        if !covered {
            outcome.failed_count += 1;
            outcome.items.push(ExecutedItem { path: item.path.clone(), moved: false, message: "Not moved: its containing folder was not moved.".into(), quarantine_id: None, size_bytes: 0 });
        }
    }
    Ok(outcome)
}

#[cfg(test)]
fn within_quarantine(app_local_data: &Path, path: &str) -> bool {
    if Path::new(path).components().any(|component| matches!(component, Component::ParentDir | Component::CurDir)) {
        return false;
    }
    let root = quarantine_root(app_local_data);
    path_is_within(path, &root.to_string_lossy()) && !path.trim_end_matches('\\').eq_ignore_ascii_case(root.to_string_lossy().trim_end_matches('\\'))
}

fn validate_quarantine_item(app_local_data: &Path, item: &QuarantineItem) -> Result<PathBuf, String> {
    let original = validate_shape(&item.original_path)?;
    let path = validate_shape(&item.quarantine_path)?;
    let root = quarantine_for(app_local_data, &original);
    // A record must describe exactly root/slot/original-name, never the root or
    // an arbitrary deeper tree. Resolve containment after checking every ancestor.
    if path.parent().and_then(Path::parent) != Some(root.as_path()) || path.file_name() != original.file_name() {
        return Err("The recorded path is outside its managed quarantine slot; refusing the operation.".into());
    }
    ensure_no_links(&path, true)?;
    if path.exists() {
        let resolved = fs::canonicalize(&path).map_err(|error| describe_io_error(&error))?;
        let resolved_root = fs::canonicalize(&root).map_err(|error| describe_io_error(&error))?;
        if !path_is_within(&resolved.to_string_lossy(), &resolved_root.to_string_lossy()) {
            return Err("The quarantine path resolves outside quarantine.".into());
        }
    }
    Ok(path)
}

pub fn restore(app_local_data: &Path, id: i64) -> Result<QuarantineItem, String> {
    let conn = storage::open_db(&database(app_local_data))?;
    let item = storage::get_quarantine(&conn, id)?.ok_or("Quarantine item not found.")?;
    if item.status != "quarantined" { return Err("This item is no longer in quarantine.".into()); }
    let _quarantine_guards = guard_parents(Path::new(&item.quarantine_path))?;
    validate_quarantine_item(app_local_data, &item)?;
    let original = validate_shape(&item.original_path)?;
    let _original_guards = guard_parents(&original)?;
    ensure_no_links(&original, true)?;
    if fs::symlink_metadata(&original).is_ok() {
        return Err("Something already exists at the original location. Move it away first, then restore.".into());
    }
    if let Some(parent) = original.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("The original parent folder could not be recreated: {}", describe_io_error(&error)))?;
    }
    let _created_parent_guards = guard_parents(&original)?;
    ensure_no_links(&original, true)?;
    validate_quarantine_item(app_local_data, &item)?;
    fs::rename(&item.quarantine_path, &original).map_err(|error| format!("Restore failed: {}", describe_io_error(&error)))?;
    drop(_created_parent_guards);
    drop(_original_guards);
    drop(_quarantine_guards);
    if let Some(slot) = Path::new(&item.quarantine_path).parent() {
        let _ = fs::remove_file(recovery_note(slot, Path::new(&item.quarantine_path).file_name().unwrap().to_string_lossy().as_ref()));
        let _ = fs::remove_dir(slot);
    }
    storage::set_quarantine_status(&conn, id, "restored")?;
    storage::restore_cleaned_path(&conn, &item.original_path)?;
    storage::record_action(&conn, "restore", &item.original_path, "restored", "");
    logging::info(app_local_data, &format!("restored {}", item.original_path));
    Ok(QuarantineItem { status: "restored".into(), ..item })
}

/// Deletes a tree without following reparse points, clearing read-only attributes
/// on regular files first. Links (junctions, symlinks) are removed as links.
fn remove_tree(path: &Path) -> std::io::Result<()> {
    remove_tree_at(path, 0)
}

#[cfg(windows)]
fn is_directory_entry(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x10 != 0
}

#[cfg(not(windows))]
fn is_directory_entry(metadata: &fs::Metadata) -> bool {
    metadata.is_dir()
}

fn remove_tree_at(path: &Path, depth: usize) -> std::io::Result<()> {
    if depth > 256 {
        return Err(std::io::Error::other("folder nesting is too deep to delete safely"));
    }
    let metadata = fs::symlink_metadata(path)?;
    if cleaner_core_reparse(&metadata) {
        // Remove the link itself, never its target.
        return if is_directory_entry(&metadata) { fs::remove_dir(path) } else { fs::remove_file(path) };
    }
    if metadata.is_dir() {
        let guards = guard_parents(&path.join("child")).map_err(std::io::Error::other)?;
        for entry in fs::read_dir(path)? {
            remove_tree_at(&entry?.path(), depth + 1)?;
        }
        drop(guards);
        return fs::remove_dir(path);
    }
    let mut permissions = metadata.permissions();
    if permissions.readonly() {
        #[allow(clippy::permissions_set_readonly_false)]
        permissions.set_readonly(false);
        let _ = fs::set_permissions(path, permissions);
    }
    fs::remove_file(path)
}

pub fn purge(app_local_data: &Path, id: i64) -> Result<QuarantineItem, String> {
    let conn = storage::open_db(&database(app_local_data))?;
    let item = storage::get_quarantine(&conn, id)?.ok_or("Quarantine item not found.")?;
    if item.status != "quarantined" { return Err("This item is no longer in quarantine.".into()); }
    purge_item(app_local_data, &conn, &item)?;
    Ok(QuarantineItem { status: "purged".into(), ..item })
}

fn purge_item(app_local_data: &Path, conn: &rusqlite::Connection, item: &QuarantineItem) -> Result<(), String> {
    let _guards = guard_parents(Path::new(&item.quarantine_path))?;
    let path = validate_quarantine_item(app_local_data, item)?;
    match remove_tree(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("Permanent deletion failed: {}", describe_io_error(&error))),
    }
    drop(_guards);
    if let Some(slot) = path.parent() {
        let _ = fs::remove_file(recovery_note(slot, path.file_name().unwrap().to_string_lossy().as_ref()));
        let _ = fs::remove_dir(slot);
    }
    storage::set_quarantine_status(conn, item.id, "purged")?;
    storage::record_action(conn, "purge", &item.original_path, "purged", "");
    logging::info(app_local_data, &format!("permanently deleted quarantined {}", item.original_path));
    Ok(())
}

/// Lists quarantine and permanently deletes items older than the retention period.
pub fn report(app_local_data: &Path) -> Result<QuarantineReport, String> {
    let database = database(app_local_data);
    let settings = storage::load_settings(&database)?;
    let conn = storage::open_db(&database)?;
    let mut expired_purged = 0;
    if settings.quarantine_retention_days > 0 {
        let cutoff = storage::now_unix().saturating_sub(u64::from(settings.quarantine_retention_days) * 86_400);
        for item in storage::list_quarantine(&conn, false)? {
            if item.created_at_unix < cutoff && purge_item(app_local_data, &conn, &item).is_ok() {
                expired_purged += 1;
            }
        }
    }
    let items = storage::list_quarantine(&conn, false)?;
    let history = storage::list_quarantine(&conn, true)?.into_iter().filter(|item| item.status != "quarantined").take(50).collect();
    Ok(QuarantineReport {
        total_bytes: items.iter().map(|item| item.size_bytes).sum(),
        items,
        history,
        retention_days: settings.quarantine_retention_days,
        quarantine_directory: quarantine_root(app_local_data).to_string_lossy().into_owned(),
        expired_purged,
    })
}

pub fn quarantined_paths(app_local_data: &Path) -> Vec<String> {
    storage::open_db(&database(app_local_data))
        .and_then(|conn| storage::cleaned_paths(&conn))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cleaner_core::{ContentItem, ContentProfile, Inventory, ScanSummary};

    fn temp(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("orphan-cleaner-cleanup-{name}-{}-{}", std::process::id(), storage::now_unix()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn scan_with(path: &Path) -> SavedScan {
        let mut result = DirectoryResult {
            path: path.to_string_lossy().into_owned(), root: "Roaming".into(), orphan_status: "probable_orphan".into(),
            ownership: "historical_confirmed".into(), owner_hint: Some("OldGame".into()),
            content: ContentProfile { items: vec![ContentItem { name: "Cache".into(), is_directory: true, kind: "cache".into(), safety: "safe".into(), ..Default::default() }], ..Default::default() },
            ..Default::default()
        };
        result.assessment = cleaner_core::assess(&result, 0);
        SavedScan { captured_at_unix: 1, inventory: Inventory::default(), summary: ScanSummary::default(), results: vec![result], references: Default::default() }
    }

    fn reviewed_request(app_data: &Path, scan: Option<&SavedScan>, paths: Vec<String>, acknowledge_warnings: bool, options: &PlanOptions<'_>) -> CleanupRequest {
        let preview = plan(app_data, scan, &paths, &[], options);
        CleanupRequest { paths, acknowledge_warnings, manual_cleanup: options.manual_cleanup, plan_token: preview.plan_token }
    }

    #[test]
    fn plan_refuses_paths_not_in_scan_and_protected_locations() {
        let base = temp("plan");
        let app_data = base.join("AppData");
        let target = base.join("Roaming").join("OldGame");
        fs::create_dir_all(target.join("Cache")).unwrap();
        fs::write(target.join("Cache").join("x.bin"), vec![0u8; 10]).unwrap();
        let scan = scan_with(&target);
        let other = base.join("Roaming").join("Other").to_string_lossy().into_owned();
        let own = app_data.join("x").to_string_lossy().into_owned();
        let plan = plan(&app_data, Some(&scan), &[target.to_string_lossy().into_owned(), other, own, r"C:\".into()], &[], &Default::default());
        assert_eq!(plan.items[0].status, "ready", "{:?}", plan.items[0].messages);
        assert!(plan.items[1..].iter().all(|item| item.status == "blocked"), "{:?}", plan.items);
        assert_eq!(plan.items[0].size_bytes, 10);
        assert!(plan.items[1..].iter().all(|item| item.status == "blocked"));
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn plan_blocks_personal_folder_and_its_content_even_from_a_saved_scan() {
        let base = temp("personal");
        let app_data = base.join("AppData");
        let target = base.join("Downloads").join("Old installer");
        fs::create_dir_all(target.join("Cache")).unwrap();
        let mut scan = scan_with(&target);
        let result = &mut scan.results[0];
        result.root = "Downloads".into();
        result.location_class = Some("user_data".into());
        result.orphan_status = "user_files".into();
        result.evidence.push(cleaner_core::Evidence { kind: "personal_location".into(), ..Default::default() });
        result.assessment = cleaner_core::assess(result, 0);
        let paths = [target.to_string_lossy().into_owned(), target.join("Cache").to_string_lossy().into_owned()];
        let preview = plan(&app_data, Some(&scan), &paths, &[], &Default::default());
        assert!(preview.items.iter().all(|item| item.status == "blocked"));
        let options = PlanOptions { manual_cleanup: true, ..Default::default() };
        let manual = plan(&app_data, Some(&scan), &paths, &[], &options);
        assert_eq!(manual.items[0].status, "warning");
        let request = reviewed_request(&app_data, Some(&scan), paths.clone().into(), false, &options);
        assert_eq!(execute(&app_data, Some(&scan), &request, &[], &options).unwrap().moved_count, 0);
        let request = reviewed_request(&app_data, Some(&scan), paths.into(), true, &options);
        let outcome = execute(&app_data, Some(&scan), &request, &[], &options).unwrap();
        assert_eq!(outcome.moved_count, 1);
        restore(&app_data, outcome.items[0].quarantine_id.unwrap()).unwrap();
        assert!(target.join("Cache").is_dir());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn quarantine_restore_and_purge_round_trip() {
        let base = temp("roundtrip");
        let app_data = base.join("AppData");
        let target = base.join("Roaming").join("OldGame");
        fs::create_dir_all(target.join("Cache")).unwrap();
        fs::write(target.join("Cache").join("x.bin"), vec![0u8; 10]).unwrap();
        let scan = scan_with(&target);
        let target_text = target.to_string_lossy().into_owned();
        // Content child is planned as content; parent+child selection marks child redundant.
        let child = target.join("Cache").to_string_lossy().into_owned();
        let preview = plan(&app_data, Some(&scan), &[target_text.clone(), child], &[], &Default::default());
        assert_eq!(preview.items[1].status, "redundant");
        let request = reviewed_request(&app_data, Some(&scan), vec![target_text.clone()], false, &Default::default());
        let outcome = execute(&app_data, Some(&scan), &request, &[], &Default::default()).unwrap();
        assert_eq!(outcome.moved_count, 1, "{:?}", outcome.items);
        assert!(!target.exists());
        let id = outcome.items[0].quarantine_id.unwrap();
        assert_eq!(quarantined_paths(&app_data), vec![target_text.clone()]);
        restore(&app_data, id).unwrap();
        assert!(target.join("Cache").join("x.bin").exists());
        let request = reviewed_request(&app_data, Some(&scan), vec![target_text.clone()], false, &Default::default());
        let outcome = execute(&app_data, Some(&scan), &request, &[], &Default::default()).unwrap();
        let id = outcome.items[0].quarantine_id.unwrap();
        let purged = purge(&app_data, id).unwrap();
        assert!(!Path::new(&purged.quarantine_path).exists());
        assert_eq!(quarantined_paths(&app_data), vec![target_text]);
        assert!(purge(&app_data, id).is_err());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn warnings_require_acknowledgement() {
        let base = temp("warn");
        let app_data = base.join("AppData");
        let target = base.join("Roaming").join("Keep");
        fs::create_dir_all(&target).unwrap();
        let mut scan = scan_with(&target);
        scan.results[0].assessment.deletion_safety = "preserve".into();
        let paths = vec![target.to_string_lossy().into_owned()];
        let request = reviewed_request(&app_data, Some(&scan), paths.clone(), false, &Default::default());
        let outcome = execute(&app_data, Some(&scan), &request, &[], &Default::default()).unwrap();
        assert_eq!(outcome.moved_count, 0);
        assert!(target.exists());
        let request = reviewed_request(&app_data, Some(&scan), paths, true, &Default::default());
        let outcome = execute(&app_data, Some(&scan), &request, &[], &Default::default()).unwrap();
        assert_eq!(outcome.moved_count, 1);
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn ignore_rules_and_dot_paths_are_refused() {
        let base = temp("rules");
        let app_data = base.join("AppData");
        let target = base.join("Roaming").join("OldGame");
        fs::create_dir_all(target.join("Cache")).unwrap();
        let scan = scan_with(&target);
        let target_text = target.to_string_lossy().into_owned();
        let ignored = vec![storage::IgnoreRule { id: 1, kind: "path".into(), value: target.join("Cache").display().to_string(), label: "Cache".into(), created_at_unix: 0, scan_at_unix: None }];
        let preview = plan(&app_data, Some(&scan), &[target_text], &[], &PlanOptions { rules: &ignored, ..Default::default() });
        assert_eq!(preview.items[0].status, "blocked", "a folder containing an ignored path cannot be moved");
        let sneaky = format!(r"{}\x\..\..\Roaming", quarantine_root(&app_data).display());
        assert!(!within_quarantine(&app_data, &sneaky));
        assert!(validate_shape(r"C:\Games").is_ok());
        assert!(validate_shape(r"C:\Games.").is_err());
        assert!(validate_shape(r"C:\Games\file:stream").is_err());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn changed_content_requires_a_new_review_and_preserve_warning() {
        let base = temp("changed-content");
        let data = base.join("AppData");
        let target = base.join("Roaming/OldGame");
        fs::create_dir_all(target.join("Cache")).unwrap();
        fs::write(target.join("Cache/cache.bin"), [0u8; 10]).unwrap();
        let scan = scan_with(&target);
        let paths = vec![target.display().to_string()];
        let reviewed = reviewed_request(&data, Some(&scan), paths.clone(), false, &Default::default());
        fs::write(target.join("Cache/progress.sav"), "irreplaceable game progress").unwrap();
        assert!(execute(&data, Some(&scan), &reviewed, &[], &Default::default()).unwrap_err().contains("changed"));
        assert!(target.exists());
        let preview = plan(&data, Some(&scan), &paths, &[], &Default::default());
        assert_eq!(preview.items[0].safety, "preserve");
        assert_eq!(preview.items[0].status, "warning");
        let child = plan(&data, Some(&scan), &[target.join("Cache").display().to_string()], &[], &Default::default());
        assert_eq!(child.items[0].safety, "preserve");
        let denied = reviewed_request(&data, Some(&scan), paths.clone(), false, &Default::default());
        assert_eq!(execute(&data, Some(&scan), &denied, &[], &Default::default()).unwrap().moved_count, 0);
        let acknowledged = reviewed_request(&data, Some(&scan), paths, true, &Default::default());
        let moved = execute(&data, Some(&scan), &acknowledged, &[], &Default::default()).unwrap();
        assert_eq!(moved.moved_count, 1);
        restore(&data, moved.items[0].quarantine_id.unwrap()).unwrap();
        assert_eq!(fs::read_to_string(target.join("Cache/progress.sav")).unwrap(), "irreplaceable game progress");
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn keep_rules_are_enforced_and_manual_override_is_per_operation() {
        let base = temp("keep-categories");
        let data = base.join("AppData");
        let target = base.join("Roaming/OldGame");
        fs::create_dir_all(target.join("Cache")).unwrap();
        let scan = scan_with(&target);
        for (kind, value) in [("application", "OldGame"), ("category", "cache"), ("path", target.to_str().unwrap())] {
            let rules = [storage::IgnoreRule { id: 1, kind: kind.into(), value: value.into(), label: "Keep".into(), created_at_unix: 0, scan_at_unix: None }];
            let paths = vec![target.display().to_string(), target.join("Cache").display().to_string()];
            let options = PlanOptions { rules: &rules, ..Default::default() };
            assert!(plan(&data, Some(&scan), &paths, &[], &options).items.iter().all(|item| item.status == "blocked"));
            let manual = PlanOptions { manual_cleanup: true, ..options };
            let preview = plan(&data, Some(&scan), &paths, &[], &manual);
            assert_eq!(preview.items[0].status, "warning");
            assert!(preview.items[0].messages.iter().any(|message| message.contains("keep rule")));
            let request = reviewed_request(&data, Some(&scan), paths, true, &manual);
            let moved = execute(&data, Some(&scan), &request, &[], &manual).unwrap();
            assert_eq!(moved.moved_count, 1);
            restore(&data, moved.items[0].quarantine_id.unwrap()).unwrap();
            assert_eq!(rules[0].kind, kind);
        }
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn manual_cleanup_accepts_unscanned_files_and_system_classifications() {
        let base = temp("manual");
        let data = base.join("AppData");
        let target = base.join("Personal/ORIGINAL_PATH.txt");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, "personal file").unwrap();
        let options = PlanOptions { manual_cleanup: true, ..Default::default() };
        let paths = vec![target.display().to_string()];
        let request = reviewed_request(&data, None, paths, true, &options);
        let moved = execute(&data, None, &request, &[], &options).unwrap();
        assert_eq!(moved.moved_count, 1);
        let record = restore(&data, moved.items[0].quarantine_id.unwrap()).unwrap();
        assert_eq!(record.item_kind, "file");
        assert_eq!(fs::read_to_string(&target).unwrap(), "personal file");
        let mut scan = scan_with(target.parent().unwrap());
        scan.results[0].location_class = Some("system".into());
        let system = plan(&data, Some(&scan), &[target.parent().unwrap().display().to_string()], &[], &options);
        assert_eq!(system.items[0].status, "warning");
        let own = plan(&data, None, &[data.display().to_string(), r"C:\".into()], &[], &options);
        assert!(own.items.iter().all(|item| item.status == "blocked"));
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn category_keep_rules_include_contents_hidden_by_display_grouping() {
        let base = temp("hidden-categories");
        let data = base.join("AppData");
        let target = base.join("Roaming/OldGame");
        for index in 0..45 {
            let folder = target.join(format!("Cache{index}"));
            fs::create_dir_all(&folder).unwrap();
            fs::write(folder.join("cache.log"), [0u8; 100]).unwrap();
        }
        fs::create_dir_all(target.join("TinySaves")).unwrap();
        fs::write(target.join("TinySaves/progress.sav"), [1u8]).unwrap();
        let measured = cleaner_core::inspect_directory(&target, &std::sync::atomic::AtomicBool::new(false));
        assert!(measured.content.categories.iter().any(|kind| kind == "save_game"));
        assert!(!measured.content.items.iter().any(|item| item.kind == "save_game"), "the small save folder should be grouped out of the displayed items");
        let scan = scan_with(&target);
        let rules = [storage::IgnoreRule { id: 1, kind: "category".into(), value: "save_game".into(), label: "Keep saves".into(), created_at_unix: 0, scan_at_unix: None }];
        let options = PlanOptions { rules: &rules, ..Default::default() };
        let paths = [target.display().to_string()];
        assert_eq!(plan(&data, Some(&scan), &paths, &[], &options).items[0].status, "blocked");
        let manual = PlanOptions { manual_cleanup: true, ..options };
        assert_eq!(plan(&data, Some(&scan), &paths, &[], &manual).items[0].status, "warning");
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn subfolder_ownership_is_revalidated_and_review_tokens_bind_manual_mode() {
        let base = temp("current-owner");
        let data = base.join("AppData");
        let target = base.join("Roaming/OldGame");
        fs::create_dir_all(target.join("Cache")).unwrap();
        let scan = scan_with(&target);
        let apps = [Application { id: "app".into(), name: "OldGame".into(), install_location: Some(target.display().to_string()), ..Default::default() }];
        let paths = vec![target.join("Cache").display().to_string()];
        assert_eq!(plan(&data, Some(&scan), &paths, &apps, &Default::default()).items[0].status, "blocked");
        let manual = PlanOptions { manual_cleanup: true, ..Default::default() };
        assert_eq!(plan(&data, Some(&scan), &paths, &apps, &manual).items[0].status, "warning");
        let mut request = reviewed_request(&data, Some(&scan), paths, false, &Default::default());
        request.manual_cleanup = true;
        assert!(execute(&data, Some(&scan), &request, &[], &manual).is_err());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn cross_drive_quarantine_namespaces_are_stable_and_volume_local() {
        let data = Path::new(r"C:\Users\Test\AppData\Local\dev.orphancleaner.desktop");
        assert_eq!(quarantine_for(data, Path::new(r"C:\Folder\file.txt")), quarantine_root(data));
        let other = quarantine_for(data, Path::new(r"D:\Folder\file.txt"));
        assert_eq!(volume_key(&other), volume_key(Path::new(r"D:\Folder")));
        assert_eq!(other, quarantine_for(data, Path::new(r"D:\Other")));
        assert_ne!(other, quarantine_for(Path::new(r"C:\Users\Other\AppData\Local\dev.orphancleaner.desktop"), Path::new(r"D:\Other")));
    }

    #[cfg(windows)]
    fn junction(link: &Path, target: &Path) {
        assert!(link.starts_with(std::env::temp_dir()));
        assert!(target.starts_with(std::env::temp_dir()));
        let command = format!("New-Item -ItemType Junction -Path '{}' -Target '{}' | Out-Null", link.display().to_string().replace('\'', "''"), target.display().to_string().replace('\'', "''"));
        assert!(std::process::Command::new("powershell.exe").args(["-NoProfile", "-NonInteractive", "-Command", &command]).status().unwrap().success());
    }

    #[cfg(windows)]
    #[test]
    fn quarantine_and_restore_refuse_junction_ancestors_and_keep_external_files() {
        let base = temp("junctions");
        let data = base.join("AppData");
        let target = base.join("Roaming/OldGame");
        fs::create_dir_all(target.join("Cache")).unwrap();
        fs::write(target.join("Cache/x.bin"), [0u8; 10]).unwrap();
        let scan = scan_with(&target);
        let request = reviewed_request(&data, Some(&scan), vec![target.display().to_string()], false, &Default::default());
        let outcome = execute(&data, Some(&scan), &request, &[], &Default::default()).unwrap();
        let id = outcome.items[0].quarantine_id.unwrap();
        let conn = storage::open_db(&database(&data)).unwrap();
        let item = storage::get_quarantine(&conn, id).unwrap().unwrap();
        let slot = Path::new(&item.quarantine_path).parent().unwrap();
        let outside = base.join("OutsideQuarantine");
        fs::rename(slot, &outside).unwrap();
        fs::write(outside.join("OldGame/valuable.txt"), "must survive").unwrap();
        junction(slot, &outside);
        assert!(purge(&data, id).is_err());
        assert!(restore(&data, id).is_err());
        assert_eq!(fs::read_to_string(outside.join("OldGame/valuable.txt")).unwrap(), "must survive");
        fs::remove_dir(slot).unwrap();
        fs::rename(&outside, slot).unwrap();
        let redirected = base.join("RedirectedOriginal");
        fs::create_dir(&redirected).unwrap();
        fs::remove_dir(target.parent().unwrap()).unwrap();
        junction(target.parent().unwrap(), &redirected);
        assert!(restore(&data, id).is_err());
        assert!(!redirected.join("OldGame").exists());
        fs::remove_dir(target.parent().unwrap()).unwrap();
        restore(&data, id).unwrap();
        assert!(target.join("Cache/x.bin").exists());
        drop(conn);
        fs::remove_dir_all(base).unwrap();
    }
}
