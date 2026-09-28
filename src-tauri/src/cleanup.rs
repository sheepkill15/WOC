//! Cleanup plans and quarantine (spec §26–27).
//!
//! Only paths that were displayed in the latest saved scan can be planned.
//! Every plan revalidates existence, reparse points, protected locations and
//! current ownership. Execution moves items into a quarantine folder on the
//! same volume with a single rename; nothing is deleted except by an explicit
//! purge (or retention expiry) of a quarantined item.

use cleaner_core::references::path_is_within;
use cleaner_core::{Application, DirectoryResult, content};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::storage::{self, QuarantineItem, SavedScan};
use crate::logging;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanupRequest {
    pub paths: Vec<String>,
    /// Required to execute items whose plan status is "warning".
    #[serde(default)]
    pub acknowledge_warnings: bool,
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

fn volume_key(path: &Path) -> Option<String> {
    match path.components().next()? {
        Component::Prefix(prefix) => Some(prefix.as_os_str().to_string_lossy().to_ascii_lowercase()),
        _ => None,
    }
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
    // Prefix + root + at least two names: refuses drive roots and top-level folders such as C:\\Games.
    if candidate.components().count() < 4 { return Err("Drive roots and top-level folders are refused.".into()); }
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

fn locate<'a>(scan: &'a SavedScan, path: &str) -> Option<Located<'a>> {
    if let Some(result) = scan.results.iter().find(|result| result.path.eq_ignore_ascii_case(path)) {
        return Some(Located::Directory(result));
    }
    let candidate = Path::new(path);
    let parent = candidate.parent()?.to_string_lossy().into_owned();
    let name = candidate.file_name()?.to_string_lossy().into_owned();
    if let Some(result) = scan.results.iter().find(|result| result.path.eq_ignore_ascii_case(&parent)) {
        if let Some(item) = result.content.items.iter().find(|item| item.is_directory && item.name.eq_ignore_ascii_case(&name)) {
            return Some(Located::Content(result, item));
        }
    }
    scan.references.references.iter()
        .find(|reference| reference.file_backed && reference.location.eq_ignore_ascii_case(path))
        .map(Located::Shortcut)
}

fn measure(path: &Path) -> (u64, u64) {
    if path.is_file() {
        return (fs::metadata(path).map(|metadata| metadata.len()).unwrap_or(0), 1);
    }
    let stats = cleaner_core::inspect_directory(path, &std::sync::atomic::AtomicBool::new(false));
    (stats.size, stats.files)
}

/// Builds a revalidated plan. `current_apps` is the freshly read inventory.
pub fn plan(app_local_data: &Path, scan: Option<&SavedScan>, paths: &[String], current_apps: &[Application], ignored: &[String]) -> CleanupPlan {
    let quarantine = quarantine_root(app_local_data);
    let quarantine_volume = volume_key(&quarantine);
    let mut items: Vec<PlanItem> = Vec::new();
    let mut unique: Vec<String> = Vec::new();
    for path in paths {
        let trimmed = path.trim().trim_end_matches('\\').to_owned();
        if !trimmed.is_empty() && !unique.iter().any(|existing| existing.eq_ignore_ascii_case(&trimmed)) {
            unique.push(trimmed);
        }
    }
    for path in &unique {
        let mut item = PlanItem {
            path: path.clone(), item_kind: "directory".into(), size_bytes: 0, file_count: 0,
            status: "ready".into(), messages: Vec::new(), owner: None, safety: content::UNKNOWN.into(), reason: String::new(),
        };
        let block = |item: &mut PlanItem, message: String| { item.status = "blocked".into(); item.messages.push(message); };
        let warn = |item: &mut PlanItem, message: String| { if item.status == "ready" { item.status = "warning".into(); } item.messages.push(message); };

        let shape = validate_shape(path);
        let Ok(candidate) = shape else { block(&mut item, shape.unwrap_err()); items.push(item); continue; };
        if let Some(message) = is_protected(path, app_local_data) { block(&mut item, message); items.push(item); continue; }
        if let Some(rule) = ignored.iter().find(|rule| path_is_within(path, rule) || path_is_within(rule, path)) {
            block(&mut item, format!("An ignore rule keeps {rule}; remove the rule first if you want to clean it."));
            items.push(item);
            continue;
        }
        let Some(scan) = scan else { block(&mut item, "No saved scan is available.".into()); items.push(item); continue; };
        match locate(scan, path) {
            None => block(&mut item, "This path was not shown in the latest scan, so it cannot be cleaned.".into()),
            Some(Located::Directory(result)) => {
                item.owner = result.owner.as_ref().map(|owner| owner.name.clone()).or_else(|| result.owner_hint.clone());
                item.safety = result.assessment.deletion_safety.clone();
                item.reason = format!("{} ({})", result.orphan_status, result.assessment.orphan_confidence);
                if matches!(result.location_class.as_deref(), Some("system" | "shared_runtime")) {
                    block(&mut item, "Windows or a shared runtime manages this location.".into());
                }
                // Revalidate ownership against the current inventory.
                let current = cleaner_core::classify_directory(&candidate, &result.root, current_apps);
                if current.orphan_status == "not_orphaned" {
                    let name = current.owner.as_ref().map(|owner| owner.name.as_str()).unwrap_or("an installed application");
                    if matches!(result.orphan_status.as_str(), "probable_orphan" | "possibly_orphaned" | "unknown" | "unregistered_application") {
                        block(&mut item, format!("This folder now matches {name}, which is currently installed."));
                    } else {
                        warn(&mut item, format!("{name} is installed and uses this folder. Removing it resets or breaks the application."));
                    }
                } else if matches!(result.orphan_status.as_str(), "not_orphaned" | "associated_with_installed" | "referenced_by_system" | "known_application_data") {
                    warn(&mut item, "This folder is linked to installed software or Windows components.".into());
                }
                if result.evidence.iter().any(|evidence| evidence.kind == "active_reference") {
                    warn(&mut item, "A startup entry, task, service or shortcut still uses files in this folder.".into());
                }
                match result.assessment.deletion_safety.as_str() {
                    content::PRESERVE => warn(&mut item, "Contains data classified as worth preserving (saves, projects, documents or media).".into()),
                    content::REVIEW | content::UNKNOWN => warn(&mut item, "Contains data that should be reviewed (settings, state or unclassified files).".into()),
                    _ => {}
                }
                if result.orphan_status == "unknown" {
                    warn(&mut item, "No owner was identified. Unknown does not mean unnecessary.".into());
                }
            }
            Some(Located::Content(result, content_item)) => {
                item.item_kind = "content".into();
                item.owner = result.owner.as_ref().map(|owner| owner.name.clone()).or_else(|| result.owner_hint.clone());
                item.safety = content_item.safety.clone();
                item.reason = format!("{} inside {}", content::kind_label(&content_item.kind), result.path);
                if matches!(result.location_class.as_deref(), Some("system" | "shared_runtime")) {
                    block(&mut item, "Windows or a shared runtime manages the containing location.".into());
                }
                if !matches!(content_item.safety.as_str(), content::SAFE | content::LIKELY_SAFE) {
                    warn(&mut item, format!("Classified as {} ({}); review before removing.", content::kind_label(&content_item.kind).to_lowercase(), content_item.safety.replace('_', " ")));
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
                if !allowed { block(&mut item, "Only shortcuts in Start Menu or Startup folders can be cleaned.".into()); }
                let target_exists = reference.target_path.as_deref().is_some_and(|target| Path::new(target).exists());
                if target_exists { block(&mut item, "The shortcut target exists again; it is no longer a dead reference.".into()); }
            }
        }
        if item.status != "blocked" {
            match fs::symlink_metadata(&candidate) {
                Err(_) => block(&mut item, "The path no longer exists.".into()),
                Ok(metadata) if cleaner_core_reparse(&metadata) => block(&mut item, "Links, junctions and other reparse points are never followed or moved.".into()),
                Ok(_) if ancestor_link(&candidate).is_some() => block(&mut item, format!("A folder above this path ({}) is a link or junction; the path is refused.", ancestor_link(&candidate).map(|link| link.display().to_string()).unwrap_or_default())),
                Ok(metadata) => {
                    if item.item_kind == "shortcut" && !metadata.is_file() { block(&mut item, "Expected a shortcut file.".into()); }
                    if item.item_kind != "shortcut" && !metadata.is_dir() { block(&mut item, "Expected a folder.".into()); }
                }
            }
        }
        if item.status != "blocked" && volume_key(&candidate) != quarantine_volume {
            block(&mut item, "The item is on a different drive than the quarantine folder; moving it would require copying, so it is refused.".into());
        }
        if item.status != "blocked" {
            let (size, files) = measure(&candidate);
            item.size_bytes = size;
            item.file_count = files;
        }
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
    CleanupPlan {
        ready_count: items.iter().filter(|item| item.status == "ready").count(),
        warning_count: items.iter().filter(|item| item.status == "warning").count(),
        blocked_count: items.iter().filter(|item| item.status == "blocked").count(),
        items,
        total_bytes,
        quarantine_directory: quarantine.to_string_lossy().into_owned(),
        scan_at_unix: scan.map(|scan| scan.captured_at_unix),
    }
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

fn describe_io_error(error: &std::io::Error) -> String {
    match error.raw_os_error() {
        Some(5) => "Access denied. The location needs administrator rights, or a file inside is in use.".into(),
        Some(32) | Some(33) => "A file inside is in use by another program. Close it and try again.".into(),
        Some(17) => "The item is on a different drive than the quarantine folder.".into(),
        _ => error.to_string(),
    }
}

/// Executes a plan: re-plans, then moves each ready (and, when acknowledged, warning) item into quarantine.
pub fn execute(app_local_data: &Path, scan: Option<&SavedScan>, request: &CleanupRequest, current_apps: &[Application], ignored: &[String]) -> Result<CleanupOutcome, String> {
    let plan = plan(app_local_data, scan, &request.paths, current_apps, ignored);
    let conn = storage::open_db(&database(app_local_data))?;
    let root = quarantine_root(app_local_data);
    fs::create_dir_all(&root).map_err(|error| format!("Quarantine folder could not be created: {error}"))?;
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
        let name = source.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_else(|| "item".into());
        let mut slot = root.join(format!("{batch}-{index}"));
        let mut attempt = 1;
        while slot.exists() {
            slot = root.join(format!("{batch}-{index}-{attempt}"));
            attempt += 1;
        }
        let destination = slot.join(&name);
        // A plain-text note next to each item keeps it recoverable even without the database.
        let result = fs::create_dir_all(&slot)
            .and_then(|_| fs::write(slot.join("ORIGINAL_PATH.txt"), format!("{}\r\n", item.path)))
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
                    item_kind: if item.item_kind == "shortcut" { "shortcut".into() } else { "directory".into() },
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
                        if restored { let _ = fs::remove_file(slot.join("ORIGINAL_PATH.txt")); let _ = fs::remove_dir(&slot); }
                        outcome.failed_count += 1;
                        outcome.items.push(ExecutedItem { path: item.path.clone(), moved: false, message: format!("Quarantine record failed ({error}); {}.", if restored { "the item was put back" } else { "the item remains in the quarantine folder" }), quarantine_id: None, size_bytes: item.size_bytes });
                    }
                }
            }
            Err(error) => {
                let _ = fs::remove_file(slot.join("ORIGINAL_PATH.txt"));
                let _ = fs::remove_dir(&slot);
                let message = describe_io_error(&error);
                storage::record_action(&conn, "quarantine", &item.path, "failed", &message);
                logging::warn(app_local_data, &format!("quarantine failed for {}: {message}", item.path));
                outcome.failed_count += 1;
                outcome.items.push(ExecutedItem { path: item.path.clone(), moved: false, message, quarantine_id: None, size_bytes: item.size_bytes });
            }
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

fn within_quarantine(app_local_data: &Path, path: &str) -> bool {
    if Path::new(path).components().any(|component| matches!(component, Component::ParentDir | Component::CurDir)) {
        return false;
    }
    let root = quarantine_root(app_local_data);
    path_is_within(path, &root.to_string_lossy()) && !path.trim_end_matches('\\').eq_ignore_ascii_case(root.to_string_lossy().trim_end_matches('\\'))
}

pub fn restore(app_local_data: &Path, id: i64) -> Result<QuarantineItem, String> {
    let conn = storage::open_db(&database(app_local_data))?;
    let item = storage::get_quarantine(&conn, id)?.ok_or("Quarantine item not found.")?;
    if item.status != "quarantined" { return Err("This item is no longer in quarantine.".into()); }
    if !within_quarantine(app_local_data, &item.quarantine_path) { return Err("The recorded quarantine path is outside the quarantine folder.".into()); }
    let original = validate_shape(&item.original_path)?;
    if fs::symlink_metadata(&original).is_ok() {
        return Err("Something already exists at the original location. Move it away first, then restore.".into());
    }
    if let Some(parent) = original.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("The original parent folder could not be recreated: {}", describe_io_error(&error)))?;
    }
    fs::rename(&item.quarantine_path, &original).map_err(|error| format!("Restore failed: {}", describe_io_error(&error)))?;
    if let Some(slot) = Path::new(&item.quarantine_path).parent() {
        let _ = fs::remove_file(slot.join("ORIGINAL_PATH.txt"));
        let _ = fs::remove_dir(slot);
    }
    storage::set_quarantine_status(&conn, id, "restored")?;
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
        for entry in fs::read_dir(path)? {
            remove_tree_at(&entry?.path(), depth + 1)?;
        }
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
    if !within_quarantine(app_local_data, &item.quarantine_path) {
        return Err("The recorded quarantine path is outside the quarantine folder; refusing to delete.".into());
    }
    let path = Path::new(&item.quarantine_path);
    match remove_tree(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("Permanent deletion failed: {}", describe_io_error(&error))),
    }
    if let Some(slot) = path.parent() {
        let _ = fs::remove_file(slot.join("ORIGINAL_PATH.txt"));
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
        .and_then(|conn| storage::list_quarantine(&conn, false))
        .map(|items| items.into_iter().map(|item| item.original_path).collect())
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
        let plan = plan(&app_data, Some(&scan), &[target.to_string_lossy().into_owned(), other, own, r"C:\".into()], &[], &[]);
        assert_eq!(plan.items[0].status, "ready", "{:?}", plan.items[0].messages);
        assert!(plan.items[1..].iter().all(|item| item.status == "blocked"), "{:?}", plan.items);
        assert_eq!(plan.items[0].size_bytes, 10);
        assert!(plan.items[1..].iter().all(|item| item.status == "blocked"));
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
        let preview = plan(&app_data, Some(&scan), &[target_text.clone(), child], &[], &[]);
        assert_eq!(preview.items[1].status, "redundant");
        let outcome = execute(&app_data, Some(&scan), &CleanupRequest { paths: vec![target_text.clone()], acknowledge_warnings: false }, &[], &[]).unwrap();
        assert_eq!(outcome.moved_count, 1, "{:?}", outcome.items);
        assert!(!target.exists());
        let id = outcome.items[0].quarantine_id.unwrap();
        assert_eq!(quarantined_paths(&app_data), vec![target_text.clone()]);
        restore(&app_data, id).unwrap();
        assert!(target.join("Cache").join("x.bin").exists());
        let outcome = execute(&app_data, Some(&scan), &CleanupRequest { paths: vec![target_text], acknowledge_warnings: false }, &[], &[]).unwrap();
        let id = outcome.items[0].quarantine_id.unwrap();
        let purged = purge(&app_data, id).unwrap();
        assert!(!Path::new(&purged.quarantine_path).exists());
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
        let outcome = execute(&app_data, Some(&scan), &CleanupRequest { paths: paths.clone(), acknowledge_warnings: false }, &[], &[]).unwrap();
        assert_eq!(outcome.moved_count, 0);
        assert!(target.exists());
        let outcome = execute(&app_data, Some(&scan), &CleanupRequest { paths, acknowledge_warnings: true }, &[], &[]).unwrap();
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
        let ignored = vec![target.join("Cache").to_string_lossy().into_owned()];
        let preview = plan(&app_data, Some(&scan), &[target_text], &[], &ignored);
        assert_eq!(preview.items[0].status, "blocked", "a folder containing an ignored path cannot be moved");
        let sneaky = format!(r"{}\x\..\..\Roaming", quarantine_root(&app_data).display());
        assert!(!within_quarantine(&app_data, &sneaky));
        assert!(validate_shape(r"C:\Games").is_err());
        fs::remove_dir_all(base).unwrap();
    }
}
