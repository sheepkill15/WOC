//! Bounded startup management and broken-registry-reference cleanup.
//! Reviews stay server-side; each write rechecks its original value and journals
//! the exact bytes before changing Windows. No keys or registration trees are deleted.
use std::{collections::{HashMap, HashSet}, fs, io::{Read, Write}, path::{Component, Path}, time::{SystemTime, UNIX_EPOCH}};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use serde::{Deserialize, Serialize};
use rusqlite::params;
use winreg::{RegKey, RegValue, enums::*};
use windows::{core::PCWSTR, Win32::{Foundation::HANDLE, Storage::FileSystem::{GetDriveTypeW, SetFileInformationByHandle, FileDispositionInfo, FILE_DISPOSITION_INFO}}};

const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const RUN_ONCE: &str = r"Software\Microsoft\Windows\CurrentVersion\RunOnce";
const APP_PATHS: &str = r"Software\Microsoft\Windows\CurrentVersion\App Paths";
const MAX_FILE: u64 = 1_048_576;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub location: String,
    pub command: String,
    pub target_path: Option<String>,
    pub target_status: String,
    pub startup_state: String,
    pub machine_wide: bool,
    pub owner: Option<String>,
    pub can_disable: bool,
    pub can_clean: bool,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Source {
    Registry { hive: String, view: u32, key: String, name: String, value_type: u32, bytes: Vec<u8> },
    File { path: String, bytes: Vec<u8> },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewedEntry { entry: Entry, source: Source }

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report { pub token: String, pub entries: Vec<Entry>, pub warnings: Vec<String>, pub captured_at_unix: u64 }

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Backup {
    pub id: i64, pub entry: Entry, pub action: String, pub status: String,
    pub created_at_unix: u64, pub detail: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Outcome { pub name: String, pub success: bool, pub error: Option<String> }

#[derive(Default)]
pub struct Reviews { scans: HashMap<String, Vec<ReviewedEntry>> }

impl Reviews {
    pub fn scan(&mut self) -> Report {
        let (entries, warnings) = collect();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        let token = now.as_nanos().to_string();
        if self.scans.len() >= 8 { self.scans.clear(); }
        self.scans.insert(token.clone(), entries.clone());
        Report { token, entries: entries.into_iter().map(|e| e.entry).collect(), warnings, captured_at_unix: now.as_secs() }
    }

    pub fn select(&self, token: &str, ids: &[String], action: &str) -> Result<Vec<ReviewedEntry>, String> {
        if !matches!(action, "disable" | "clean") { return Err("Unknown maintenance action.".into()); }
        if ids.is_empty() || ids.len() > 200 { return Err("Select between one and 200 entries.".into()); }
        let reviewed = self.scans.get(token).ok_or("This review has expired. Refresh the list before making changes.")?;
        let mut seen = HashSet::new();
        ids.iter().map(|id| {
            if !seen.insert(id) { return Err("An entry was selected twice.".into()); }
            let item = reviewed.iter().find(|item| &item.entry.id == id).ok_or("An entry is outside the reviewed list.")?;
            if (action == "clean" && !item.entry.can_clean) || (action == "disable" && !item.entry.can_disable) {
                return Err("The requested action is unavailable for this entry.".into());
            }
            Ok(item.clone())
        }).collect()
    }
}

fn error(e: impl std::fmt::Display) -> String { e.to_string() }
fn view_flag(view: u32) -> Result<u32, String> { match view { 32 => Ok(KEY_WOW64_32KEY), 64 => Ok(KEY_WOW64_64KEY), _ => Err("Invalid registry view.".into()) } }
fn hive(hive: &str) -> Result<RegKey, String> { match hive { "HKCU" => Ok(RegKey::predef(HKEY_CURRENT_USER)), "HKLM" => Ok(RegKey::predef(HKEY_LOCAL_MACHINE)), _ => Err("Invalid registry hive.".into()) } }

fn string_value(value: &RegValue) -> Option<String> {
    if !matches!(value.vtype, REG_SZ | REG_EXPAND_SZ) || value.bytes.len() % 2 != 0 { return None; }
    let units: Vec<_> = value.bytes.chunks_exact(2).map(|b| u16::from_le_bytes([b[0], b[1]])).collect();
    let text = String::from_utf16(&units).ok()?;
    let text = text.trim_end_matches('\0');
    if text.contains('\0') { return None; }
    Some(text.to_owned())
}

fn expand_environment(text: &str) -> String {
    let mut rest = text;
    let mut out = String::new();
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let Some(end) = after.find('%') else { out.push_str(&rest[start..]); return out; };
        let name = &after[..end];
        if let Some((_, value)) = std::env::vars().find(|(key, _)| key.eq_ignore_ascii_case(name)) { out.push_str(&value); }
        else { out.push_str(&rest[start..start + end + 2]); }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

// Ambiguous unquoted commands, relative executables, network/device paths and
// command hosts are never guessed into a cleanup candidate.
fn target(command: &str, app_path: bool) -> Option<String> {
    let expanded = expand_environment(command.trim());
    let text = expanded.trim();
    let value = if app_path {
        if let Some(quoted) = text.strip_prefix('"') { quoted.strip_suffix('"')? } else { text }
    } else if let Some(rest) = text.strip_prefix('"') {
        let (path, after) = rest.split_once('"')?;
        if !after.is_empty() && !after.starts_with(char::is_whitespace) { return None; }
        path
    } else {
        text.split_whitespace().next()?
    };
    if value.contains('%') || !local_absolute(value) { return None; }
    let mut path = value.to_owned();
    if app_path && Path::new(&path).extension().is_none() { path.push_str(".exe"); }
    let extension = Path::new(&path).extension()?.to_string_lossy().to_ascii_lowercase();
    if !matches!(extension.as_str(), "exe" | "com" | "bat" | "cmd") { return None; }
    Some(path)
}

fn local_absolute(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() > 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\'
        && !path.contains('/') && !path.contains('\0')
        && !path.split('\\').any(|part| part == "." || part == "..")
        && !Path::new(path).components().any(|c| match c {
            Component::ParentDir | Component::CurDir => true,
            Component::Normal(name) => { let name = name.to_string_lossy(); name.ends_with(['.', ' ']) || name.contains(':') },
            _ => false,
        })
}

fn no_reparse(path: &Path) -> Result<(), String> {
    for parent in path.ancestors() {
        match fs::symlink_metadata(parent) {
            Ok(meta) if meta.file_attributes() & 0x400 != 0 => return Err("A junction or symbolic link is in this path.".into()),
            Ok(_) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(error(e)),
        }
    }
    Ok(())
}

fn presence(path: &Option<String>) -> String {
    let Some(path) = path else { return "unresolved".into(); };
    if !local_absolute(path) || no_reparse(Path::new(path)).is_err() { return "unresolved".into(); }
    let root: Vec<u16> = path[..3].encode_utf16().chain(Some(0)).collect();
    // DRIVE_FIXED = 3; removable/offline/network volumes are not cleanup evidence.
    if unsafe { GetDriveTypeW(PCWSTR(root.as_ptr())) } != 3 || fs::metadata(&path[..3]).is_err() { return "unresolved".into(); }
    match fs::metadata(path) {
        Ok(m) if m.is_file() => "ok",
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => "missing",
        _ => "unresolved",
    }.into()
}

fn is_system(path: &Option<String>) -> bool {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()).to_ascii_lowercase();
    path.as_ref().is_some_and(|p| p.to_ascii_lowercase().starts_with(&format!("{}\\", root.trim_end_matches('\\'))))
}

fn owner(target: &Option<String>, apps: &[cleaner_core::Application]) -> Option<String> {
    let path = target.as_ref()?.to_lowercase();
    if let Some(app) = apps.iter().find(|a| a.display_icon_executable.as_ref().is_some_and(|icon| icon.eq_ignore_ascii_case(&path))) { return Some(app.name.clone()); }
    apps.iter().filter_map(|a| a.install_location.as_ref().filter(|root| root.trim_end_matches('\\').len() > 3 && path.starts_with(&format!("{}\\", root.trim_end_matches('\\').to_lowercase()))).map(|r| (r.len(), a.name.clone())))
        .max_by_key(|(len, _)| *len).map(|(_, name)| name)
}

fn approval_state(hive_name: &str, branch: &str, name: &str) -> String {
    let key_path = format!(r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\{branch}");
    let root = RegKey::predef(if hive_name == "HKCU" { HKEY_CURRENT_USER } else { HKEY_LOCAL_MACHINE });
    match root.open_subkey_with_flags(key_path, KEY_READ | KEY_WOW64_64KEY).and_then(|k| k.get_raw_value(name)) {
        Ok(value) if value.vtype == REG_BINARY && value.bytes.len() >= 12 => match value.bytes[0] {
            2 | 6 => "enabled", 3 | 7 => "windows_disabled", _ => "unknown",
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => "registered",
        _ => "unknown",
    }.into()
}

fn registry_entry(hive_name: &str, view: u32, key_path: &str, name: &str, value: RegValue, apps: &[cleaner_core::Application]) -> Option<ReviewedEntry> {
    let command = string_value(&value)?;
    let app_path = key_path.starts_with(&format!("{APP_PATHS}\\"));
    let target_path = target(&command, app_path);
    let target_status = presence(&target_path);
    let can_clean = target_status == "missing" && !is_system(&target_path);
    let can_disable = !app_path;
    let startup_state = if app_path { "not_applicable".into() } else if key_path == RUN_ONCE { "once".into() }
        else { approval_state(hive_name, if view == 32 { "Run32" } else { "Run" }, name) };
    let registry_view = if app_path { "shared view".into() } else { format!("{view}-bit") };
    let location = format!(r"{hive_name}\{key_path} ({registry_view}) → {}", if name.is_empty() { "(Default)" } else { name });
    let entry = Entry {
        id: format!("registry:{hive_name}:{view}:{key_path}:{name}").to_lowercase(),
        name: if app_path { key_path.rsplit('\\').next()?.to_owned() } else { name.to_owned() },
        kind: if app_path { "app_path" } else if key_path == RUN_ONCE { "run_once" } else { "run" }.into(),
        owner: owner(&target_path, apps), command, target_path, target_status,
        startup_state, machine_wide: hive_name == "HKLM", can_disable, can_clean,
        reason: if can_clean { "The exact program target is missing from an available local drive. Only this registry value will be removed." }
            else if is_system(&target(&string_value(&value)?, app_path)) { "Windows program references are excluded from registry cleanup." }
            else { "Existing, inaccessible or ambiguous targets are excluded from registry cleanup." }.into(),
        location,
    };
    Some(ReviewedEntry { entry, source: Source::Registry { hive: hive_name.into(), view, key: key_path.into(), name: name.into(), value_type: value.vtype as u32, bytes: value.bytes } })
}

fn read_file(path: &Path) -> Result<Vec<u8>, String> {
    let _parents = crate::cleanup::guard_parents(path)?;
    no_reparse(path)?;
    let meta = fs::symlink_metadata(path).map_err(error)?;
    if !meta.is_file() || meta.len() > MAX_FILE { return Err("Only ordinary startup files up to 1 MB can be managed here.".into()); }
    // Prevent concurrent writers while the bytes are inspected; allow deletion
    // so the same lock can cover the journal and removal.
    let mut file = fs::OpenOptions::new().read(true).share_mode(4).custom_flags(0x00200000).open(path).map_err(error)?;
    if file.metadata().map_err(error)?.file_attributes() & 0x400 != 0 { return Err("Startup file became a link.".into()); }
    let mut bytes = Vec::new();
    (&mut file).take(MAX_FILE + 1).read_to_end(&mut bytes).map_err(error)?;
    if bytes.len() as u64 > MAX_FILE { return Err("Startup file grew during inspection.".into()); }
    Ok(bytes)
}

fn collect() -> (Vec<ReviewedEntry>, Vec<String>) {
    let inventory = cleaner_core::installed_applications();
    let mut warnings = inventory.warnings;
    let mut entries = Vec::new();
    for hive_name in ["HKCU", "HKLM"] {
        // HKCU Run is shared between views; HKLM Run and App Paths are redirected.
        for view in [64, 32] {
            let root = hive(hive_name).expect("fixed hive");
            let flag = view_flag(view).expect("fixed view");
            for key_path in [RUN, RUN_ONCE] {
                if hive_name == "HKCU" && view == 32 { continue; }
                match root.open_subkey_with_flags(key_path, KEY_READ | flag) {
                    Ok(key) => for value in key.enum_values() {
                        match value {
                            Ok((name, value)) => if let Some(entry) = registry_entry(hive_name, view, key_path, &name, value, &inventory.applications) { entries.push(entry); },
                            Err(e) => warnings.push(format!("Could not read {hive_name} {key_path}: {e}")),
                        }
                    },
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                    Err(e) => warnings.push(format!("Could not read {hive_name} {view}-bit {key_path}: {e}")),
                }
            }
            // App Paths is shared between views on supported Windows versions.
            if view == 32 { continue; }
            match root.open_subkey_with_flags(APP_PATHS, KEY_READ | flag) {
                Ok(paths) => for name in paths.enum_keys() {
                    let name = match name { Ok(n) => n, Err(e) => { warnings.push(error(e)); continue; } };
                    let path = format!("{APP_PATHS}\\{name}");
                    match root.open_subkey_with_flags(&path, KEY_READ | flag).and_then(|k| k.get_raw_value("")) {
                        Ok(value) => if let Some(entry) = registry_entry(hive_name, view, &path, "", value, &inventory.applications) { entries.push(entry); },
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                        Err(e) => warnings.push(format!("Could not read {hive_name} {path}: {e}")),
                    }
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(e) => warnings.push(error(e)),
            }
        }
    }
    for (directory, machine_wide) in cleaner_core::startup_directories() {
        if no_reparse(&directory).is_err() { warnings.push(format!("Skipped linked Startup folder: {}", directory.display())); continue; }
        let files = match fs::read_dir(&directory) {
            Ok(files) => files,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => { warnings.push(format!("Could not read {}: {e}", directory.display())); continue; }
        };
        for file in files {
            let file = match file { Ok(file) => file, Err(e) => { warnings.push(error(e)); continue; } };
            let path = file.path();
            if path.file_name().is_some_and(|name| name.eq_ignore_ascii_case("desktop.ini")) { continue; }
            let Ok(meta) = fs::symlink_metadata(&path) else { continue; };
            if !meta.is_file() { continue; }
            let bytes = read_file(&path);
            let target_path = if path.extension().is_some_and(|e| e.eq_ignore_ascii_case("lnk")) {
                bytes.as_ref().ok().and_then(|b| cleaner_core::references::parse_shell_link(b, &path)).filter(|p| local_absolute(p))
            } else if path.extension().is_some_and(|e| e.eq_ignore_ascii_case("exe") || e.eq_ignore_ascii_case("bat") || e.eq_ignore_ascii_case("cmd")) {
                Some(path.to_string_lossy().into_owned())
            } else { None };
            let name = file.file_name().to_string_lossy().into_owned();
            let target_status = presence(&target_path);
            let entry = Entry {
                id: format!("file:{}", path.to_string_lossy().to_lowercase()), name: name.clone(), kind: "startup_folder".into(),
                location: path.to_string_lossy().into_owned(), command: target_path.clone().unwrap_or_else(|| path.to_string_lossy().into_owned()),
                owner: owner(&target_path, &inventory.applications), target_path, target_status,
                startup_state: approval_state(if machine_wide { "HKLM" } else { "HKCU" }, "StartupFolder", &name),
                machine_wide, can_disable: bytes.is_ok(), can_clean: false,
                reason: bytes.as_ref().err().cloned().unwrap_or_else(|| "Disabling saves this startup file in the backup database, then removes it from the Startup folder.".into()),
            };
            // Unmanageable entries remain visible, but cannot be selected.
            entries.push(ReviewedEntry { entry, source: Source::File { path: path.to_string_lossy().into_owned(), bytes: bytes.unwrap_or_default() } });
        }
    }
    let mut seen = HashSet::new();
    entries.retain(|e| seen.insert(e.entry.id.clone()));
    entries.sort_by_key(|e| e.entry.name.to_lowercase());
    (entries, warnings)
}

fn allowed_registry(hive_name: &str, view: u32, key: &str, name: &str, value_type: u32) -> Result<(), String> {
    hive(hive_name)?; view_flag(view)?;
    if value_type != REG_SZ as u32 && value_type != REG_EXPAND_SZ as u32 { return Err("Unsupported registry value type.".into()); }
    let app_path = key.strip_prefix(&format!("{APP_PATHS}\\")).is_some_and(|child| !child.is_empty() && !child.contains('\\') && name.is_empty());
    if key != RUN && key != RUN_ONCE && !app_path { return Err("This registry location is outside maintenance scope.".into()); }
    Ok(())
}

fn raw_value(value_type: u32, bytes: &[u8]) -> Result<RegValue, String> {
    let vtype = if value_type == REG_SZ as u32 { REG_SZ } else if value_type == REG_EXPAND_SZ as u32 { REG_EXPAND_SZ } else { return Err("Unsupported backup value type.".into()); };
    Ok(RegValue { vtype, bytes: bytes.to_vec() })
}

fn valid_startup_file(path: &str) -> Result<(), String> {
    if !local_absolute(path) { return Err("Startup files must use an ordinary local path.".into()); }
    let parent = Path::new(path).parent().ok_or("Invalid startup path.")?;
    if !cleaner_core::startup_directories().iter().any(|(root, _)| parent.to_string_lossy().eq_ignore_ascii_case(&root.to_string_lossy())) { return Err("This file is outside the Windows Startup folders.".into()); }
    no_reparse(Path::new(path))
}

fn journal(database: &Path, item: &ReviewedEntry, action: &str) -> Result<i64, String> {
    let conn = crate::storage::open_db(database)?;
    conn.execute("INSERT INTO maintenance_backups (entry_json, action, status, created_at_unix) VALUES (?1, ?2, 'pending', ?3)",
        params![serde_json::to_string(item).map_err(error)?, action, crate::storage::now_unix() as i64]).map_err(error)?;
    Ok(conn.last_insert_rowid())
}

fn mark(database: &Path, id: i64, status: &str, detail: &str) -> Result<(), String> {
    crate::storage::open_db(database)?.execute("UPDATE maintenance_backups SET status = ?1, detail = ?2 WHERE id = ?3", params![status, detail, id]).map_err(error)?;
    Ok(())
}

fn ensure_clean(item: &ReviewedEntry, action: &str) -> Result<(), String> {
    if action == "clean" {
        let Source::Registry { key, .. } = &item.source else { return Err("Registry cleanup cannot remove files.".into()); };
        let fresh_target = target(&item.entry.command, key.starts_with(&format!("{APP_PATHS}\\")));
        if !item.entry.can_clean || fresh_target != item.entry.target_path || presence(&fresh_target) != "missing" || is_system(&fresh_target) {
            return Err("The target is no longer confirmed missing. Refresh and review it again.".into());
        }
    } else if action != "disable" || !item.entry.can_disable { return Err("This startup entry cannot be disabled.".into()); }
    Ok(())
}

fn remove(database: &Path, item: &ReviewedEntry, action: &str) -> Result<(), String> {
    ensure_clean(item, action)?;
    match &item.source {
        Source::Registry { hive: hive_name, view, key, name, value_type, bytes } => {
            allowed_registry(hive_name, *view, key, name, *value_type)?;
            if action == "disable" && key != RUN && key != RUN_ONCE { return Err("This is not a startup registry entry.".into()); }
            let handle = hive(hive_name)?.open_subkey_with_flags(key, KEY_READ | KEY_SET_VALUE | view_flag(*view)?).map_err(|e| format!("Could not change this registry entry; all-users entries may require administrator rights. {e}"))?;
            let expected = raw_value(*value_type, bytes)?;
            if handle.get_raw_value(name).map_err(error)? != expected { return Err("The registry value changed since review. Refresh the list.".into()); }
            ensure_clean(item, action)?;
            let id = journal(database, item, action)?;
            // Recheck after the durable backup, without relying on cached scan data.
            let operation = (|| {
                if handle.get_raw_value(name).map_err(error)? != expected { return Err("The registry value changed during backup.".into()); }
                ensure_clean(item, action)?;
                handle.delete_value(name).map_err(error)
            })();
            match operation { Ok(()) => mark(database, id, "removed", ""), Err(e) => { mark(database, id, "failed", &e)?; Err(e) } }
        }
        Source::File { path, bytes } => {
            let _parents = crate::cleanup::guard_parents(Path::new(path))?;
            valid_startup_file(path)?;
            // GENERIC_READ | DELETE, OPEN_REPARSE_POINT, exclusive sharing. This
            // pins the reviewed file itself, so deletion never re-resolves a path.
            let mut locked = fs::OpenOptions::new().access_mode(0x80010000).share_mode(0).custom_flags(0x00200000).open(path).map_err(error)?;
            let meta = locked.metadata().map_err(error)?;
            if !meta.is_file() || meta.file_attributes() & 0x400 != 0 || meta.len() > MAX_FILE { return Err("Startup file changed since review.".into()); }
            let mut current = Vec::new();
            (&mut locked).take(MAX_FILE + 1).read_to_end(&mut current).map_err(error)?;
            if &current != bytes { return Err("The startup file changed since review. Refresh the list.".into()); }
            valid_startup_file(path)?;
            let id = journal(database, item, action)?;
            let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
            let removed = unsafe { SetFileInformationByHandle(HANDLE(locked.as_raw_handle()), FileDispositionInfo, &disposition as *const _ as _, std::mem::size_of_val(&disposition) as u32) };
            drop(locked);
            match removed {
                Ok(()) => mark(database, id, "removed", ""),
                Err(e) => { let detail = error(e); mark(database, id, "failed", &detail)?; Err(detail) }
            }
        }
    }
}

pub fn apply(database: &Path, selected: &[ReviewedEntry], action: &str) -> Vec<Outcome> {
    selected.iter().map(|item| {
        let result = remove(database, item, action);
        Outcome { name: item.entry.name.clone(), success: result.is_ok(), error: result.err() }
    }).collect()
}

pub fn backups(database: &Path) -> Result<Vec<Backup>, String> {
    let conn = crate::storage::open_db(database)?;
    let mut stmt = conn.prepare("SELECT id, entry_json, action, status, created_at_unix, detail FROM maintenance_backups ORDER BY id DESC").map_err(error)?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?, r.get::<_, i64>(4)?, r.get::<_, String>(5)?))).map_err(error)?;
    rows.map(|row| {
        let (id, json, action, status, created, detail) = row.map_err(error)?;
        let reviewed: ReviewedEntry = serde_json::from_str(&json).map_err(error)?;
        Ok(Backup { id, entry: reviewed.entry, action, status, created_at_unix: created.max(0) as u64, detail })
    }).collect()
}

pub fn restore(database: &Path, id: i64) -> Result<(), String> {
    let conn = crate::storage::open_db(database)?;
    let (json, status): (String, String) = conn.query_row("SELECT entry_json, status FROM maintenance_backups WHERE id = ?1", [id], |row| Ok((row.get(0)?, row.get(1)?))).map_err(error)?;
    if !matches!(status.as_str(), "removed" | "pending") { return Err("This backup is not awaiting restoration.".into()); }
    let item: ReviewedEntry = serde_json::from_str(&json).map_err(error)?;
    match &item.source {
        Source::Registry { hive: hive_name, view, key, name, value_type, bytes } => {
            allowed_registry(hive_name, *view, key, name, *value_type)?;
            // Do not recreate a key removed by an uninstaller in the meantime.
            let handle = hive(hive_name)?.open_subkey_with_flags(key, KEY_READ | KEY_SET_VALUE | view_flag(*view)?).map_err(|e| format!("The original registry key is unavailable. {e}"))?;
            let original = raw_value(*value_type, bytes)?;
            match handle.get_raw_value(name) {
                Ok(current) if current == original => (), // recovery after a crash
                Ok(_) => return Err("A different value exists at the original location. It will not be overwritten.".into()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => handle.set_raw_value(name, &original).map_err(error)?,
                Err(e) => return Err(error(e)),
            }
        }
        Source::File { path, bytes } => {
            let _parents = crate::cleanup::guard_parents(Path::new(path))?;
            valid_startup_file(path)?;
            if bytes.len() as u64 > MAX_FILE { return Err("Backup is too large.".into()); }
            match fs::symlink_metadata(path) {
                Ok(_) => {
                    if read_file(Path::new(path))? != *bytes { return Err("A different startup file exists at the original location. It will not be overwritten.".into()); }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    let mut file = fs::OpenOptions::new().write(true).create_new(true).share_mode(0).open(path).map_err(error)?;
                    file.write_all(bytes).and_then(|_| file.sync_all()).map_err(error)?;
                }
                Err(e) => return Err(error(e)),
            }
        }
    }
    mark(database, id, "restored", "")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn only_explicit_local_commands_are_cleanup_targets() {
        assert_eq!(target(r#""C:\Program Files\Old\app.exe" --background"#, false).as_deref(), Some(r"C:\Program Files\Old\app.exe"));
        assert!(target(r"C:\Program Files\Old\app.exe --background", false).is_none());
        for command in [r"app.exe", r"\\server\share\app.exe", r"C:\..\app.exe", r"C:\Old\app.exe:stream", r"%UNRESOLVED_ENVIRONMENT_FOR_TEST%\app.exe"] { assert!(target(command, false).is_none(), "{command}"); }
        assert_eq!(target(r"C:\Program Files\Old\app", true).as_deref(), Some(r"C:\Program Files\Old\app.exe"));
        assert!(target(r"rundll32.exe C:\Old\app.dll,Entry", false).is_none());
    }

    #[test]
    fn registry_scope_never_accepts_arbitrary_keys_or_types() {
        assert!(allowed_registry("HKCU", 64, RUN, "App", REG_SZ as u32).is_ok());
        assert!(allowed_registry("HKLM", 32, &format!("{APP_PATHS}\\app.exe"), "", REG_EXPAND_SZ as u32).is_ok());
        for key in [r"SYSTEM\CurrentControlSet\Services", r"Software\Classes", &format!("{APP_PATHS}\\app.exe\\Other")] {
            assert!(allowed_registry("HKCU", 64, key, "", REG_SZ as u32).is_err());
        }
        assert!(allowed_registry("HKCU", 64, RUN, "App", REG_BINARY as u32).is_err());
        assert!(allowed_registry("HKCU", 12, RUN, "App", REG_SZ as u32).is_err());
    }

    fn test_entry(key_path: &str, name: &str, command: &str) -> ReviewedEntry {
        let value = RegValue { vtype: REG_SZ, bytes: command.encode_utf16().chain(Some(0)).flat_map(u16::to_le_bytes).collect() };
        registry_entry("HKCU", 64, key_path, name, value, &[]).unwrap()
    }

    #[test]
    fn reviews_reject_unselected_or_ineligible_entries() {
        let item = test_entry(RUN, "Fixture", r"C:\Unknown\Fixture.exe");
        let mut reviews = Reviews::default();
        reviews.scans.insert("review".into(), vec![item.clone()]);
        assert!(reviews.select("expired", &[item.entry.id.clone()], "disable").is_err());
        assert!(reviews.select("review", &["invented".into()], "disable").is_err());
        assert!(reviews.select("review", &[item.entry.id.clone(), item.entry.id.clone()], "disable").is_err());
        assert_eq!(reviews.select("review", &[item.entry.id.clone()], "disable").unwrap().len(), 1);
        assert!(reviews.select("review", &[item.entry.id], "invented").is_err());
    }

    #[test]
    fn fixture_registry_disable_restore_preserves_raw_bytes_and_siblings() {
        // Only create/delete uniquely named test values; never touch an existing entry.
        let suffix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let name = format!("OrphanCleanerTest-{suffix}");
        let key = RegKey::predef(HKEY_CURRENT_USER).create_subkey(RUN).unwrap().0;
        let db: PathBuf = std::env::temp_dir().join(format!("cleaner-maintenance-{suffix}.sqlite3"));
        let item = test_entry(RUN, &name, r#""C:\OrphanCleanerDisposableFixture\missing.exe" --test"#);
        let Source::Registry { value_type, bytes, .. } = &item.source else { unreachable!() };
        let original = raw_value(*value_type, bytes).unwrap();
        key.set_raw_value(&name, &original).unwrap();
        let sibling = format!("{name}-sibling");
        key.set_value(&sibling, &"leave unchanged").unwrap();
        assert!(apply(&db, &[item.clone()], "disable")[0].success);
        assert!(key.get_raw_value(&name).is_err());
        let saved = backups(&db).unwrap();
        assert_eq!(saved[0].status, "removed");
        key.set_value(&name, &"changed since backup").unwrap();
        assert!(restore(&db, saved[0].id).is_err());
        key.delete_value(&name).unwrap();
        restore(&db, saved[0].id).unwrap();
        assert_eq!(key.get_raw_value(&name).unwrap(), original);
        assert_eq!(key.get_value::<String, _>(&sibling).unwrap(), "leave unchanged");
        assert_eq!(backups(&db).unwrap()[0].status, "restored");
        key.delete_value(&name).unwrap(); key.delete_value(&sibling).unwrap();
        fs::remove_file(db).unwrap();
    }

    #[test]
    fn changed_registry_review_is_rejected_before_backup() {
        let suffix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let name = format!("OrphanCleanerTest-{suffix}");
        let key = RegKey::predef(HKEY_CURRENT_USER).create_subkey(RUN).unwrap().0;
        let db = std::env::temp_dir().join(format!("cleaner-stale-{suffix}.sqlite3"));
        let item = test_entry(RUN, &name, r"C:\Old\app.exe");
        key.set_value(&name, &r"C:\New\app.exe").unwrap();
        assert!(!apply(&db, &[item], "disable")[0].success);
        assert!(!db.exists());
        assert_eq!(key.get_value::<String, _>(&name).unwrap(), r"C:\New\app.exe");
        key.delete_value(&name).unwrap();
    }

    #[test]
    fn registry_clean_rechecks_missing_target_and_preserves_key_values() {
        let suffix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let name = format!("OrphanCleanerTest-{suffix}.exe");
        let key_path = format!("{APP_PATHS}\\{name}");
        let root = RegKey::predef(HKEY_CURRENT_USER);
        let key = root.create_subkey(&key_path).unwrap().0;
        let missing = std::env::temp_dir().join(format!("missing-cleaner-fixture-{suffix}.exe"));
        let db = std::env::temp_dir().join(format!("registry-cleaner-{suffix}.sqlite3"));
        let item = test_entry(&key_path, "", &missing.to_string_lossy());
        assert!(item.entry.can_clean);
        key.set_value("", &missing.to_string_lossy().as_ref()).unwrap();
        key.set_value("Path", &"a sibling value retained during cleanup").unwrap();
        fs::write(&missing, b"disposable non-executable fixture").unwrap();
        assert!(!apply(&db, &[item.clone()], "clean")[0].success);
        assert!(!db.exists(), "working targets must be rejected before journaling");
        fs::remove_file(&missing).unwrap();
        assert!(apply(&db, &[item], "clean")[0].success);
        assert!(key.get_raw_value("").is_err());
        assert_eq!(key.get_value::<String, _>("Path").unwrap(), "a sibling value retained during cleanup");
        let saved = backups(&db).unwrap();
        assert_eq!(saved[0].action, "clean");
        restore(&db, saved[0].id).unwrap();
        assert_eq!(key.get_value::<String, _>("").unwrap(), missing.to_string_lossy());
        drop(key);
        root.delete_subkey(&key_path).unwrap();
        fs::remove_file(db).unwrap();
    }

    #[test]
    fn startup_file_disable_restore_is_exact_and_conflict_safe() {
        let suffix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let directory = cleaner_core::startup_directories().into_iter().find(|(_, machine)| !machine).unwrap().0;
        let path = directory.join(format!("OrphanCleanerTest-{suffix}.lnk"));
        let db = std::env::temp_dir().join(format!("startup-file-{suffix}.sqlite3"));
        let bytes = b"Invalid disposable test shortcut; cannot launch anything".to_vec();
        fs::OpenOptions::new().write(true).create_new(true).open(&path).unwrap().write_all(&bytes).unwrap();
        let mut item = test_entry(RUN, "File fixture", r"C:\Fixture\app.exe");
        item.entry.id = format!("file:{}", path.display());
        item.entry.kind = "startup_folder".into();
        item.entry.location = path.to_string_lossy().into_owned();
        item.entry.can_clean = false;
        item.source = Source::File { path: path.to_string_lossy().into_owned(), bytes: bytes.clone() };
        fs::write(&path, b"changed since review").unwrap();
        assert!(!apply(&db, &[item.clone()], "disable")[0].success);
        assert!(!db.exists());
        fs::write(&path, &bytes).unwrap();
        assert!(apply(&db, &[item], "disable")[0].success);
        assert!(!path.exists());
        let saved = backups(&db).unwrap();
        fs::write(&path, b"new startup file").unwrap();
        assert!(restore(&db, saved[0].id).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"new startup file");
        fs::remove_file(&path).unwrap();
        restore(&db, saved[0].id).unwrap();
        assert_eq!(fs::read(&path).unwrap(), bytes);
        fs::remove_file(path).unwrap(); fs::remove_file(db).unwrap();
    }

    #[test]
    fn interrupted_journal_is_restorable_even_when_nothing_was_removed() {
        let suffix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let name = format!("OrphanCleanerTest-{suffix}");
        let db = std::env::temp_dir().join(format!("pending-cleaner-{suffix}.sqlite3"));
        let key = RegKey::predef(HKEY_CURRENT_USER).create_subkey(RUN).unwrap().0;
        let item = test_entry(RUN, &name, r"C:\Fixture\app.exe");
        key.set_value(&name, &r"C:\Fixture\app.exe").unwrap();
        let id = journal(&db, &item, "disable").unwrap();
        assert_eq!(backups(&db).unwrap()[0].status, "pending");
        restore(&db, id).unwrap();
        assert_eq!(backups(&db).unwrap()[0].status, "restored");
        key.delete_value(&name).unwrap(); fs::remove_file(db).unwrap();
    }
}
