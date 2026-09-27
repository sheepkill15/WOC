use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::UNIX_EPOCH;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY};
use winreg::RegKey;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Application {
    pub id: String,
    pub name: String,
    pub publisher: Option<String>,
    pub version: Option<String>,
    pub install_location: Option<String>,
    pub sources: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    pub kind: String,
    pub description: String,
    pub strength: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryResult {
    pub path: String,
    pub root: String,
    pub size_bytes: u64,
    pub file_count: u64,
    pub directory_count: u64,
    pub newest_modified_unix: Option<u64>,
    pub skipped_entries: u64,
    pub owner: Option<Application>,
    pub ownership: String,
    pub orphan_status: String,
    pub evidence: Vec<Evidence>,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanSummary {
    pub directories: u64,
    pub bytes: u64,
    pub skipped_entries: u64,
    pub canceled: bool,
}

pub fn normalize_name(value: &str) -> String {
    value.chars().filter(|ch| ch.is_alphanumeric()).flat_map(char::to_lowercase).collect()
}

pub fn installed_applications() -> Vec<Application> {
    let mut found: HashMap<String, Application> = HashMap::new();
    for (hive, hive_name) in [
        (RegKey::predef(HKEY_CURRENT_USER), "HKCU"),
        (RegKey::predef(HKEY_LOCAL_MACHINE), "HKLM"),
    ] {
        for (view, flag) in [("64", KEY_WOW64_64KEY), ("32", KEY_WOW64_32KEY)] {
            let Ok(uninstall) = hive.open_subkey_with_flags(
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                KEY_READ | flag,
            ) else {
                continue;
            };
            for subkey in uninstall.enum_keys().flatten() {
                let Ok(entry) = uninstall.open_subkey_with_flags(&subkey, KEY_READ) else {
                    continue;
                };
                let Ok(name) = entry.get_value::<String, _>("DisplayName") else {
                    continue;
                };
                if name.trim().is_empty() || entry.get_value::<u32, _>("SystemComponent").unwrap_or(0) == 1 {
                    continue;
                }
                let publisher = entry.get_value::<String, _>("Publisher").ok().filter(|s| !s.trim().is_empty());
                let version = entry.get_value::<String, _>("DisplayVersion").ok().filter(|s| !s.trim().is_empty());
                let install_location = entry.get_value::<String, _>("InstallLocation").ok().filter(|s| !s.trim().is_empty());
                let source = format!("{hive_name} {view}-bit uninstall registry");
                let id = format!("{hive_name}:{view}:{subkey}");
                let key = format!("{}|{}|{}", normalize_name(&name), publisher.as_deref().map(normalize_name).unwrap_or_default(), version.as_deref().unwrap_or_default());
                if let Some(existing) = found.get_mut(&key) {
                    if !existing.sources.contains(&source) {
                        existing.sources.push(source);
                    }
                    if existing.install_location.is_none() {
                        existing.install_location = install_location;
                    }
                } else {
                    found.insert(key, Application { id, name, publisher, version, install_location, sources: vec![source] });
                }
            }
        }
    }
    let mut apps: Vec<_> = found.into_values().collect();
    apps.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    apps
}

fn scan_roots() -> Vec<(String, PathBuf)> {
    let mut roots = Vec::new();
    for (label, variable) in [("Local", "LOCALAPPDATA"), ("Roaming", "APPDATA"), ("ProgramData", "PROGRAMDATA")] {
        if let Some(path) = std::env::var_os(variable).map(PathBuf::from).filter(|p| p.is_dir()) {
            roots.push((label.to_owned(), path));
        }
    }
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        let path = PathBuf::from(profile).join("AppData").join("LocalLow");
        if path.is_dir() {
            roots.push(("LocalLow".to_owned(), path));
        }
    }
    let mut seen = HashSet::new();
    roots.retain(|(_, path)| seen.insert(path.to_string_lossy().to_lowercase()));
    roots
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn inspect_directory(path: &Path, cancel: &AtomicBool) -> (u64, u64, u64, Option<u64>, u64) {
    let mut size = 0u64;
    let mut files = 0u64;
    let mut directories = 0u64;
    let mut newest = None::<u64>;
    let mut skipped = 0u64;
    let mut pending = vec![path.to_path_buf()];
    while let Some(current) = pending.pop() {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let Ok(entries) = fs::read_dir(&current) else {
            skipped += 1;
            continue;
        };
        for entry in entries {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            let Ok(entry) = entry else {
                skipped += 1;
                continue;
            };
            let Ok(metadata) = fs::symlink_metadata(entry.path()) else {
                skipped += 1;
                continue;
            };
            if is_reparse_point(&metadata) || metadata.file_type().is_symlink() {
                skipped += 1;
                continue;
            }
            if metadata.is_dir() {
                directories += 1;
                pending.push(entry.path());
            } else if metadata.is_file() {
                files += 1;
                size = size.saturating_add(metadata.len());
                if let Ok(seconds) = metadata.modified().and_then(|t| t.duration_since(UNIX_EPOCH).map_err(std::io::Error::other)) {
                    newest = Some(newest.map_or(seconds.as_secs(), |old| old.max(seconds.as_secs())));
                }
            }
        }
    }
    (size, files, directories, newest, skipped)
}

fn resolve_owner(path: &Path, apps: &[Application]) -> (Option<Application>, String, String, Vec<Evidence>) {
    let basename = path.file_name().map(|s| s.to_string_lossy()).unwrap_or_default();
    let normalized = normalize_name(&basename);
    if normalized.is_empty() {
        return (None, "unknown".into(), "unknown".into(), vec![]);
    }
    let path_string = path.to_string_lossy().to_lowercase();
    let mut matches = Vec::new();
    for app in apps {
        let exact_name = normalize_name(&app.name) == normalized;
        let exact_install = app.install_location.as_deref().is_some_and(|location| {
            Path::new(location).to_string_lossy().trim_end_matches(['\\', '/']).eq_ignore_ascii_case(&path_string)
        });
        if exact_name || exact_install {
            matches.push((app, exact_name, exact_install));
        }
    }
    if matches.len() != 1 {
        let evidence = if matches.len() > 1 { vec![Evidence { kind: "multiple_matches".into(), description: "Several installed applications match this directory; ownership is ambiguous.".into(), strength: "weak".into() }] } else { vec![] };
        return (None, "unknown".into(), "unknown".into(), evidence);
    }
    let (app, exact_name, exact_install) = matches[0];
    let evidence = if exact_install {
        vec![Evidence { kind: "install_path_match".into(), description: format!("The installed application's registered path is this directory ({}).", app.sources.join(", ")), strength: "strong".into() }]
    } else if exact_name {
        vec![Evidence { kind: "directory_name_match".into(), description: format!("The directory name exactly matches installed application “{}”.", app.name), strength: "medium".into() }]
    } else { vec![] };
    let ownership = if exact_install { "confirmed" } else { "likely" };
    (Some(app.clone()), ownership.into(), "not_orphaned".into(), evidence)
}

pub fn scan<F, P>(apps: &[Application], cancel: &AtomicBool, mut on_result: F, mut on_progress: P) -> ScanSummary
where
    F: FnMut(DirectoryResult),
    P: FnMut(String),
{
    let mut summary = ScanSummary::default();
    for (label, root) in scan_roots() {
        if cancel.load(Ordering::Relaxed) { break; }
        let Ok(entries) = fs::read_dir(&root) else {
            summary.skipped_entries += 1;
            continue;
        };
        for entry in entries {
            if cancel.load(Ordering::Relaxed) { break; }
            let Ok(entry) = entry else { summary.skipped_entries += 1; continue; };
            let Ok(metadata) = fs::symlink_metadata(entry.path()) else { summary.skipped_entries += 1; continue; };
            if !metadata.is_dir() || is_reparse_point(&metadata) { continue; }
            let path = entry.path();
            on_progress(path.to_string_lossy().into_owned());
            let (size, files, directories, newest, skipped) = inspect_directory(&path, cancel);
            if cancel.load(Ordering::Relaxed) { break; }
            let (owner, ownership, orphan_status, evidence) = resolve_owner(&path, apps);
            summary.directories += 1;
            summary.bytes = summary.bytes.saturating_add(size);
            summary.skipped_entries += skipped;
            on_result(DirectoryResult {
                path: path.to_string_lossy().into_owned(), root: label.clone(), size_bytes: size,
                file_count: files, directory_count: directories, newest_modified_unix: newest,
                skipped_entries: skipped, owner, ownership, orphan_status, evidence,
            });
        }
    }
    summary.canceled = cancel.load(Ordering::Relaxed);
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_normalization_matches_punctuation_without_fuzzy_guessing() {
        assert_eq!(normalize_name("JetBrains.Rider"), "jetbrainsrider");
        assert_ne!(normalize_name("Rider2024"), normalize_name("Rider2025"));
    }

    #[test]
    fn missing_app_does_not_make_an_orphan() {
        let (_, ownership, orphan, _) = resolve_owner(Path::new(r"C:\Users\Test\AppData\Roaming\OldGame"), &[]);
        assert_eq!(ownership, "unknown");
        assert_eq!(orphan, "unknown");
    }

    #[test]
    fn active_exact_match_is_not_orphaned() {
        let app = Application { id: "test".into(), name: "Notion".into(), publisher: None, version: None, install_location: None, sources: vec!["test".into()] };
        let (owner, ownership, orphan, evidence) = resolve_owner(Path::new(r"C:\Users\Test\AppData\Roaming\Notion"), &[app]);
        assert_eq!(owner.unwrap().name, "Notion");
        assert_eq!(ownership, "likely");
        assert_eq!(orphan, "not_orphaned");
        assert_eq!(evidence.len(), 1);
    }
}
