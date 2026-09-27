use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::UNIX_EPOCH;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY};
use winreg::RegKey;
use windows::core::GUID;
use windows::Win32::System::Com::{CoInitializeEx, CoTaskMemFree, CoUninitialize, COINIT_MULTITHREADED};
use windows::Win32::UI::Shell::{SHGetKnownFolderPath, KF_FLAG_DEFAULT, FOLDERID_LocalAppData, FOLDERID_LocalAppDataLow, FOLDERID_ProgramData, FOLDERID_RoamingAppData};

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Application {
    pub id: String,
    pub name: String,
    pub publisher: Option<String>,
    pub version: Option<String>,
    pub install_location: Option<String>,
    pub package_family_name: Option<String>,
    pub sources: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Inventory {
    pub applications: Vec<Application>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AppxPackage {
    name: String,
    publisher_display_name: Option<String>,
    version: Option<String>,
    install_location: Option<String>,
    package_family_name: String,
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
    pub scanned_roots: Vec<String>,
    pub warnings: Vec<String>,
}

pub fn normalize_name(value: &str) -> String {
    value.chars().filter(|ch| ch.is_alphanumeric()).flat_map(char::to_lowercase).collect()
}

fn registry_applications() -> Vec<Application> {
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
                    found.insert(key, Application { id, name, publisher, version, install_location, package_family_name: None, sources: vec![source] });
                }
            }
        }
    }
    let mut apps: Vec<_> = found.into_values().collect();
    apps.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    apps
}

fn msix_applications() -> Result<Vec<Application>, String> {
    // This fixed, read-only command avoids loading or executing anything found during scanning.
    let script = "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); ConvertTo-Json -InputObject @(Get-AppxPackage | Select-Object Name,PublisherDisplayName,Version,InstallLocation,PackageFamilyName) -Depth 3 -Compress";
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map_err(|err| format!("MSIX inventory could not start: {err}"))?;
    if !output.status.success() {
        return Err("MSIX inventory failed; package data will remain unknown.".into());
    }
    let packages: Vec<AppxPackage> = serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("MSIX inventory output was unreadable: {err}"))?;
    Ok(packages.into_iter().filter(|p| !p.package_family_name.is_empty()).map(|package| Application {
        id: format!("msix:{}", package.package_family_name),
        name: package.name,
        publisher: package.publisher_display_name,
        version: package.version,
        install_location: package.install_location.filter(|s| !s.is_empty()),
        package_family_name: Some(package.package_family_name),
        sources: vec!["Current-user MSIX/AppX package".into()],
    }).collect())
}

pub fn installed_applications() -> Inventory {
    let mut applications = registry_applications();
    let mut warnings = Vec::new();
    match msix_applications() {
        Ok(mut packages) => applications.append(&mut packages),
        Err(warning) => warnings.push(warning),
    }
    applications.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    Inventory { applications, warnings }
}

fn known_folder_path(id: &GUID) -> Option<PathBuf> {
    // SHGetKnownFolderPath requires COM on the current scan thread.
    let initialized = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.is_ok();
    let path = unsafe { SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, None) }.ok().and_then(|wide| {
        let raw = wide.0;
        if raw.is_null() { return None; }
        let mut length = 0;
        // The API returns a null-terminated UTF-16 buffer owned by the caller.
        unsafe { while *raw.add(length) != 0 { length += 1; } }
        let path = PathBuf::from(OsString::from_wide(unsafe { std::slice::from_raw_parts(raw, length) }));
        unsafe { CoTaskMemFree(Some(raw.cast())); }
        Some(path)
    });
    if initialized { unsafe { CoUninitialize(); } }
    path
}

fn scan_roots() -> (Vec<(String, PathBuf)>, Vec<String>) {
    let mut roots = Vec::new();
    let mut warnings = Vec::new();
    for (label, id, fallback) in [
        ("Local", &FOLDERID_LocalAppData, "LOCALAPPDATA"),
        ("Roaming", &FOLDERID_RoamingAppData, "APPDATA"),
        ("LocalLow", &FOLDERID_LocalAppDataLow, ""),
        ("ProgramData", &FOLDERID_ProgramData, "PROGRAMDATA"),
    ] {
        let known = known_folder_path(id);
        let path = known.or_else(|| {
            warnings.push(format!("Windows Known Folder lookup failed for {label}; using the environment fallback."));
            if label == "LocalLow" {
                std::env::var_os("USERPROFILE").map(|profile| PathBuf::from(profile).join("AppData").join("LocalLow"))
            } else {
                std::env::var_os(fallback).map(PathBuf::from)
            }
        });
        match path {
            Some(path) if path.is_dir() => roots.push((label.to_owned(), path)),
            _ => warnings.push(format!("{label} could not be scanned because its folder is unavailable.")),
        }
    }
    let mut seen = HashSet::new();
    roots.retain(|(_, path)| seen.insert(path.to_string_lossy().to_lowercase()));
    (roots, warnings)
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
    let is_package_data = path.parent().and_then(Path::file_name).is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case("Packages"));
    let mut strong = Vec::new();
    let mut names = Vec::new();
    for app in apps {
        let exact_name = normalize_name(&app.name) == normalized;
        let exact_install = app.install_location.as_deref().is_some_and(|location| {
            Path::new(location).to_string_lossy().trim_end_matches(['\\', '/']).eq_ignore_ascii_case(&path_string)
        });
        let exact_package = is_package_data && app.package_family_name.as_deref().is_some_and(|family| family.eq_ignore_ascii_case(&basename));
        if exact_install || exact_package {
            strong.push((app, exact_install, exact_package));
        } else if exact_name {
            names.push(app);
        }
    }
    if strong.len() > 1 || (strong.is_empty() && names.len() > 1) {
        let evidence = vec![Evidence { kind: "multiple_matches".into(), description: "Several installed applications match this directory; ownership is ambiguous.".into(), strength: "weak".into() }];
        return (None, "unknown".into(), "unknown".into(), evidence);
    }
    let (app, ownership, evidence) = if let Some((app, install, package)) = strong.first() {
        let (kind, description) = if *package {
            ("package_family_match", format!("Directory matches installed package family {}.", app.package_family_name.as_deref().unwrap_or_default()))
        } else if *install {
            ("install_path_match", format!("The installed application's registered path is this directory ({}).", app.sources.join(", ")))
        } else { unreachable!() };
        (*app, "confirmed", vec![Evidence { kind: kind.into(), description, strength: "strong".into() }])
    } else if let Some(app) = names.first() {
        (*app, "likely", vec![Evidence { kind: "directory_name_match".into(), description: format!("The directory name exactly matches installed application “{}”.", app.name), strength: "medium".into() }])
    } else {
        return (None, "unknown".into(), "unknown".into(), vec![]);
    };
    (Some(app.clone()), ownership.into(), "not_orphaned".into(), evidence)
}

fn scan_target(path: PathBuf, root: &str, apps: &[Application], cancel: &AtomicBool, summary: &mut ScanSummary, on_result: &mut impl FnMut(DirectoryResult), on_progress: &mut impl FnMut(String)) {
    if cancel.load(Ordering::Relaxed) { return; }
    on_progress(path.to_string_lossy().into_owned());
    let (size, files, directories, newest, skipped) = inspect_directory(&path, cancel);
    if cancel.load(Ordering::Relaxed) { return; }
    let (owner, ownership, orphan_status, evidence) = resolve_owner(&path, apps);
    summary.directories += 1;
    summary.bytes = summary.bytes.saturating_add(size);
    summary.skipped_entries += skipped;
    on_result(DirectoryResult {
        path: path.to_string_lossy().into_owned(), root: root.to_owned(), size_bytes: size,
        file_count: files, directory_count: directories, newest_modified_unix: newest,
        skipped_entries: skipped, owner, ownership, orphan_status, evidence,
    });
}

pub fn scan<F, P>(apps: &[Application], cancel: &AtomicBool, mut on_result: F, mut on_progress: P) -> ScanSummary
where
    F: FnMut(DirectoryResult),
    P: FnMut(String),
{
    let mut summary = ScanSummary::default();
    let (roots, warnings) = scan_roots();
    summary.warnings = warnings;
    for (label, root) in roots {
        if cancel.load(Ordering::Relaxed) { break; }
        let Ok(entries) = fs::read_dir(&root) else {
            summary.skipped_entries += 1;
            summary.warnings.push(format!("{label} could not be enumerated: {}", root.display()));
            continue;
        };
        summary.scanned_roots.push(format!("{label}: {}", root.display()));
        for entry in entries {
            if cancel.load(Ordering::Relaxed) { break; }
            let Ok(entry) = entry else { summary.skipped_entries += 1; continue; };
            let Ok(metadata) = fs::symlink_metadata(entry.path()) else { summary.skipped_entries += 1; continue; };
            if !metadata.is_dir() || is_reparse_point(&metadata) { continue; }
            let path = entry.path();
            let structural_container = label == "Local" && ["Packages", "Programs"].iter().any(|name| entry.file_name().to_string_lossy().eq_ignore_ascii_case(name));
            if structural_container {
                let Ok(children) = fs::read_dir(&path) else { summary.skipped_entries += 1; continue; };
                for child in children {
                    if cancel.load(Ordering::Relaxed) { break; }
                    let Ok(child) = child else { summary.skipped_entries += 1; continue; };
                    let child_path = child.path();
                    let Ok(child_metadata) = fs::symlink_metadata(&child_path) else { summary.skipped_entries += 1; continue; };
                    if !child_metadata.is_dir() || is_reparse_point(&child_metadata) { continue; }
                    scan_target(child_path, &label, apps, cancel, &mut summary, &mut on_result, &mut on_progress);
                }
            } else {
                scan_target(path, &label, apps, cancel, &mut summary, &mut on_result, &mut on_progress);
            }
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
        let app = Application { id: "test".into(), name: "Notion".into(), publisher: None, version: None, install_location: None, package_family_name: None, sources: vec!["test".into()] };
        let (owner, ownership, orphan, evidence) = resolve_owner(Path::new(r"C:\Users\Test\AppData\Roaming\Notion"), &[app]);
        assert_eq!(owner.unwrap().name, "Notion");
        assert_eq!(ownership, "likely");
        assert_eq!(orphan, "not_orphaned");
        assert_eq!(evidence.len(), 1);
    }

    #[test]
    fn package_family_beats_an_unrelated_name_match() {
        let package = Application { id: "package".into(), name: "Calculator".into(), publisher: None, version: None, install_location: None, package_family_name: Some("Microsoft.WindowsCalculator_8wekyb3d8bbwe".into()), sources: vec!["MSIX".into()] };
        let unrelated = Application { id: "name".into(), name: "Microsoft.WindowsCalculator_8wekyb3d8bbwe".into(), publisher: None, version: None, install_location: None, package_family_name: None, sources: vec!["registry".into()] };
        let (owner, ownership, orphan, evidence) = resolve_owner(Path::new(r"C:\Users\Test\AppData\Local\Packages\Microsoft.WindowsCalculator_8wekyb3d8bbwe"), &[package, unrelated]);
        assert_eq!(owner.unwrap().id, "package");
        assert_eq!(ownership, "confirmed");
        assert_eq!(orphan, "not_orphaned");
        assert_eq!(evidence[0].kind, "package_family_match");
    }
}
