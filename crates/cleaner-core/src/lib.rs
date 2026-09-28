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

mod known_locations;
pub mod public_data;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Application {
    pub id: String,
    pub name: String,
    pub publisher: Option<String>,
    pub version: Option<String>,
    pub install_location: Option<String>,
    #[serde(default)]
    pub display_icon_executable: Option<String>,
    pub package_family_name: Option<String>,
    pub sources: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    pub kind: String,
    pub description: String,
    pub strength: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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
    #[serde(default)]
    pub owner_hint: Option<String>,
    pub ownership: String,
    pub orphan_status: String,
    pub evidence: Vec<Evidence>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
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

fn product_name_without_version(name: &str) -> String {
    let name = name.trim();
    let name = [" (User)", " (x64)", " (x86)"].iter()
        .find_map(|suffix| name.strip_suffix(suffix)).unwrap_or(name);
    let mut words = name.split_whitespace();
    let mut product = Vec::new();
    if let Some(first) = words.next() { product.push(first); }
    product.extend(words.take_while(|word| {
        let year = word.len() == 4 && word.starts_with("20") && word.chars().all(|ch| ch.is_ascii_digit());
        let version = word.starts_with(|ch: char| ch.is_ascii_digit()) && word.contains('.');
        !year && !version
    }));
    product.join(" ")
}

fn vendor_name(publisher: &str) -> String {
    let mut words: Vec<&str> = publisher.split_whitespace().collect();
    while words.last().is_some_and(|word| matches!(word.trim_end_matches([',', '.']).to_ascii_lowercase().as_str(),
        "ab" | "inc" | "llc" | "ltd" | "limited" | "corporation" | "corp" | "gmbh" | "s.r.o")) {
        words.pop();
    }
    normalize_name(&words.join(" "))
}

fn install_path_has_component(location: &str, name: &str) -> bool {
    if matches!(name, "app" | "application" | "bin" | "cache" | "common" | "packages" | "programs" | "temp") {
        return false;
    }
    location.split(['\\', '/']).any(|part| normalize_name(part) == name)
}

fn display_icon_executable(value: &str) -> Option<String> {
    // DisplayIcon is commonly a quoted executable plus an optional icon index.
    // Ignore DLLs, environment-variable paths and missing files: none proves an active app.
    let trimmed = value.trim();
    let path = if let Some(rest) = trimmed.strip_prefix('"') {
        rest.split_once('"')?.0
    } else {
        match trimmed.rsplit_once(',') {
            Some((path, index)) if index.trim().parse::<i32>().is_ok() => path.trim(),
            _ => trimmed,
        }
    };
    if path.contains('%') || !path.to_ascii_lowercase().ends_with(".exe")
        || !Path::new(path).is_absolute() || !Path::new(path).is_file() {
        return None;
    }
    Some(path.to_owned())
}

fn registry_applications() -> (Vec<Application>, Vec<String>) {
    let mut found: HashMap<String, Application> = HashMap::new();
    let mut warnings = Vec::new();
    for (hive, hive_name) in [
        (RegKey::predef(HKEY_CURRENT_USER), "HKCU"),
        (RegKey::predef(HKEY_LOCAL_MACHINE), "HKLM"),
    ] {
        for (view, flag) in [("64", KEY_WOW64_64KEY), ("32", KEY_WOW64_32KEY)] {
            let uninstall = hive.open_subkey_with_flags(
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                KEY_READ | flag,
            );
            let Ok(uninstall) = uninstall else {
                warnings.push(format!("Could not read {hive_name} {view}-bit uninstall entries."));
                continue;
            };
            for subkey in uninstall.enum_keys() {
                let Ok(subkey) = subkey else {
                    warnings.push(format!("Could not enumerate every {hive_name} {view}-bit uninstall entry."));
                    continue;
                };
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
                let display_icon_executable = entry.get_value::<String, _>("DisplayIcon").ok()
                    .and_then(|icon| display_icon_executable(&icon));
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
                    if existing.display_icon_executable.is_none() {
                        existing.display_icon_executable = display_icon_executable;
                    }
                } else {
                    found.insert(key, Application { id, name, publisher, version, install_location, display_icon_executable, package_family_name: None, sources: vec![source] });
                }
            }
        }
    }
    let mut apps: Vec<_> = found.into_values().collect();
    apps.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    (apps, warnings)
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
        display_icon_executable: None,
        package_family_name: Some(package.package_family_name),
        sources: vec!["Current-user MSIX/AppX package".into()],
    }).collect())
}

pub fn installed_applications() -> Inventory {
    let (mut applications, mut warnings) = registry_applications();
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
    let mut vendors = Vec::new();
    for app in apps {
        let exact_name = normalize_name(&app.name) == normalized;
        let product = product_name_without_version(&app.name);
        let versioned_name = normalize_name(&product) == normalized;
        let package_product = app.package_family_name.is_some()
            && product.rsplit_once('.').is_some_and(|(_, tail)| normalize_name(tail) == normalized);
        let desktop_folder = basename.to_ascii_lowercase().strip_suffix("-desktop")
            .is_some_and(|base| normalize_name(base) == normalize_name(&product));
        let known_alias = normalized == "tft"
            && matches!(normalize_name(&product).as_str(), "teamfighttactics" | "teamfighttacticspbe");
        let product_family = [" Desktop", " Studio"].iter()
            .any(|suffix| product.strip_suffix(suffix).is_some_and(|base| normalize_name(base) == normalized));
        let exact_install = app.install_location.as_deref().is_some_and(|location| {
            Path::new(location).to_string_lossy().trim_end_matches(['\\', '/']).eq_ignore_ascii_case(&path_string)
        });
        let exact_package = is_package_data && app.package_family_name.as_deref().is_some_and(|family| family.eq_ignore_ascii_case(&basename));
        let icon_inside = app.display_icon_executable.as_deref()
            .and_then(|icon| Path::new(icon).parent())
            .is_some_and(|parent| parent.to_string_lossy().trim_end_matches(['\\', '/']).eq_ignore_ascii_case(&path_string));
        if exact_install || exact_package || icon_inside {
            strong.push((app, exact_install, exact_package, icon_inside));
        } else if exact_name || versioned_name || package_product || desktop_folder || known_alias {
            names.push(app);
        } else if product_family
            || app.publisher.as_deref().is_some_and(|publisher| normalize_name(publisher) == normalized || vendor_name(publisher) == normalized)
            || app.install_location.as_deref().is_some_and(|location| install_path_has_component(location, &normalized)) {
            vendors.push(app);
        }
    }
    if strong.len() > 1 || (strong.is_empty() && names.len() > 1) {
        let matching = if strong.is_empty() { names.iter().map(|app| app.name.as_str()).collect::<Vec<_>>() }
            else { strong.iter().map(|(app, _, _, _)| app.name.as_str()).collect::<Vec<_>>() };
        let evidence = vec![Evidence { kind: "multiple_matches".into(), description: format!("Several installed applications match this directory ({}); no single product owner can be assigned.", matching.join(", ")), strength: "medium".into() }];
        return (None, "shared".into(), "associated_with_installed".into(), evidence);
    }
    let (app, ownership, evidence) = if let Some((app, install, package, icon)) = strong.first() {
        let (kind, description) = if *package {
            ("package_family_match", format!("Directory matches installed package family {}.", app.package_family_name.as_deref().unwrap_or_default()))
        } else if *install {
            ("install_path_match", format!("The installed application's registered path is this directory ({}).", app.sources.join(", ")))
        } else if *icon {
            ("registered_executable", format!("The installed application's registry entry points to an existing executable inside this directory ({}).", app.sources.join(", ")))
        } else { unreachable!() };
        (*app, "confirmed", vec![Evidence { kind: kind.into(), description, strength: "strong".into() }])
    } else if let Some(app) = names.first() {
        let description = if normalize_name(&app.name) == normalized {
            format!("The directory name exactly matches installed application “{}”.", app.name)
        } else {
            format!("The directory name matches a product or package-name variant of installed application “{}”.", app.name)
        };
        (*app, "likely", vec![Evidence { kind: "directory_name_match".into(), description, strength: "medium".into() }])
    } else {
        if vendors.is_empty() {
            return (None, "unknown".into(), "unknown".into(), vec![]);
        }
        let examples = vendors.iter().take(3).map(|app| app.name.as_str()).collect::<Vec<_>>().join(", ");
        return (None, "shared".into(), "associated_with_installed".into(), vec![Evidence {
            kind: "vendor_or_install_segment".into(),
            description: format!("This folder name matches an installed application's publisher or an installation-path component (for example: {examples}). It may also contain data from other or older products."),
            strength: "weak".into(),
        }]);
    };
    (Some(app.clone()), ownership.into(), "not_orphaned".into(), evidence)
}

fn nested_installed_owner(path: &Path, apps: &[Application]) -> Option<Application> {
    let vendor = normalize_name(&path.file_name()?.to_string_lossy());
    let candidates: Vec<_> = apps.iter().filter(|app| app.publisher.as_deref()
        .is_some_and(|publisher| normalize_name(publisher) == vendor || vendor_name(publisher) == vendor)).collect();
    if candidates.is_empty() { return None; }
    let mut children = Vec::new();
    for entry in fs::read_dir(path).ok()?.take(65) {
        let entry = entry.ok()?;
        let metadata = fs::symlink_metadata(entry.path()).ok()?;
        if metadata.is_dir() && !is_reparse_point(&metadata) {
            children.push(normalize_name(&entry.file_name().to_string_lossy()));
        }
    }
    if children.len() != 1 { return None; }
    let matches: Vec<_> = candidates.into_iter().filter(|app| {
        normalize_name(&app.name) == children[0]
            || normalize_name(&product_name_without_version(&app.name)) == children[0]
    }).collect();
    (matches.len() == 1).then(|| (*matches[0]).clone())
}

fn shared_vendor_hint(path: &Path, apps: &[Application]) -> Option<String> {
    let folder = path.file_name()?.to_string_lossy().into_owned();
    let normalized = normalize_name(&folder);
    let matching_publishers: Vec<&str> = apps.iter().filter_map(|app| app.publisher.as_deref())
        .filter(|publisher| normalize_name(publisher) == normalized || vendor_name(publisher) == normalized)
        .collect();
    let distinct: HashSet<String> = matching_publishers.iter().map(|publisher| normalize_name(publisher)).collect();
    if distinct.len() == 1 {
        Some(matching_publishers[0].to_owned())
    } else {
        Some(folder)
    }
}

fn enrich_directory(result: &mut DirectoryResult, apps: &[Application]) {
    if result.orphan_status == "associated_with_installed"
        && Path::new(&result.path).file_name().is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case("TFT"))
        && apps.iter().any(|app| normalize_name(&app.name).starts_with("teamfighttactics")) {
        result.owner_hint = Some("Teamfight Tactics".into());
        result.evidence.push(Evidence {
            kind: "known_product_alias".into(),
            description: "TFT is the Teamfight Tactics data-folder name; installed editions may share this folder.".into(),
            strength: "medium".into(),
        });
    }
    if result.owner.is_none() && matches!(result.orphan_status.as_str(), "unknown" | "associated_with_installed") {
        if let Some(app) = nested_installed_owner(Path::new(&result.path), apps) {
            result.evidence.push(Evidence {
                kind: "publisher_and_child_match".into(),
                description: format!("The folder name matches publisher {} and its only immediate product folder matches installed application {}.", app.publisher.as_deref().unwrap_or_default(), app.name),
                strength: "medium".into(),
            });
            result.owner = Some(app);
            result.owner_hint = None;
            result.ownership = "likely".into();
            result.orphan_status = "not_orphaned".into();
            return;
        }
    }
    if result.orphan_status == "associated_with_installed" && result.owner_hint.is_none() {
        result.owner_hint = shared_vendor_hint(Path::new(&result.path), apps);
    }
    if result.orphan_status != "unknown" { return; }
    let Some(name) = Path::new(&result.path).file_name() else { return; };
    let Some(known) = known_locations::lookup(&result.root, &name.to_string_lossy()) else { return; };
    result.owner_hint = Some(known.label.into());
    result.ownership = "known_location".into();
    result.orphan_status = if known.possible_former { "possibly_orphaned" } else { "known_application_data" }.into();
    result.evidence.push(Evidence {
        kind: "known_location".into(),
        description: known.description.into(),
        strength: if known.possible_former { "weak" } else { "medium" }.into(),
    });
    if known.possible_former {
        result.evidence.push(Evidence {
            kind: "missing_installed_app".into(),
            description: "No matching uninstall or current-user package entry was found. A launcher-managed or portable installation may still exist.".into(),
            strength: "weak".into(),
        });
    }
}

fn same_application(left: &Application, right: &Application) -> bool {
    left.id.eq_ignore_ascii_case(&right.id)
        || left.package_family_name.as_deref().zip(right.package_family_name.as_deref())
            .is_some_and(|(a, b)| a.eq_ignore_ascii_case(b))
        || left.install_location.as_deref().zip(right.install_location.as_deref())
            .is_some_and(|(a, b)| !a.is_empty() && a.eq_ignore_ascii_case(b))
        || normalize_name(&left.name) == normalize_name(&right.name)
}

/// Carries forward a previously observed owner only when the same resource remains
/// and the current app inventory has no matching installation. It makes no safety claim.
pub fn apply_history(result: &mut DirectoryResult, current: &Inventory, previous: &Inventory, previous_result: Option<&DirectoryResult>) {
    if result.owner.is_some() || !current.warnings.is_empty() || !previous.warnings.is_empty() {
        return;
    }
    let Some(previous_result) = previous_result else { return; };
    let Some(previous_owner) = previous_result.owner.as_ref() else { return; };
    if !previous_result.path.eq_ignore_ascii_case(&result.path) { return; }
    if current.applications.iter().any(|app| same_application(app, previous_owner)) { return; }
    let previously_observed = match previous_result.orphan_status.as_str() {
        "not_orphaned" => previous.applications.iter().any(|app| same_application(app, previous_owner)),
        "probable_orphan" | "possibly_orphaned" => true,
        _ => false,
    };
    if !previously_observed { return; }
    let strong_history = previous_result.ownership == "confirmed"
        || previous_result.ownership == "historical_confirmed";
    result.owner = Some(previous_owner.clone());
    result.ownership = if strong_history { "historical_confirmed" } else { "historical_likely" }.into();
    result.orphan_status = if strong_history { "probable_orphan" } else { "possibly_orphaned" }.into();
    result.evidence.push(Evidence {
        kind: "historical_owner".into(),
        description: format!("A previous completed scan linked this exact directory to {}.", previous_owner.name),
        strength: if strong_history { "strong" } else { "medium" }.into(),
    });
    result.evidence.push(Evidence {
        kind: "missing_installed_app".into(),
        description: format!("{} is absent from the current uninstall and current-user package inventory. Portable or unregistered installations may still exist.", previous_owner.name),
        strength: "weak".into(),
    });
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
    let mut result = DirectoryResult {
        path: path.to_string_lossy().into_owned(), root: root.to_owned(), size_bytes: size,
        file_count: files, directory_count: directories, newest_modified_unix: newest,
        skipped_entries: skipped, owner, owner_hint: None, ownership, orphan_status, evidence,
    };
    enrich_directory(&mut result, apps);
    on_result(result);
}

fn is_excluded(path: &Path, excluded_paths: &[PathBuf]) -> bool {
    excluded_paths.iter().any(|excluded| path.to_string_lossy().eq_ignore_ascii_case(&excluded.to_string_lossy()))
}

pub fn scan<F, P>(apps: &[Application], excluded_paths: &[PathBuf], cancel: &AtomicBool, mut on_result: F, mut on_progress: P) -> ScanSummary
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
            if is_excluded(&path, excluded_paths) { continue; }
            let structural_container = label == "Local" && ["Packages", "Programs"].iter().any(|name| entry.file_name().to_string_lossy().eq_ignore_ascii_case(name));
            if structural_container {
                let Ok(children) = fs::read_dir(&path) else { summary.skipped_entries += 1; continue; };
                for child in children {
                    if cancel.load(Ordering::Relaxed) { break; }
                    let Ok(child) = child else { summary.skipped_entries += 1; continue; };
                    let child_path = child.path();
                    if is_excluded(&child_path, excluded_paths) { continue; }
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
        assert_eq!(product_name_without_version("Signal 8.28.0"), "Signal");
        assert_eq!(product_name_without_version("Microsoft 365"), "Microsoft 365");
        assert_eq!(product_name_without_version("7-Zip 25.01"), "7-Zip");
    }

    #[test]
    fn display_icon_accepts_only_an_existing_executable() {
        let executable = std::env::current_exe().unwrap();
        let executable = executable.to_string_lossy();
        assert_eq!(display_icon_executable(&format!("\"{executable}\",0")), Some(executable.to_string()));
        assert_eq!(display_icon_executable(r"C:\Missing\App.exe,0"), None);
        assert_eq!(display_icon_executable(r"C:\Windows\System32\shell32.dll,0"), None);
    }

    #[test]
    fn missing_app_does_not_make_an_orphan() {
        let (_, ownership, orphan, _) = resolve_owner(Path::new(r"C:\Users\Test\AppData\Roaming\OldGame"), &[]);
        assert_eq!(ownership, "unknown");
        assert_eq!(orphan, "unknown");
    }

    #[test]
    fn active_exact_match_is_not_orphaned() {
        let app = Application { id: "test".into(), name: "Notion".into(), publisher: None, version: None, install_location: None, display_icon_executable: None, package_family_name: None, sources: vec!["test".into()] };
        let (owner, ownership, orphan, evidence) = resolve_owner(Path::new(r"C:\Users\Test\AppData\Roaming\Notion"), &[app]);
        assert_eq!(owner.unwrap().name, "Notion");
        assert_eq!(ownership, "likely");
        assert_eq!(orphan, "not_orphaned");
        assert_eq!(evidence.len(), 1);
    }

    #[test]
    fn package_family_beats_an_unrelated_name_match() {
        let package = Application { id: "package".into(), name: "Calculator".into(), publisher: None, version: None, install_location: None, display_icon_executable: None, package_family_name: Some("Microsoft.WindowsCalculator_8wekyb3d8bbwe".into()), sources: vec!["MSIX".into()] };
        let unrelated = Application { id: "name".into(), name: "Microsoft.WindowsCalculator_8wekyb3d8bbwe".into(), publisher: None, version: None, install_location: None, display_icon_executable: None, package_family_name: None, sources: vec!["registry".into()] };
        let (owner, ownership, orphan, evidence) = resolve_owner(Path::new(r"C:\Users\Test\AppData\Local\Packages\Microsoft.WindowsCalculator_8wekyb3d8bbwe"), &[package, unrelated]);
        assert_eq!(owner.unwrap().id, "package");
        assert_eq!(ownership, "confirmed");
        assert_eq!(orphan, "not_orphaned");
        assert_eq!(evidence[0].kind, "package_family_match");
    }

    #[test]
    fn registered_executable_matches_only_its_own_directory() {
        let mut app = example_app("registered-app");
        app.name = "Different Product Name".into();
        app.display_icon_executable = Some(r"C:\Users\Test\AppData\Local\Programs\Example\Example.exe".into());
        let (owner, ownership, _, evidence) = resolve_owner(
            Path::new(r"C:\Users\Test\AppData\Local\Programs\Example"), &[app.clone()]);
        assert_eq!(owner.unwrap().id, app.id);
        assert_eq!(ownership, "confirmed");
        assert_eq!(evidence[0].kind, "registered_executable");
        let (owner, _, _, _) = resolve_owner(
            Path::new(r"C:\Users\Test\AppData\Local\Programs"), &[app]);
        assert!(owner.is_none());
    }

    #[test]
    fn multiple_registered_executables_remain_ambiguous() {
        let mut first = example_app("first");
        first.display_icon_executable = Some(r"C:\Apps\Shared\First.exe".into());
        let mut second = example_app("second");
        second.display_icon_executable = Some(r"C:\Apps\Shared\Second.exe".into());
        let (owner, ownership, _, evidence) = resolve_owner(Path::new(r"C:\Apps\Shared"), &[first, second]);
        assert!(owner.is_none());
        assert_eq!(ownership, "shared");
        assert_eq!(evidence[0].kind, "multiple_matches");
    }

    #[test]
    fn versioned_uninstall_name_matches_product_data_folder() {
        let mut app = example_app("signal");
        app.name = "Signal 8.28.0".into();
        let (owner, ownership, status, evidence) = resolve_owner(
            Path::new(r"C:\Users\Test\AppData\Roaming\Signal"), &[app]);
        assert_eq!(owner.unwrap().name, "Signal 8.28.0");
        assert_eq!(ownership, "likely");
        assert_eq!(status, "not_orphaned");
        assert_eq!(evidence[0].kind, "directory_name_match");
    }

    #[test]
    fn vendor_directory_is_associated_without_single_owner() {
        let mut driver = example_app("driver");
        driver.name = "NVIDIA Graphics Driver 617.14".into();
        driver.publisher = Some("NVIDIA Corporation".into());
        let mut app = example_app("nvidia-app");
        app.name = "NVIDIA App 11.0.9.251".into();
        app.publisher = Some("NVIDIA Corporation".into());
        let (owner, ownership, status, evidence) = resolve_owner(
            Path::new(r"C:\ProgramData\NVIDIA Corporation"), &[driver.clone(), app.clone()]);
        assert!(owner.is_none());
        assert_eq!(ownership, "shared");
        assert_eq!(status, "associated_with_installed");
        assert_eq!(evidence[0].kind, "vendor_or_install_segment");
        let mut result = example_result(None, &ownership, &status);
        result.path = r"C:\ProgramData\NVIDIA Corporation".into();
        enrich_directory(&mut result, &[driver, app]);
        assert_eq!(result.owner_hint.as_deref(), Some("NVIDIA Corporation"));
        assert_eq!(result.orphan_status, "associated_with_installed");
    }

    #[test]
    fn install_path_component_associates_brave_vendor_data() {
        let mut app = example_app("brave");
        app.name = "Brave".into();
        app.install_location = Some(r"C:\Program Files\BraveSoftware\Brave-Browser\Application".into());
        let (owner, ownership, status, _) = resolve_owner(
            Path::new(r"C:\Users\Test\AppData\Local\BraveSoftware"), &[app]);
        assert!(owner.is_none());
        assert_eq!(ownership, "shared");
        assert_eq!(status, "associated_with_installed");
        assert_eq!(shared_vendor_hint(Path::new(r"C:\Users\Test\AppData\Local\BraveSoftware"), &[]).as_deref(), Some("BraveSoftware"));
    }

    #[test]
    fn studio_family_is_associated_without_claiming_exclusive_owner() {
        let mut app = example_app("android-studio");
        app.name = "Android Studio".into();
        let (owner, ownership, status, _) = resolve_owner(
            Path::new(r"C:\Users\Test\AppData\Local\Android"), &[app]);
        assert!(owner.is_none());
        assert_eq!(ownership, "shared");
        assert_eq!(status, "associated_with_installed");
    }

    #[test]
    fn package_product_name_links_codex_data() {
        let mut app = example_app("codex-msix");
        app.name = "OpenAI.Codex".into();
        app.package_family_name = Some("OpenAI.Codex_2p2nqsd0c76g0".into());
        let (owner, ownership, status, _) = resolve_owner(
            Path::new(r"C:\Users\Test\AppData\Roaming\Codex"), &[app]);
        assert_eq!(owner.unwrap().name, "OpenAI.Codex");
        assert_eq!(ownership, "likely");
        assert_eq!(status, "not_orphaned");
    }

    #[test]
    fn tft_alias_links_installed_teamfight_tactics_without_choosing_between_editions() {
        let mut live = example_app("tft-live");
        live.name = "Teamfight Tactics".into();
        live.publisher = Some("Riot Games, Inc".into());
        let mut pbe = example_app("tft-pbe");
        pbe.name = "Teamfight Tactics PBE".into();
        pbe.publisher = Some("Riot Games, Inc".into());
        let apps = vec![live, pbe];
        let (owner, ownership, status, evidence) = resolve_owner(
            Path::new(r"C:\Users\Test\AppData\Local\TFT"), &apps);
        assert!(owner.is_none());
        assert_eq!(ownership, "shared");
        assert_eq!(status, "associated_with_installed");
        assert!(evidence[0].description.contains("Teamfight Tactics"));
        let mut result = example_result(None, &ownership, &status);
        result.path = r"C:\Users\Test\AppData\Local\TFT".into();
        result.root = "Local".into();
        enrich_directory(&mut result, &apps);
        assert_eq!(result.owner_hint.as_deref(), Some("Teamfight Tactics"));
    }

    #[test]
    fn nested_valheim_folder_and_publisher_link_iron_gate() {
        let parent = std::env::temp_dir().join(format!("orphan-cleaner-test-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos())).join("IronGate");
        fs::create_dir_all(parent.join("Valheim")).unwrap();
        let mut app = example_app("valheim");
        app.name = "Valheim".into();
        app.publisher = Some("Iron Gate AB".into());
        let owner = nested_installed_owner(&parent, &[app]).unwrap();
        assert_eq!(owner.name, "Valheim");
        fs::remove_dir_all(parent.parent().unwrap()).unwrap();
    }

    #[test]
    fn listed_common_locations_are_recognized_without_an_orphan_claim() {
        for (root, name) in [
            ("Local", "wsl"), ("Local", "Temp"), ("ProgramData", "Package Cache"),
            ("Local", "pnpm"), ("Local", "NuGet"), ("Local", "npm-cache"),
            ("Local", "Pub"), ("Roaming", "npm"), ("Local", "CrashDumps"),
            ("Local", "electron"), ("Local", "D3DSCache"), ("Local", "pnpm-cache"),
            ("LocalLow", "Unfrozen"), ("Local", "pip"), ("Roaming", "EasyAntiCheat"),
            ("Roaming", "AMD"), ("Local", "Comms"), ("Local", "electron-builder"),
            ("Roaming", "Electron"), ("ProgramData", "Windows App Certification Kit"),
            ("Local", "AMDSoftwareInstaller"),
        ] {
            let location = known_locations::lookup(root, name).unwrap_or_else(|| panic!("missing {root}/{name}"));
            assert!(!location.possible_former, "{root}/{name} must not imply an uninstall");
        }
    }

    #[test]
    fn image_line_and_aion_are_only_possible_former_data() {
        for (root, name) in [("Roaming", "Image-Line"), ("Local", "AION2")] {
            let mut result = example_result(None, "unknown", "unknown");
            result.root = root.into();
            result.path = format!(r"C:\Users\Test\AppData\{root}\{name}");
            enrich_directory(&mut result, &[]);
            assert_eq!(result.orphan_status, "possibly_orphaned");
            assert_eq!(result.ownership, "known_location");
            assert!(result.owner.is_none());
            assert!(result.owner_hint.is_some());
        }
    }

    #[test]
    fn app_data_exclusion_ignores_windows_path_case() {
        let excluded = vec![PathBuf::from(r"C:\Users\Test\AppData\Local\dev.orphancleaner.desktop")];
        assert!(is_excluded(Path::new(r"c:\users\test\appdata\local\DEV.ORPHANCLEANER.DESKTOP"), &excluded));
    }

    fn example_app(id: &str) -> Application {
        Application { id: id.into(), name: "Example".into(), publisher: None, version: None,
            install_location: None, display_icon_executable: None, package_family_name: None, sources: vec!["registry".into()] }
    }

    fn example_result(owner: Option<Application>, ownership: &str, status: &str) -> DirectoryResult {
        DirectoryResult { path: r"C:\Users\Test\AppData\Roaming\Example".into(), root: "Roaming".into(),
            size_bytes: 100, file_count: 1, directory_count: 0, newest_modified_unix: None,
            skipped_entries: 0, owner, owner_hint: None, ownership: ownership.into(), orphan_status: status.into(), evidence: vec![] }
    }

    #[test]
    fn strong_previous_relationship_becomes_probable_leftover() {
        let app = example_app("old-registry-key");
        let previous = Inventory { applications: vec![app.clone()], warnings: vec![] };
        let current = Inventory { applications: vec![], warnings: vec![] };
        let before = example_result(Some(app), "confirmed", "not_orphaned");
        let mut now = example_result(None, "unknown", "unknown");
        apply_history(&mut now, &current, &previous, Some(&before));
        assert_eq!(now.orphan_status, "probable_orphan");
        assert_eq!(now.evidence.len(), 2);
    }

    #[test]
    fn name_only_history_remains_tentative_and_incomplete_inventory_is_ignored() {
        let app = example_app("old-registry-key");
        let previous = Inventory { applications: vec![app.clone()], warnings: vec![] };
        let before = example_result(Some(app), "likely", "not_orphaned");
        let mut now = example_result(None, "unknown", "unknown");
        let incomplete = Inventory { applications: vec![], warnings: vec!["MSIX unavailable".into()] };
        apply_history(&mut now, &incomplete, &previous, Some(&before));
        assert_eq!(now.orphan_status, "unknown");
        let complete = Inventory { applications: vec![], warnings: vec![] };
        apply_history(&mut now, &complete, &previous, Some(&before));
        assert_eq!(now.orphan_status, "possibly_orphaned");
    }

    #[test]
    fn updated_registration_prevents_false_removal() {
        let app = example_app("old-registry-key");
        let previous = Inventory { applications: vec![app.clone()], warnings: vec![] };
        let current = Inventory { applications: vec![example_app("new-registry-key")], warnings: vec![] };
        let before = example_result(Some(app), "confirmed", "not_orphaned");
        let mut now = example_result(None, "unknown", "unknown");
        apply_history(&mut now, &current, &previous, Some(&before));
        assert_eq!(now.orphan_status, "unknown");
    }
}
