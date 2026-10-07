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
use windows::core::{GUID, PCWSTR};
use windows::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};
use windows::Win32::System::Com::{CoInitializeEx, CoTaskMemFree, CoUninitialize, COINIT_MULTITHREADED};
use windows::Win32::UI::Shell::{SHGetKnownFolderPath, KF_FLAG_DEFAULT, FOLDERID_CommonPrograms, FOLDERID_CommonStartup, FOLDERID_Desktop, FOLDERID_Documents, FOLDERID_Downloads, FOLDERID_Favorites, FOLDERID_Music, FOLDERID_Pictures, FOLDERID_Public, FOLDERID_SavedGames, FOLDERID_Videos, FOLDERID_LocalAppData, FOLDERID_LocalAppDataLow, FOLDERID_Profile, FOLDERID_ProgramData, FOLDERID_ProgramFilesX64, FOLDERID_ProgramFilesX86, FOLDERID_Programs, FOLDERID_RoamingAppData, FOLDERID_Startup};

mod known_locations;
pub mod assessment;
pub mod content;
pub mod definitions;
pub mod executables;
pub mod public_data;
pub mod references;

pub use assessment::{Assessment, Reason, assess};
pub use content::{ContentItem, ContentProfile, ExtensionStat};
pub use definitions::Definitions;
pub use executables::ExecutableInfo;
pub use references::{ReferenceInventory, SystemReference};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
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

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    pub kind: String,
    pub description: String,
    pub strength: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryResult {
    pub path: String,
    pub root: String,
    #[serde(default)]
    pub parent_path: Option<String>,
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
    #[serde(default)]
    pub oldest_modified_unix: Option<u64>,
    #[serde(default)]
    pub created_unix: Option<u64>,
    /// Treatment class of a recognized location: app_data | system | shared_runtime | tool_cache | user_data.
    #[serde(default)]
    pub location_class: Option<String>,
    #[serde(default)]
    pub content: ContentProfile,
    #[serde(default)]
    pub executables: Vec<ExecutableInfo>,
    #[serde(default)]
    pub assessment: Assessment,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanSummary {
    #[serde(default)]
    pub mode: String,
    /// True when every expected root was enumerated and the scan was not canceled.
    #[serde(default)]
    pub complete: bool,
    #[serde(default)]
    pub started_at_unix: u64,
    #[serde(default)]
    pub duration_ms: u64,
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

pub(crate) fn product_name_without_version(name: &str) -> String {
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
    if product.last().is_some_and(|word| word.eq_ignore_ascii_case("version")) {
        product.pop();
    }
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
            let uninstall = match uninstall {
                Ok(uninstall) => uninstall,
                // A missing key simply means nothing is registered there (common for HKCU).
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => {
                    warnings.push(format!("Could not read {hive_name} {view}-bit uninstall entries."));
                    continue;
                }
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
    let output = Command::new(powershell_path())
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

/// Absolute path to Windows PowerShell, so a same-named file next to the app is never run.
pub fn powershell_path() -> PathBuf {
    let root = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    root.join("System32").join("WindowsPowerShell").join("v1.0").join("powershell.exe")
}

pub fn installed_applications() -> Inventory {
    let (mut applications, mut warnings) = registry_applications();
    match msix_applications() {
        Ok(mut packages) => applications.append(&mut packages),
        Err(warning) => warnings.push(warning),
    }
    // AppX can list multiple architecture/resource variants of the same family.
    let mut identities = HashSet::new();
    applications.retain(|app| identities.insert(app.id.to_lowercase()));
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

fn publisher_container_match(folder: &str, publisher: &str) -> bool {
    let folder = normalize_name(folder);
    let publisher_name = normalize_name(publisher);
    let vendor = vendor_name(publisher);
    if folder == publisher_name || folder == vendor {
        return true;
    }
    if vendor.len() < 4 {
        return false;
    }
    folder.strip_prefix(&vendor).is_some_and(|suffix| {
        matches!(suffix, "cloud" | "software" | "audio" | "games" | "entertainment")
    })
}

fn package_namespace_prefix(app: &Application) -> Option<String> {
    app.package_family_name.as_ref()?;
    product_name_without_version(&app.name).rsplit_once('.')
        .map(|(prefix, _)| normalize_name(prefix))
        .filter(|prefix| prefix.len() >= 4)
}

fn versioned_name(value: &str) -> Option<(String, Vec<u64>)> {
    let value = value.trim();
    let version_start = value.char_indices().find_map(|(index, ch)| {
        (ch.is_ascii_digit()
            && value[index..].chars().all(|tail| {
                tail.is_ascii_digit() || matches!(tail, '.' | '-' | '_' | ' ')
            }))
        .then_some(index)
    })?;
    let product = value[..version_start].trim_end_matches([' ', '-', '_']);
    let version = value[version_start..]
        .split(|ch: char| !ch.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .map(str::parse)
        .collect::<Result<Vec<u64>, _>>()
        .ok()?;
    (!product.is_empty() && !version.is_empty()).then(|| (normalize_name(product), version))
}

fn version_components(value: &str) -> Option<Vec<u64>> {
    let value = value.trim();
    if value.is_empty()
        || !value.chars().all(|ch| ch.is_ascii_digit() || matches!(ch, '.' | '-' | '_' | ' '))
    {
        return None;
    }
    let version = value
        .split(|ch: char| !ch.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .map(str::parse)
        .collect::<Result<Vec<u64>, _>>()
        .ok()?;
    (!version.is_empty()).then_some(version)
}

fn nested_product_version(path: &Path, app: &Application) -> Option<Vec<u64>> {
    let Some(parent) = path.parent().and_then(Path::file_name) else { return None; };
    let Some(publisher) = app.publisher.as_deref() else { return None; };
    let parent = normalize_name(&parent.to_string_lossy());
    if normalize_name(publisher) != parent && vendor_name(publisher) != parent {
        return None;
    }

    let product = normalize_name(&product_name_without_version(&app.name));
    let Some((child_product, child_version)) = path.file_name()
        .and_then(|name| versioned_name(&name.to_string_lossy())) else { return None; };
    // Registrations such as "JetBrains Rider 2024.1" repeat the publisher before the
    // product; the version folder then names only the product ("Rider2024.1").
    let without_publisher = product.strip_prefix(&normalize_name(publisher))
        .or_else(|| product.strip_prefix(&vendor_name(publisher)))
        .filter(|rest| rest.len() >= 4);
    let matches = (product.len() >= 4 && child_product == product) || without_publisher == Some(child_product.as_str());
    if !matches {
        return None;
    }
    Some(child_version)
}

#[derive(Clone, Copy)]
enum DirectoryNameMatch {
    Ordinary,
    NestedVersion,
    NestedNamespace,
    NestedVendorProduct,
    ReverseDomainProduct,
    UpdaterAlias,
    LauncherComponent,
}

fn product_component_alias(name: &str, app: &Application) -> Option<DirectoryNameMatch> {
    let lower = name.to_ascii_lowercase();
    let updater_base = ["-updater", "_updater", " updater"].iter()
        .find_map(|suffix| lower.strip_suffix(suffix));
    let component_base = ["-ux", "_ux", "-components", "_components", "persistent"].iter()
        .find_map(|suffix| lower.strip_suffix(suffix));
    let product = normalize_name(&product_name_without_version(&app.name));
    if product.len() < 4 {
        return None;
    }
    if updater_base.is_some_and(|base| normalize_name(base) == product) {
        return Some(DirectoryNameMatch::UpdaterAlias);
    }
    if component_base.is_some_and(|base| normalize_name(base) == product) {
        return Some(DirectoryNameMatch::LauncherComponent);
    }
    None
}

fn reverse_domain_parts(name: &str) -> Option<Vec<String>> {
    let mut parts = name.split('.');
    let prefix = parts.next()?.to_ascii_lowercase();
    if !matches!(prefix.as_str(), "com" | "org" | "net" | "io" | "ai" | "dev") {
        return None;
    }
    let parts = parts.map(normalize_name).collect::<Vec<_>>();
    if parts.is_empty() || parts.iter().any(String::is_empty)
        || matches!(parts[0].as_str(), "example" | "sample" | "test" | "common" | "unknown") {
        return None;
    }
    Some(parts)
}

fn reverse_domain_product_match(name: &str, app: &Application) -> bool {
    let Some(parts) = reverse_domain_parts(name) else { return false; };
    let product = normalize_name(&product_name_without_version(&app.name));
    product.len() >= 4 && parts.concat() == product
}

fn reverse_domain_vendor_match(name: &str, app: &Application) -> bool {
    let Some(parts) = reverse_domain_parts(name) else { return false; };
    let Some(publisher) = app.publisher.as_deref() else { return false; };
    let vendor = &parts[0];
    vendor.len() >= 4
        && (normalize_name(publisher) == *vendor || vendor_name(publisher) == *vendor)
}

fn nested_named_product_match(path: &Path, app: &Application) -> Option<DirectoryNameMatch> {
    let parent = path.parent()?.file_name()?.to_string_lossy();
    let child = path.file_name()?.to_string_lossy();
    let joined = normalize_name(&format!("{parent}.{child}"));
    if app.package_family_name.is_some()
        && app.name.contains('.')
        && joined == normalize_name(&product_name_without_version(&app.name)) {
        return Some(DirectoryNameMatch::NestedNamespace);
    }

    let publisher = app.publisher.as_deref()?;
    if !publisher_container_match(&parent, publisher) {
        return None;
    }
    let child = normalize_name(&child);
    let product = normalize_name(&product_name_without_version(&app.name));
    let publisher_name = normalize_name(publisher);
    let vendor = vendor_name(publisher);
    let stripped = product.strip_prefix(&publisher_name)
        .or_else(|| product.strip_prefix(&vendor));
    (child == product || stripped.is_some_and(|product| product.len() >= 4 && product == child))
        .then_some(DirectoryNameMatch::NestedVendorProduct)
}

fn registered_product_versions(app: &Application) -> Vec<Vec<u64>> {
    let mut registered_versions = Vec::new();
    if let Some(version) = app.version.as_deref().and_then(version_components) {
        registered_versions.push(version);
    }
    if let Some((_, version)) = versioned_name(&app.name) {
        if !registered_versions.contains(&version) {
            registered_versions.push(version);
        }
    }
    registered_versions
}

fn versions_agree(left: &[u64], right: &[u64]) -> bool {
    let common = left.len().min(right.len());
    common > 0 && left[..common] == right[..common]
}

fn nested_versioned_product_match(path: &Path, app: &Application) -> bool {
    let Some(child_version) = nested_product_version(path, app) else { return false; };
    let registered_versions = registered_product_versions(app);
    registered_versions.iter().any(|version| versions_agree(version, &child_version))
}

fn same_product_family(left: &Application, right: &Application) -> bool {
    if normalize_name(&product_name_without_version(&left.name))
        != normalize_name(&product_name_without_version(&right.name)) {
        return false;
    }
    left.publisher.as_deref().zip(right.publisher.as_deref()).is_some_and(|(left, right)| {
        normalize_name(left) == normalize_name(right) || vendor_name(left) == vendor_name(right)
    })
}

fn version_is_strictly_newer(current: &[u64], previous: &[u64]) -> bool {
    let length = current.len().max(previous.len());
    (0..length).find_map(|index| {
        let current = current.get(index).copied().unwrap_or(0);
        let previous = previous.get(index).copied().unwrap_or(0);
        (current != previous).then_some(current > previous)
    }).unwrap_or(false)
}

fn has_strictly_newer_comparable_version(previous: &Application, current: &Application, directory_version: &[u64]) -> bool {
    let previous_display = previous.version.as_deref().and_then(version_components);
    let current_display = current.version.as_deref().and_then(version_components);
    let display_is_newer = previous_display.as_deref().zip(current_display.as_deref())
        .is_some_and(|(previous, current)| {
            versions_agree(previous, directory_version)
                && version_is_strictly_newer(current, directory_version)
        });
    let previous_name = versioned_name(&previous.name).map(|(_, version)| version);
    let current_name = versioned_name(&current.name).map(|(_, version)| version);
    let name_is_newer = previous_name.as_deref().zip(current_name.as_deref())
        .is_some_and(|(previous, current)| {
            versions_agree(previous, directory_version)
                && version_is_strictly_newer(current, directory_version)
        });
    display_is_newer || name_is_newer
}

pub fn local_app_data_path() -> Option<PathBuf> {
    known_folder_path(&FOLDERID_LocalAppData)
        .or_else(|| std::env::var_os("LOCALAPPDATA").map(PathBuf::from))
}

pub fn downloads_path() -> Option<PathBuf> {
    known_folder_path(&FOLDERID_Downloads)
        .or_else(|| std::env::var_os("USERPROFILE").map(|profile| PathBuf::from(profile).join("Downloads")))
}

pub fn user_profile_path() -> Option<PathBuf> {
    known_folder_path(&FOLDERID_Profile)
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
}

/// Start Menu and Startup folders for the current user and all users.
pub(crate) fn shortcut_directories() -> Vec<(&'static str, PathBuf, bool)> {
    let mut directories = Vec::new();
    for (kind, id, machine_wide) in [
        ("startup_folder", &FOLDERID_Startup, false),
        ("startup_folder", &FOLDERID_CommonStartup, true),
        ("start_menu_shortcut", &FOLDERID_Programs, false),
        ("start_menu_shortcut", &FOLDERID_CommonPrograms, true),
    ] {
        if let Some(path) = known_folder_path(id) {
            directories.push((kind, path, machine_wide));
        }
    }
    directories
}

/// Folders that hold the user's own files or define scan roots. Cleanup refuses
/// these folders and any folder that contains one of them.
pub fn protected_folders() -> Vec<PathBuf> {
    let mut folders: Vec<PathBuf> = [
        &FOLDERID_Profile, &FOLDERID_Documents, &FOLDERID_Desktop, &FOLDERID_Pictures, &FOLDERID_Music, &FOLDERID_Videos,
        &FOLDERID_Downloads, &FOLDERID_SavedGames, &FOLDERID_Favorites, &FOLDERID_LocalAppData, &FOLDERID_RoamingAppData,
        &FOLDERID_LocalAppDataLow, &FOLDERID_ProgramData, &FOLDERID_ProgramFilesX64, &FOLDERID_ProgramFilesX86,
        &FOLDERID_Programs, &FOLDERID_CommonPrograms, &FOLDERID_Startup, &FOLDERID_CommonStartup,
    ].into_iter().filter_map(known_folder_path).collect();
    for variable in ["OneDrive", "OneDriveConsumer", "OneDriveCommercial", "SystemRoot", "USERPROFILE", "PUBLIC"] {
        if let Some(value) = std::env::var_os(variable) {
            folders.push(PathBuf::from(value));
        }
    }
    folders.retain(|folder| folder.components().count() >= 2);
    folders
}

/// Directories where `.lnk` files may be quarantined as dead shortcuts.
pub fn shortcut_roots() -> Vec<PathBuf> {
    shortcut_directories().into_iter().map(|(_, path, _)| path).collect()
}

/// Resolved Windows Startup folders, including their all-users scope.
pub fn startup_directories() -> Vec<(PathBuf, bool)> {
    shortcut_directories().into_iter().filter(|(kind, _, _)| *kind == "startup_folder")
        .map(|(_, path, machine_wide)| (path, machine_wide)).collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ScanMode {
    /// AppData, ProgramData, Downloads, Public, and other fixed-drive Downloads.
    #[default]
    Quick,
    /// Adds Program Files, personal folders, the user profile, and executable metadata.
    Deep,
}

impl ScanMode {
    pub fn as_str(self) -> &'static str {
        match self { Self::Quick => "quick", Self::Deep => "deep" }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value { "quick" => Some(Self::Quick), "deep" => Some(Self::Deep), _ => None }
    }
}

/// A scan root: label used for classification and the resolved folder.
#[derive(Clone, Debug)]
pub struct ScanRoot {
    pub label: String,
    pub path: PathBuf,
}

pub fn scan_roots(mode: ScanMode) -> (Vec<ScanRoot>, Vec<String>, usize) {
    scan_roots_with_apps(mode, &[])
}

fn fixed_drives() -> Result<Vec<PathBuf>, String> {
    let mask = unsafe { GetLogicalDrives() };
    if mask == 0 { return Err("Windows could not enumerate logical drives.".into()); }
    let mut drives = Vec::new();
    for index in 0..26u32 {
        if mask & (1 << index) == 0 { continue; }
        let root = format!("{}:\\", (b'A' + index as u8) as char);
        let wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();
        // DRIVE_FIXED = 3; removable and network drives are deliberately omitted.
        if unsafe { GetDriveTypeW(PCWSTR(wide.as_ptr())) } == 3 {
            drives.push(PathBuf::from(root));
        }
    }
    Ok(drives)
}

fn discover_conventional_roots(drives: &[PathBuf]) -> Vec<ScanRoot> {
    let mut roots = Vec::new();
    for drive in drives {
        for top in fs::read_dir(drive).into_iter().flatten().flatten() {
            let path = top.path();
            let Ok(metadata) = fs::symlink_metadata(&path) else { continue; };
            if !metadata.is_dir() || is_reparse_point(&metadata) { continue; }
            let name = top.file_name().to_string_lossy().to_ascii_lowercase();
            if name == "downloads" {
                roots.push(ScanRoot { label: "OtherDownloads".into(), path });
                continue;
            }
            if name == "temp" || name == "tmp" {
                roots.push(ScanRoot { label: "OtherTemp".into(), path });
                continue;
            }
            if name == "program files" || name == "program files (x86)" {
                roots.push(ScanRoot { label: if name == "program files" { "ProgramFiles" } else { "ProgramFilesX86" }.into(), path });
                continue;
            }
            if matches!(name.as_str(), "users" | "windows" | "programdata" | "windowsapps" | "system volume information" | "$recycle.bin" | "recovery") { continue; }
            let child_path = path.join("Downloads");
            if fs::symlink_metadata(&child_path).is_ok_and(|metadata| metadata.is_dir() && !is_reparse_point(&metadata)) {
                roots.push(ScanRoot { label: "OtherDownloads".into(), path: child_path });
            }
        }
    }
    roots
}

fn add_registered_install_roots(roots: &mut Vec<ScanRoot>, drives: &[PathBuf], apps: &[Application]) -> usize {
    let mut added = 0;
    for app in apps {
        let Some(location) = app.install_location.as_deref() else { continue; };
        let path = PathBuf::from(location.trim().trim_matches('"'));
        if !path.is_absolute() || path.components().count() < 4 { continue; }
        let name = path.file_name().map(|name| name.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
        if matches!(name.as_str(), "games" | "steamapps" | "common" | "program files" | "program files (x86)" | "windowsapps" | "users" | "documents" | "downloads" | "temp" | "tmp" | "mods" | "backup" | "backups") { continue; }
        if !drives.iter().any(|drive| references::path_is_within(&path.to_string_lossy(), &drive.to_string_lossy())) { continue; }
        if !fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.is_dir() && !is_reparse_point(&metadata)) { continue; }
        if roots.iter().any(|root| references::path_is_within(&path.to_string_lossy(), &root.path.to_string_lossy())) { continue; }
        added += 1;
        roots.push(ScanRoot { label: "RegisteredInstall".into(), path });
    }
    added
}

fn scan_roots_with_apps(mode: ScanMode, apps: &[Application]) -> (Vec<ScanRoot>, Vec<String>, usize) {
    let mut roots = Vec::new();
    let mut warnings = Vec::new();
    let mut entries: Vec<(&str, &GUID, &str)> = vec![
        ("Local", &FOLDERID_LocalAppData, "LOCALAPPDATA"),
        ("Roaming", &FOLDERID_RoamingAppData, "APPDATA"),
        ("LocalLow", &FOLDERID_LocalAppDataLow, ""),
        ("ProgramData", &FOLDERID_ProgramData, "PROGRAMDATA"),
        ("Downloads", &FOLDERID_Downloads, ""),
        ("Public", &FOLDERID_Public, "PUBLIC"),
    ];
    if mode == ScanMode::Deep {
        entries.push(("ProgramFiles", &FOLDERID_ProgramFilesX64, "ProgramW6432"));
        entries.push(("ProgramFilesX86", &FOLDERID_ProgramFilesX86, "ProgramFiles(x86)"));
        entries.push(("Documents", &FOLDERID_Documents, ""));
        entries.push(("Desktop", &FOLDERID_Desktop, ""));
        entries.push(("Pictures", &FOLDERID_Pictures, ""));
        entries.push(("Music", &FOLDERID_Music, ""));
        entries.push(("Videos", &FOLDERID_Videos, ""));
        entries.push(("SavedGames", &FOLDERID_SavedGames, ""));
        entries.push(("UserProfile", &FOLDERID_Profile, "USERPROFILE"));
    }
    let mut expected = entries.len();
    for (label, id, fallback) in entries {
        let optional_personal = matches!(label, "Documents" | "Downloads" | "Public" | "Desktop" | "Pictures" | "Music" | "Videos" | "SavedGames");
        let known = known_folder_path(id);
        let path = known.or_else(|| {
            let fallback_path = if label == "LocalLow" {
                std::env::var_os("USERPROFILE").map(|profile| PathBuf::from(profile).join("AppData").join("LocalLow"))
            } else if fallback.is_empty() {
                let folder = if label == "SavedGames" { "Saved Games" } else { label };
                std::env::var_os("USERPROFILE").map(|profile| PathBuf::from(profile).join(folder))
            } else {
                std::env::var_os(fallback).map(PathBuf::from)
            };
            if !optional_personal || fallback_path.as_ref().is_some_and(|path| path.is_dir()) {
                warnings.push(format!("Windows Known Folder lookup failed for {label}; using the environment fallback."));
            }
            fallback_path
        });
        match path {
            Some(path) if path.is_dir() => roots.push(ScanRoot { label: label.to_owned(), path }),
            _ if optional_personal => expected -= 1,
            _ => warnings.push(format!("{label} could not be scanned because its folder is unavailable.")),
        }
    }
    let drives = match fixed_drives() {
        Ok(drives) => drives,
        Err(error) => {
            warnings.push(format!("Additional fixed-drive folders were not discovered: {error}"));
            Vec::new()
        }
    };
    for root in discover_conventional_roots(&drives) {
        if mode != ScanMode::Deep && root.label != "OtherDownloads" { continue; }
        expected += 1;
        roots.push(root);
    }
    // Application totals include registered installation files in both scan modes.
    expected += add_registered_install_roots(&mut roots, &drives, apps);
    let mut seen = HashSet::new();
    let before = roots.len();
    roots.retain(|root| seen.insert(root.path.to_string_lossy().to_lowercase()));
    // Duplicate roots (e.g. identical Program Files folders on 32-bit systems) are not missing coverage.
    let expected = expected - (before - roots.len());
    (roots, warnings, expected)
}

#[cfg(windows)]
pub(crate) fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
pub(crate) fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn unix_seconds(time: std::io::Result<std::time::SystemTime>) -> Option<u64> {
    time.ok()?.duration_since(UNIX_EPOCH).ok().map(|duration| duration.as_secs())
}

/// Aggregate measurements for one directory tree. File contents are never read.
#[derive(Default)]
pub struct DirectoryStats {
    pub size: u64,
    pub files: u64,
    pub directories: u64,
    pub newest: Option<u64>,
    pub oldest: Option<u64>,
    pub created: Option<u64>,
    pub skipped: u64,
    pub content: ContentProfile,
    /// Executables at most two levels deep, largest first (paths are not persisted).
    pub shallow_executables: Vec<(PathBuf, u64)>,
}

pub fn inspect_directory(path: &Path, cancel: &AtomicBool) -> DirectoryStats {
    inspect_directory_inner(path, cancel, false)
}

fn inspect_directory_inner(path: &Path, cancel: &AtomicBool, loose_only: bool) -> DirectoryStats {
    use content::{ChildAccumulator, LARGE_FILE_BYTES, MAX_TRACKED_CHILDREN};
    let mut stats = DirectoryStats {
        created: fs::metadata(path).ok().and_then(|metadata| unix_seconds(metadata.created())),
        ..Default::default()
    };
    let mut children: Vec<ChildAccumulator> = Vec::new();
    let mut loose: std::collections::BTreeMap<&'static str, ChildAccumulator> = Default::default();
    let mut extensions: std::collections::BTreeMap<String, (u64, u64)> = Default::default();
    let mut untracked = ChildAccumulator::new("Other folders");
    let mut untracked_children = 0u64;
    let mut executable_count = 0u64;
    let mut database_count = 0u64;
    let mut large_file_count = 0u64;
    let mut large_file_bytes = 0u64;
    // (directory, child accumulator index; usize::MAX = untracked, None = root, depth)
    let mut pending: Vec<(PathBuf, Option<usize>, usize)> = vec![(path.to_path_buf(), None, 0)];
    while let Some((current, child_index, depth)) = pending.pop() {
        if cancel.load(Ordering::Relaxed) { break; }
        let Ok(entries) = fs::read_dir(&current) else {
            stats.skipped += 1;
            continue;
        };
        for entry in entries {
            if cancel.load(Ordering::Relaxed) { break; }
            let Ok(entry) = entry else { stats.skipped += 1; continue; };
            let entry_path = entry.path();
            let Ok(metadata) = fs::symlink_metadata(&entry_path) else { stats.skipped += 1; continue; };
            if is_reparse_point(&metadata) || metadata.file_type().is_symlink() {
                stats.skipped += 1;
                continue;
            }
            if metadata.is_dir() {
                if loose_only { continue; }
                stats.directories += 1;
                let name = entry.file_name().to_string_lossy().into_owned();
                let index = match child_index {
                    None if children.len() < MAX_TRACKED_CHILDREN => { children.push(ChildAccumulator::new(name)); Some(children.len() - 1) }
                    None => { untracked_children += 1; untracked.add_directory_name(&name); Some(usize::MAX) }
                    Some(index) => {
                        if index == usize::MAX { untracked.add_directory_name(&name); } else { children[index].add_directory_name(&name); }
                        Some(index)
                    }
                };
                pending.push((entry_path, index, depth + 1));
            } else if metadata.is_file() {
                let size = metadata.len();
                let modified = unix_seconds(metadata.modified());
                stats.files += 1;
                stats.size = stats.size.saturating_add(size);
                if let Some(seconds) = modified {
                    stats.newest = Some(stats.newest.map_or(seconds, |old| old.max(seconds)));
                    stats.oldest = Some(stats.oldest.map_or(seconds, |old| old.min(seconds)));
                }
                let extension = entry_path.extension().map(|extension| extension.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
                if !extension.is_empty() && extension.len() <= 16 {
                    let stat = extensions.entry(extension.clone()).or_default();
                    stat.0 = stat.0.saturating_add(size);
                    stat.1 += 1;
                }
                match extension.as_str() {
                    "exe" => {
                        executable_count += 1;
                        if depth <= 1 { stats.shallow_executables.push((entry_path.clone(), size)); }
                    }
                    "sqlite" | "sqlite3" | "db" | "db3" | "mdb" | "accdb" => database_count += 1,
                    _ => {}
                }
                if size >= LARGE_FILE_BYTES {
                    large_file_count += 1;
                    large_file_bytes = large_file_bytes.saturating_add(size);
                }
                match child_index {
                    None => {
                        let kind = content::kind_for_extension(&extension).unwrap_or("unknown");
                        loose.entry(kind).or_insert_with(|| ChildAccumulator::new(kind)).add_file(&extension, size, modified);
                    }
                    Some(usize::MAX) => untracked.add_file(&extension, size, modified),
                    Some(index) => children[index].add_file(&extension, size, modified),
                }
            }
        }
    }
    stats.shallow_executables.sort_by(|left, right| right.1.cmp(&left.1));
    stats.shallow_executables.truncate(3);
    stats.content = content::build_profile(children, loose, extensions, executable_count, database_count, large_file_count, large_file_bytes, untracked_children);
    if untracked_children > 0 {
        stats.content.categories.extend(untracked.categories());
        stats.content.categories.sort();
        stats.content.categories.dedup();
        let mut item = untracked.into_item(false);
        item.name = format!("{untracked_children} more folders");
        item.reason = format!("Only the first {MAX_TRACKED_CHILDREN} folders are listed individually. {}", item.reason);
        stats.content.items.push(item);
    }
    stats
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
    let mut nested_families = Vec::new();
    let mut reverse_domain_vendors = Vec::new();
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
        let nested_product_version = nested_product_version(path, app);
        let nested_name_match = if nested_versioned_product_match(path, app) {
            Some(DirectoryNameMatch::NestedVersion)
        } else {
            nested_named_product_match(path, app)
        };
        let package_namespace = package_namespace_prefix(app).is_some_and(|prefix| prefix == normalized);
        let reverse_domain_product = reverse_domain_product_match(&basename, app);
        let reverse_domain_vendor = reverse_domain_vendor_match(&basename, app);
        let product_component_alias = product_component_alias(&basename, app);
        let exact_install = app.install_location.as_deref().is_some_and(|location| {
            Path::new(location).to_string_lossy().trim_end_matches(['\\', '/']).eq_ignore_ascii_case(&path_string)
        });
        let exact_package = is_package_data && app.package_family_name.as_deref().is_some_and(|family| family.eq_ignore_ascii_case(&basename));
        let icon_inside = app.display_icon_executable.as_deref()
            .and_then(|icon| Path::new(icon).parent())
            .is_some_and(|parent| parent.to_string_lossy().trim_end_matches(['\\', '/']).eq_ignore_ascii_case(&path_string));
        if exact_install || exact_package || icon_inside {
            strong.push((app, exact_install, exact_package, icon_inside));
        } else if exact_name || versioned_name || package_product || desktop_folder || known_alias
            || nested_name_match.is_some() || reverse_domain_product || product_component_alias.is_some() {
            let name_match = if let Some(component) = product_component_alias {
                component
            } else if reverse_domain_product {
                DirectoryNameMatch::ReverseDomainProduct
            } else {
                nested_name_match.unwrap_or(DirectoryNameMatch::Ordinary)
            };
            names.push((app, name_match));
        } else if nested_product_version.is_some() {
            nested_families.push(app);
        } else if reverse_domain_vendor {
            reverse_domain_vendors.push(app);
        } else if product_family
            || package_namespace
            || app.publisher.as_deref().is_some_and(|publisher| normalize_name(publisher) == normalized || vendor_name(publisher) == normalized)
            || app.publisher.as_deref().is_some_and(|publisher| publisher_container_match(&basename, publisher))
            || app.install_location.as_deref().is_some_and(|location| install_path_has_component(location, &normalized)) {
            vendors.push(app);
        }
    }
    if strong.len() > 1 || (strong.is_empty() && names.len() > 1) {
        let matching = if strong.is_empty() { names.iter().map(|(app, _)| app.name.as_str()).collect::<Vec<_>>() }
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
    } else if let Some((app, name_match)) = names.first() {
        let (kind, description) = match name_match {
            DirectoryNameMatch::NestedVersion => ("nested_product_version_match", format!("The nested directory identifies installed product “{}” and its registered version under publisher {}.", app.name, app.publisher.as_deref().unwrap_or_default())),
            DirectoryNameMatch::NestedNamespace => ("nested_package_namespace_match", format!("The parent and child directory names exactly reconstruct installed package product “{}”.", app.name)),
            DirectoryNameMatch::NestedVendorProduct => ("nested_vendor_product_match", format!("The child directory exactly matches installed product “{}” inside its publisher container.", app.name)),
            DirectoryNameMatch::ReverseDomainProduct => ("reverse_domain_product_match", format!("The reverse-domain directory identifier exactly names installed product “{}”.", app.name)),
            DirectoryNameMatch::UpdaterAlias => ("updater_product_match", format!("Removing the explicit updater suffix leaves the exact normalized name of installed product “{}”. This associates the updater state with the active product but does not make it safe to remove.", app.name)),
            DirectoryNameMatch::LauncherComponent => ("launcher_component_match", format!("Removing the audited component suffix leaves the exact normalized name of installed product “{}”. This is active-product evidence, not cleanup approval.", app.name)),
            DirectoryNameMatch::Ordinary if normalize_name(&app.name) == normalized => ("directory_name_match", format!("The directory name exactly matches installed application “{}”.", app.name)),
            DirectoryNameMatch::Ordinary => ("directory_name_match", format!("The directory name matches a product or package-name variant of installed application “{}”.", app.name)),
        };
        (*app, "likely", vec![Evidence { kind: kind.into(), description, strength: "medium".into() }])
    } else {
        let nested_products: HashSet<String> = nested_families.iter()
            .map(|app| normalize_name(&product_name_without_version(&app.name))).collect();
        if nested_products.len() == 1 {
            let examples = nested_families.iter().take(3).map(|app| app.name.as_str()).collect::<Vec<_>>().join(", ");
            return (None, "product_family".into(), "unknown".into(), vec![Evidence {
                kind: "nested_product_version_mismatch".into(),
                description: format!("This nested directory names the same product family as installed software ({examples}), but its version does not agree with a current registration. That mismatch alone does not show whether the directory is active or abandoned."),
                strength: "weak".into(),
            }]);
        }
        if !reverse_domain_vendors.is_empty() {
            let examples = reverse_domain_vendors.iter().take(3)
                .map(|app| app.name.as_str()).collect::<Vec<_>>().join(", ");
            return (None, "shared".into(), "associated_with_installed".into(), vec![Evidence {
                kind: "reverse_domain_vendor_match".into(),
                description: format!("The vendor segment in this reverse-domain directory identifier matches installed software (for example: {examples}). The remaining identifier does not establish a single product owner."),
                strength: "weak".into(),
            }]);
        }
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
    let matching_publishers: Vec<&str> = apps.iter().filter(|app| {
        app.publisher.as_deref().is_some_and(|publisher| publisher_container_match(&folder, publisher))
            || reverse_domain_vendor_match(&folder, app)
    }).filter_map(|app| app.publisher.as_deref())
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
    if result.ownership == "product_family" {
        result.owner_hint = apps.iter()
            .find(|app| nested_product_version(Path::new(&result.path), app).is_some())
            .map(|app| product_name_without_version(&app.name));
        return;
    }
    if result.orphan_status != "unknown" { return; }
    let Some(name) = Path::new(&result.path).file_name() else { return; };
    let Some(known) = known_locations::lookup(&result.root, &name.to_string_lossy()) else { return; };
    result.owner_hint = Some(known.label.into());
    result.location_class = Some(known.class.as_str().into());
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

/// Classifies a directory without traversing its contents. This is the shared
/// entry point for the live scanner and the fixture-based ownership corpus.
/// Size and timestamp fields remain empty until the scanner measures them.
pub fn classify_directory(path: &Path, root: &str, apps: &[Application]) -> DirectoryResult {
    let (owner, ownership, orphan_status, evidence) = resolve_owner(path, apps);
    let mut result = DirectoryResult {
        path: path.to_string_lossy().into_owned(), root: root.to_owned(), parent_path: None, size_bytes: 0,
        file_count: 0, directory_count: 0, newest_modified_unix: None,
        skipped_entries: 0, owner, owner_hint: None, ownership, orphan_status, evidence,
        ..Default::default()
    };
    enrich_directory(&mut result, apps);
    if is_personal_scan_target(root, path) {
        result.location_class = Some("user_data".into());
        result.orphan_status = "user_files".into();
        result.evidence.push(Evidence {
            kind: "personal_location".into(),
            description: "This personal folder is scanned for review. Its contents are not application leftovers or cleanup candidates.".into(),
            strength: "strong".into(),
        });
    }
    result
}

fn is_personal_scan_target(root: &str, path: &Path) -> bool {
    match root {
        "Documents" | "Downloads" | "OtherDownloads" | "OtherTemp" | "Public" | "Desktop" | "Pictures" | "Music" | "Videos" | "SavedGames" => true,
        "UserProfile" => path.file_name().is_none_or(|name| !known_locations::USER_PROFILE_DEVELOPER_FOLDERS
            .iter().any(|folder| folder.eq_ignore_ascii_case(&name.to_string_lossy()))),
        _ => false,
    }
}

/// Compares application records across scans while tolerating registry-key or
/// package inventory changes that preserve another stable identity signal.
pub fn same_application(left: &Application, right: &Application) -> bool {
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
    if result.location_class.as_deref() == Some("user_data") || result.owner.is_some() || !current.warnings.is_empty() || !previous.warnings.is_empty() {
        return;
    }
    let Some(previous_result) = previous_result else { return; };
    let Some(previous_owner) = previous_result.owner.as_ref() else { return; };
    if !previous_result.path.eq_ignore_ascii_case(&result.path) { return; }
    let version_mismatch = result.evidence.iter().any(|item| item.kind == "nested_product_version_mismatch");
    let previously_active_version = previous_result.evidence.iter()
        .any(|item| item.kind == "nested_product_version_match");
    if version_mismatch && previously_active_version
        && previous.applications.iter().any(|app| same_application(app, previous_owner)) {
        let path = Path::new(&result.path);
        let newer = current.applications.iter().find(|app| {
            same_product_family(app, previous_owner)
                && nested_product_version(path, app).is_some_and(|old_version| {
                    has_strictly_newer_comparable_version(previous_owner, app, &old_version)
                })
        });
        if let Some(newer) = newer {
            result.owner = Some(previous_owner.clone());
            result.owner_hint = None;
            result.ownership = "historical_version".into();
            result.orphan_status = "possibly_orphaned".into();
            result.evidence.push(Evidence {
                kind: "historical_version_owner".into(),
                description: format!("A previous completed scan linked this exact versioned directory to {} while that version was installed.", previous_owner.name),
                strength: "medium".into(),
            });
            result.evidence.push(Evidence {
                kind: "newer_product_version_installed".into(),
                description: format!("A strictly newer registered version of the same product family is installed ({}). Settings or project data may still be valuable, so this remains only a possible leftover.", newer.name),
                strength: "weak".into(),
            });
            return;
        }
    }
    if current.applications.iter().any(|app| same_application(app, previous_owner)) { return; }
    let previously_observed = match previous_result.orphan_status.as_str() {
        "not_orphaned" => previous.applications.iter().any(|app| same_application(app, previous_owner)),
        "probable_orphan" | "possibly_orphaned" => true,
        _ => false,
    };
    if !previously_observed { return; }
    // The registered installation folder disappearing together with the registration
    // upgrades a name-based relationship: the uninstall is observed, not inferred.
    let install_removed = previous_owner.install_location.as_deref()
        .filter(|location| location.len() > 3 && Path::new(location).is_absolute())
        .is_some_and(|location| !Path::new(location).exists() && !location.eq_ignore_ascii_case(&result.path));
    let strong_history = previous_result.ownership == "confirmed"
        || previous_result.ownership == "historical_confirmed"
        || install_removed;
    result.owner = Some(previous_owner.clone());
    result.ownership = if strong_history { "historical_confirmed" } else { "historical_likely" }.into();
    result.orphan_status = if strong_history { "probable_orphan" } else { "possibly_orphaned" }.into();
    result.evidence.push(Evidence {
        kind: "historical_owner".into(),
        description: format!("A previous completed scan linked this exact directory to {}.", previous_owner.name),
        strength: if strong_history { "strong" } else { "medium" }.into(),
    });
    if install_removed {
        let location = previous_owner.install_location.as_deref().unwrap_or_default();
        result.evidence.push(Evidence {
            kind: "install_location_removed".into(),
            description: format!("{}'s registered installation folder ({location}) no longer exists.", previous_owner.name),
            strength: "strong".into(),
        });
    }
    result.evidence.push(Evidence {
        kind: "missing_installed_app".into(),
        description: format!("{} is absent from the current uninstall and current-user package inventory. Portable or unregistered installations may still exist.", previous_owner.name),
        strength: "weak".into(),
    });
}

/// Applies a known location's content category to otherwise unclassified items.
fn apply_location_content(result: &mut DirectoryResult) {
    let Some(name) = Path::new(&result.path).file_name().map(|name| name.to_string_lossy().into_owned()) else { return; };
    let Some(known) = known_locations::lookup(&result.root, &name) else { return; };
    if result.location_class.is_none() {
        result.location_class = Some(known.class.as_str().into());
    }
    let Some(kind) = known.content_kind else { return; };
    for item in &mut result.content.items {
        if item.kind == "unknown" || (item.source == "extension" && content::safety_for_kind(&item.kind) == content::UNKNOWN) {
            item.kind = kind.into();
            item.safety = content::safety_for_kind(kind).into();
            item.source = "location".into();
            item.reason = format!("Inside {}, a recognized {} location.", known.label, content::kind_label(kind).to_lowercase());
        }
    }
}

/// Reads version metadata from up to three shallow executables and uses it to
/// link unmatched installation folders or mark them as unregistered/portable.
fn apply_executable_metadata(result: &mut DirectoryResult, shallow: &[(PathBuf, u64)], apps: &[Application]) {
    if shallow.is_empty() || !matches!(result.orphan_status.as_str(), "unknown" | "associated_with_installed") {
        return;
    }
    if matches!(result.location_class.as_deref(), Some("system" | "shared_runtime")) { return; }
    let infos: Vec<ExecutableInfo> = shallow.iter().filter_map(|(path, _)| executables::read_executable_info(path)).collect();
    if infos.is_empty() { return; }
    let describe = |info: &ExecutableInfo| {
        let mut parts = vec![info.file_name.clone()];
        if let Some(product) = &info.product_name { parts.push(format!("product “{product}”")); }
        if let Some(company) = &info.company_name { parts.push(format!("company “{company}”")); }
        if let Some(version) = &info.product_version { parts.push(format!("version {version}")); }
        parts.join(", ")
    };
    result.executables = infos.clone();
    if result.orphan_status == "unknown" {
        // An executable whose ProductName exactly names one installed product links the folder.
        let mut matches: Vec<&Application> = Vec::new();
        for info in &infos {
            let Some(product) = info.product_name.as_deref().map(normalize_name).filter(|name| name.len() >= 4) else { continue; };
            for app in apps {
                if normalize_name(&product_name_without_version(&app.name)) == product || normalize_name(&app.name) == product {
                    if !matches.iter().any(|existing| existing.id == app.id) { matches.push(app); }
                }
            }
        }
        if matches.len() == 1 {
            let app = matches[0];
            let info = infos.iter().find(|info| info.product_name.is_some()).unwrap_or(&infos[0]);
            result.evidence.push(Evidence {
                kind: "executable_metadata".into(),
                description: format!("Version metadata of {} names installed product {}. The file was read, never run.", describe(info), app.name),
                strength: "medium".into(),
            });
            result.owner = Some(app.clone());
            result.owner_hint = None;
            result.ownership = "likely".into();
            result.orphan_status = "not_orphaned".into();
            return;
        }
        let info = &infos[0];
        result.owner_hint = info.product_name.clone().or_else(|| info.file_description.clone()).or_else(|| Some(info.file_name.clone()));
        result.ownership = "unregistered".into();
        result.orphan_status = "unregistered_application".into();
        result.evidence.push(Evidence {
            kind: "executable_metadata".into(),
            description: format!("Contains application executables ({}) that match no uninstall registration or package. This may be a portable or manually copied application rather than leftovers.", infos.iter().map(describe).collect::<Vec<_>>().join("; ")),
            strength: "weak".into(),
        });
    } else {
        result.evidence.push(Evidence {
            kind: "executable_metadata".into(),
            description: format!("Executable metadata inside this shared folder: {}.", infos.iter().map(describe).collect::<Vec<_>>().join("; ")),
            strength: "weak".into(),
        });
    }
}

/// Relates system references to a directory. Live references mark the folder as
/// in use; dead references are weak evidence that software was removed.
pub fn apply_references(result: &mut DirectoryResult, references: &[SystemReference]) {
    let mut live = Vec::new();
    let mut dead = Vec::new();
    for reference in references {
        let Some(target) = reference.target_path.as_deref() else { continue; };
        if !references::path_is_within(target, &result.path) { continue; }
        match reference.status.as_str() {
            "ok" => live.push(reference),
            "dead" => dead.push(reference),
            _ => {}
        }
    }
    let describe = |items: &[&SystemReference]| items.iter().take(3)
        .map(|reference| format!("{} “{}”", references::kind_label(&reference.kind).to_lowercase(), reference.name))
        .collect::<Vec<_>>().join(", ");
    if !live.is_empty() {
        result.evidence.push(Evidence {
            kind: "active_reference".into(),
            description: format!("{} existing system reference(s) use files in this folder: {}.", live.len(), describe(&live)),
            strength: "medium".into(),
        });
        if result.orphan_status == "unknown" {
            result.owner_hint = Some(references::display_owner(live[0]));
            result.ownership = "referenced".into();
            result.orphan_status = "referenced_by_system".into();
        }
    }
    if !dead.is_empty() {
        result.evidence.push(Evidence {
            kind: "dead_reference".into(),
            description: format!("{} system reference(s) point to missing files in this folder: {}. The software that created them appears to have been removed.", dead.len(), describe(&dead)),
            strength: "weak".into(),
        });
        if result.orphan_status == "unknown" && live.is_empty() {
            result.owner_hint = Some(references::display_owner(dead[0]));
            result.ownership = "reference_inferred".into();
            result.orphan_status = "possibly_orphaned".into();
        }
    }
}

/// A directory selected for measurement.
#[derive(Clone, Debug)]
pub struct ScanTarget {
    pub path: PathBuf,
    pub root: String,
    pub parent_path: Option<PathBuf>,
    /// False for nested targets whose bytes are already counted by their parent.
    pub count_bytes: bool,
    /// Measure files directly in this folder; other roots cover its subfolders.
    pub loose_only: bool,
}

fn measure_target(target: &ScanTarget, apps: &[Application], cancel: &AtomicBool) -> Option<DirectoryResult> {
    let stats = inspect_directory_inner(&target.path, cancel, target.loose_only);
    if cancel.load(Ordering::Relaxed) { return None; }
    let mut result = classify_directory(&target.path, &target.root, apps);
    result.parent_path = target.parent_path.as_ref().map(|parent| parent.to_string_lossy().into_owned());
    result.size_bytes = stats.size;
    result.file_count = stats.files;
    result.directory_count = stats.directories;
    result.newest_modified_unix = stats.newest;
    result.oldest_modified_unix = stats.oldest;
    result.created_unix = stats.created;
    result.skipped_entries = stats.skipped;
    result.content = stats.content;
    apply_location_content(&mut result);
    apply_executable_metadata(&mut result, &stats.shallow_executables, apps);
    Some(result)
}

fn nested_product_targets(parent: &Path, root: &str, apps: &[Application]) -> Vec<PathBuf> {
    let parent_result = classify_directory(parent, root, apps);
    if parent_result.orphan_status != "associated_with_installed" {
        return Vec::new();
    }
    let Ok(entries) = fs::read_dir(parent) else { return Vec::new(); };
    let mut children = Vec::new();
    for entry in entries.take(257) {
        let Ok(entry) = entry else { return Vec::new(); };
        let child = entry.path();
        let Ok(metadata) = fs::symlink_metadata(&child) else { return Vec::new(); };
        if metadata.is_dir() && !is_reparse_point(&metadata) {
            children.push(child);
        }
    }
    if children.len() > 256 {
        return Vec::new();
    }
    children.retain(|child| {
        let result = classify_directory(child, root, apps);
        result.evidence.iter().any(|item| matches!(item.kind.as_str(),
            "nested_product_version_match" | "nested_product_version_mismatch"
                | "nested_package_namespace_match" | "nested_vendor_product_match"))
    });
    children
}

fn is_excluded(path: &Path, excluded_paths: &[PathBuf]) -> bool {
    excluded_paths.iter().any(|excluded| path.to_string_lossy().eq_ignore_ascii_case(&excluded.to_string_lossy()))
}

fn child_directories(path: &Path, summary: &mut ScanSummary) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(path) else { summary.skipped_entries += 1; return Vec::new(); };
    let mut directories = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else { summary.skipped_entries += 1; continue; };
        let Ok(metadata) = fs::symlink_metadata(entry.path()) else { summary.skipped_entries += 1; continue; };
        if metadata.is_dir() && !is_reparse_point(&metadata) {
            directories.push(entry.path());
        }
    }
    directories.sort();
    directories
}

/// Enumerates the directories a scan in `mode` measures.
pub fn collect_targets(apps: &[Application], mode: ScanMode, excluded_paths: &[PathBuf], summary: &mut ScanSummary, cancel: &AtomicBool) -> Vec<ScanTarget> {
    let (roots, warnings, expected_roots) = scan_roots_with_apps(mode, apps);
    summary.warnings.extend(warnings);
    collect_targets_in_roots(&roots, expected_roots, apps, excluded_paths, summary, cancel)
}

fn profile_targets(path: &Path, explicit_paths: &[&Path], excluded_paths: &[PathBuf], summary: &mut ScanSummary, targets: &mut Vec<ScanTarget>) {
    if is_excluded(path, excluded_paths) { return; }
    let name = path.file_name().map(|name| name.to_string_lossy()).unwrap_or_default();
    if name.eq_ignore_ascii_case("AppData") { return; }
    let overlaps = |left: &Path, right: &Path| references::path_is_within(&left.to_string_lossy(), &right.to_string_lossy());
    if explicit_paths.iter().any(|known| overlaps(path, known)) { return; }
    if explicit_paths.iter().any(|known| overlaps(known, path)) {
        targets.push(ScanTarget { path: path.to_path_buf(), root: "UserProfile".into(), parent_path: None, count_bytes: true, loose_only: true });
        for child in child_directories(path, summary) {
            profile_targets(&child, explicit_paths, excluded_paths, summary, targets);
        }
    } else {
        targets.push(ScanTarget { path: path.to_path_buf(), root: "UserProfile".into(), parent_path: None, count_bytes: true, loose_only: false });
    }
}

fn collect_targets_in_roots(roots: &[ScanRoot], expected_roots: usize, apps: &[Application], excluded_paths: &[PathBuf], summary: &mut ScanSummary, cancel: &AtomicBool) -> Vec<ScanTarget> {
    let mut targets = Vec::new();
    let mut enumerated = 0usize;
    let explicit_paths: Vec<&Path> = roots.iter().filter(|root| root.label != "UserProfile")
        .map(|root| root.path.as_path()).collect();
    for root in roots {
        if cancel.load(Ordering::Relaxed) { break; }
        let label = root.label.clone();
        if fs::read_dir(&root.path).is_err() {
            summary.skipped_entries += 1;
            summary.warnings.push(format!("{label} could not be enumerated: {}", root.path.display()));
            continue;
        }
        enumerated += 1;
        summary.scanned_roots.push(format!("{label}: {}", root.path.display()));
        if label == "RegisteredInstall" {
            if !is_excluded(&root.path, excluded_paths) {
                targets.push(ScanTarget { path: root.path.clone(), root: label, parent_path: None, count_bytes: true, loose_only: false });
            }
            continue;
        }
        if label == "UserProfile" {
            targets.push(ScanTarget { path: root.path.clone(), root: label.clone(), parent_path: None, count_bytes: true, loose_only: true });
        }
        if is_personal_scan_target(&label, &root.path) && label != "UserProfile" {
            // The root covers loose files and the entire tree. Child rows make forgotten
            // folders individually visible without counting their bytes twice.
            targets.push(ScanTarget { path: root.path.clone(), root: label.clone(), parent_path: None, count_bytes: true, loose_only: false });
            for child in child_directories(&root.path, summary) {
                if !is_excluded(&child, excluded_paths) {
                    targets.push(ScanTarget { path: child, root: label.clone(), parent_path: Some(root.path.clone()), count_bytes: false, loose_only: false });
                }
            }
            continue;
        }
        for path in child_directories(&root.path, summary) {
            if is_excluded(&path, excluded_paths) { continue; }
            let name = path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
            if label == "UserProfile" {
                // Split a container such as OneDrive when a redirected known folder
                // lives inside it, so its other children remain covered.
                profile_targets(&path, &explicit_paths, excluded_paths, summary, &mut targets);
                continue;
            }
            let structural_container = label == "Local" && ["Packages", "Programs"].iter().any(|container| name.eq_ignore_ascii_case(container));
            if structural_container {
                for child in child_directories(&path, summary) {
                    if is_excluded(&child, excluded_paths) { continue; }
                    targets.push(ScanTarget { path: child, root: label.clone(), parent_path: None, count_bytes: true, loose_only: false });
                }
            } else {
                let nested = nested_product_targets(&path, &label, apps);
                targets.push(ScanTarget { path: path.clone(), root: label.clone(), parent_path: None, count_bytes: true, loose_only: false });
                for child in nested {
                    targets.push(ScanTarget { path: child, root: label.clone(), parent_path: Some(path.clone()), count_bytes: false, loose_only: false });
                }
            }
        }
    }
    summary.complete = enumerated == expected_roots;
    targets
}

enum WorkerMessage {
    Progress(String),
    Result(Box<DirectoryResult>, bool, u64, u64),
}

/// Measures targets on a small worker pool and streams results in completion
/// order. Worker count is capped to limit disk thrashing (spec §30).
pub fn scan_targets<F, P>(targets: Vec<ScanTarget>, apps: &[Application], cancel: &AtomicBool, summary: &mut ScanSummary, mut on_result: F, mut on_progress: P)
where
    F: FnMut(DirectoryResult),
    P: FnMut(String),
{
    let workers = std::thread::available_parallelism().map(|count| count.get()).unwrap_or(2).clamp(1, 4).min(targets.len().max(1));
    // Largest-looking targets first tends to finish sooner overall; sort by name for stability.
    let next = std::sync::atomic::AtomicUsize::new(0);
    let (sender, receiver) = std::sync::mpsc::channel::<WorkerMessage>();
    std::thread::scope(|scope| {
        for _ in 0..workers {
            let sender = sender.clone();
            let targets = &targets;
            let next = &next;
            scope.spawn(move || {
                loop {
                    if cancel.load(Ordering::Relaxed) { break; }
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(target) = targets.get(index) else { break; };
                    let _ = sender.send(WorkerMessage::Progress(target.path.to_string_lossy().into_owned()));
                    if let Some(result) = measure_target(target, apps, cancel) {
                        let size = result.size_bytes;
                        let skipped = result.skipped_entries;
                        if sender.send(WorkerMessage::Result(Box::new(result), target.count_bytes, size, skipped)).is_err() { break; }
                    }
                }
            });
        }
        drop(sender);
        for message in receiver {
            match message {
                WorkerMessage::Progress(path) => on_progress(path),
                WorkerMessage::Result(result, count_bytes, size, skipped) => {
                    summary.directories += 1;
                    if count_bytes {
                        summary.bytes = summary.bytes.saturating_add(size);
                        summary.skipped_entries += skipped;
                    }
                    on_result(*result);
                }
            }
        }
    });
}

fn now_unix() -> u64 {
    std::time::SystemTime::now().duration_since(UNIX_EPOCH).map(|duration| duration.as_secs()).unwrap_or_default()
}

/// Runs a full scan in the given mode.
pub fn scan_with_mode<F, P>(apps: &[Application], mode: ScanMode, excluded_paths: &[PathBuf], cancel: &AtomicBool, on_result: F, on_progress: P) -> ScanSummary
where
    F: FnMut(DirectoryResult),
    P: FnMut(String),
{
    let started = std::time::Instant::now();
    let mut summary = ScanSummary { mode: mode.as_str().into(), started_at_unix: now_unix(), ..Default::default() };
    let targets = collect_targets(apps, mode, excluded_paths, &mut summary, cancel);
    scan_targets(targets, apps, cancel, &mut summary, on_result, on_progress);
    summary.canceled = cancel.load(Ordering::Relaxed);
    summary.complete = summary.complete && !summary.canceled;
    summary.duration_ms = started.elapsed().as_millis() as u64;
    summary
}

/// Quick scan compatible with earlier callers.
pub fn scan<F, P>(apps: &[Application], excluded_paths: &[PathBuf], cancel: &AtomicBool, on_result: F, on_progress: P) -> ScanSummary
where
    F: FnMut(DirectoryResult),
    P: FnMut(String),
{
    scan_with_mode(apps, ScanMode::Quick, excluded_paths, cancel, on_result, on_progress)
}

/// Finalizes a result after history, public data, definitions and references
/// have been applied: computes the separate assessment.
pub fn finalize(result: &mut DirectoryResult) {
    result.assessment = assess(result, now_unix());
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
        assert_eq!(product_name_without_version("Spitfire Audio version 3.4.18"), "Spitfire Audio");
    }

    #[test]
    fn nested_versions_match_by_components_not_digit_prefixes() {
        let mut app = example_app("android-studio");
        app.name = "Android Studio".into();
        app.publisher = Some("Google LLC".into());
        app.version = Some("2026.1".into());
        assert!(nested_versioned_product_match(
            Path::new(r"C:\Users\Test\AppData\Local\Google\AndroidStudio2026.1.3"),
            &app,
        ));
        assert!(!nested_versioned_product_match(
            Path::new(r"C:\Users\Test\AppData\Local\Google\AndroidStudio2026.10"),
            &app,
        ));
        assert!(version_is_strictly_newer(&[2026, 2], &[2026, 1, 9]));
        assert!(!version_is_strictly_newer(&[2026, 1], &[2026, 1, 3]));
    }

    #[test]
    fn retained_active_version_becomes_possible_only_after_a_strictly_newer_version() {
        let path = Path::new(r"C:\Users\Test\AppData\Local\JetBrains\Rider2024.1");
        let previous_owner = nested_app("stable-rider-key", "Rider 2024.1", "JetBrains s.r.o.", "2024.1");
        let newer = nested_app("stable-rider-key", "Rider 2026.2", "JetBrains s.r.o.", "2026.2");
        let previous_result = classify_directory(path, "Local", std::slice::from_ref(&previous_owner));
        assert_eq!(previous_result.orphan_status, "not_orphaned");
        let mut current_result = classify_directory(path, "Local", std::slice::from_ref(&newer));
        assert_eq!(current_result.orphan_status, "unknown");

        apply_history(
            &mut current_result,
            &Inventory { applications: vec![newer], warnings: vec![] },
            &Inventory { applications: vec![previous_owner.clone()], warnings: vec![] },
            Some(&previous_result),
        );

        assert_eq!(current_result.orphan_status, "possibly_orphaned");
        assert_eq!(current_result.ownership, "historical_version");
        assert_eq!(current_result.owner.as_ref().map(|app| app.name.as_str()), Some("Rider 2024.1"));
        assert!(current_result.evidence.iter().any(|item| item.kind == "historical_version_owner"));
        assert!(current_result.evidence.iter().any(|item| item.kind == "newer_product_version_installed"));
    }

    #[test]
    fn downgrade_or_first_seen_version_mismatch_stays_unknown() {
        let path = Path::new(r"C:\Users\Test\AppData\Local\JetBrains\Rider2024.1");
        let previous_owner = nested_app("stable-rider-key", "Rider 2024.1", "JetBrains s.r.o.", "2024.1");
        let older = nested_app("stable-rider-key", "Rider 2023.3", "JetBrains s.r.o.", "2023.3");
        let previous_result = classify_directory(path, "Local", std::slice::from_ref(&previous_owner));
        let mut current_result = classify_directory(path, "Local", std::slice::from_ref(&older));
        assert_eq!(current_result.orphan_status, "unknown");
        assert!(current_result.evidence.iter().any(|item| item.kind == "nested_product_version_mismatch"));

        apply_history(
            &mut current_result,
            &Inventory { applications: vec![older], warnings: vec![] },
            &Inventory { applications: vec![previous_owner], warnings: vec![] },
            Some(&previous_result),
        );

        assert_eq!(current_result.orphan_status, "unknown");
        assert!(current_result.owner.is_none());

        let previous_build_owner = nested_app("stable-rider-key", "Rider 2024.1", "JetBrains s.r.o.", "241.100");
        let unrelated_build_scheme = nested_app("stable-rider-key", "Rider", "JetBrains s.r.o.", "9999.1");
        let previous_result = classify_directory(path, "Local", std::slice::from_ref(&previous_build_owner));
        let mut current_result = classify_directory(path, "Local", std::slice::from_ref(&unrelated_build_scheme));
        apply_history(
            &mut current_result,
            &Inventory { applications: vec![unrelated_build_scheme], warnings: vec![] },
            &Inventory { applications: vec![previous_build_owner], warnings: vec![] },
            Some(&previous_result),
        );
        assert_eq!(current_result.orphan_status, "unknown", "different version schemes must not be compared");
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
            ("Local", "AMDSoftwareInstaller"), ("ProgramData", "SoftwareDistribution"),
            ("ProgramData", "USOPrivate"), ("ProgramData", "USOShared"),
            ("ProgramData", "Whesvc"), ("ProgramData", "ssh"),
            ("ProgramData", "regid.1991-06.com.microsoft"),
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

    fn temp_tree(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("orphan-cleaner-{name}-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn conventional_drive_discovery_is_bounded_and_install_roots_do_not_overlap() {
        let tree = temp_tree("discovery");
        let drive = tree.join("Drive");
        for path in [drive.join("Downloads"), drive.join("Mods").join("Downloads"), drive.join("temp"), drive.join("Program Files"),
            drive.join("Windows").join("Downloads"), drive.join("Games").join("Example"),
            drive.join("Downloads").join("Portable")]
        {
            fs::create_dir_all(path).unwrap();
        }
        let mut roots = discover_conventional_roots(&[drive.clone()]);
        assert!(roots.iter().any(|root| root.path == drive.join("Downloads") && root.label == "OtherDownloads"));
        assert!(roots.iter().any(|root| root.path == drive.join("Mods").join("Downloads")));
        assert!(roots.iter().any(|root| root.path == drive.join("temp") && root.label == "OtherTemp"));
        assert!(roots.iter().any(|root| root.path == drive.join("Program Files") && root.label == "ProgramFiles"));
        assert!(!roots.iter().any(|root| root.path == drive.join("Windows").join("Downloads")));
        let apps = [
            Application { install_location: Some(drive.join("Games").join("Example").to_string_lossy().into_owned()), ..Default::default() },
            Application { install_location: Some(drive.join("Downloads").join("Portable").to_string_lossy().into_owned()), ..Default::default() },
            Application { install_location: Some(drive.join("Games").to_string_lossy().into_owned()), ..Default::default() },
        ];
        assert_eq!(add_registered_install_roots(&mut roots, &[drive.clone()], &apps), 1);
        assert!(roots.iter().any(|root| root.path == drive.join("Games").join("Example") && root.label == "RegisteredInstall"));
        let downloads = classify_directory(&drive.join("Mods").join("Downloads"), "OtherDownloads", &[]);
        assert_eq!(downloads.orphan_status, "user_files");
        assert_eq!(downloads.location_class.as_deref(), Some("user_data"));
        fs::remove_dir_all(tree).unwrap();
    }

    #[test]
    fn deep_personal_roots_cover_downloads_and_profile_without_appdata_overlap() {
        let tree = temp_tree("personal-roots");
        let profile = tree.join("Profile");
        let downloads = profile.join("Downloads");
        let documents = profile.join("OneDrive").join("Documents");
        let app_data = profile.join("AppData").join("Local");
        for path in [&downloads, &downloads.join("Old installer"), &documents, &documents.join("Notes"),
            &profile.join("Projects"), &profile.join(".cargo"), &profile.join("OneDrive").join("Other"), &app_data.join("App")]
        {
            fs::create_dir_all(path).unwrap();
        }
        fs::write(profile.join("at-home.txt"), b"home").unwrap();
        fs::write(profile.join("OneDrive").join("at-root.txt"), b"cloud").unwrap();
        fs::write(downloads.join("forgotten.zip"), b"loose").unwrap();
        fs::write(downloads.join("Old installer").join("setup.exe"), b"nested").unwrap();
        let roots = vec![
            ScanRoot { label: "Local".into(), path: app_data.clone() },
            ScanRoot { label: "Documents".into(), path: documents.clone() },
            ScanRoot { label: "Downloads".into(), path: downloads.clone() },
            ScanRoot { label: "UserProfile".into(), path: profile.clone() },
        ];
        let mut summary = ScanSummary::default();
        let targets = collect_targets_in_roots(&roots, roots.len(), &[], &[], &mut summary, &AtomicBool::new(false));
        assert!(summary.complete);
        assert!(targets.iter().any(|target| target.path == downloads && target.count_bytes));
        assert!(targets.iter().any(|target| target.path == downloads.join("Old installer") && !target.count_bytes));
        assert!(targets.iter().any(|target| target.path == documents.join("Notes")));
        assert!(targets.iter().any(|target| target.path == profile.join("Projects")));
        assert!(targets.iter().any(|target| target.path == profile.join("OneDrive").join("Other")));
        assert!(targets.iter().any(|target| target.path == profile && target.loose_only));
        assert!(targets.iter().any(|target| target.path == profile.join("OneDrive") && target.loose_only));
        assert!(targets.iter().any(|target| target.path == profile.join(".cargo")));
        assert!(!targets.iter().any(|target| target.path == profile.join("AppData")));
        assert_eq!(inspect_directory_inner(&profile, &AtomicBool::new(false), true).size, 4);
        assert_eq!(inspect_directory_inner(&profile.join("OneDrive"), &AtomicBool::new(false), true).size, 5);
        let stats = inspect_directory(&downloads, &AtomicBool::new(false));
        assert_eq!(stats.size, 11);
        assert_eq!(stats.files, 2);
        let result = classify_directory(&downloads, "Downloads", &[]);
        assert_eq!(result.location_class.as_deref(), Some("user_data"));
        assert_eq!(result.orphan_status, "user_files");
        fs::remove_dir_all(tree).unwrap();
    }

    #[test]
    fn inspection_profiles_children_without_reading_contents() {
        let root = temp_tree("inspect").join("OldApp");
        fs::create_dir_all(root.join("Cache").join("deep")).unwrap();
        fs::create_dir_all(root.join("Profiles").join("SaveGames")).unwrap();
        fs::write(root.join("Cache").join("deep").join("a.bin"), vec![0u8; 2048]).unwrap();
        fs::write(root.join("Profiles").join("SaveGames").join("slot1.sav"), b"x").unwrap();
        fs::write(root.join("app.log"), b"log").unwrap();
        let stats = inspect_directory(&root, &AtomicBool::new(false));
        assert_eq!(stats.files, 3);
        assert_eq!(stats.size, 2048 + 1 + 3);
        let cache = stats.content.items.iter().find(|item| item.name == "Cache").unwrap();
        assert_eq!(cache.safety, "safe");
        assert_eq!(cache.size_bytes, 2048);
        let profiles = stats.content.items.iter().find(|item| item.name == "Profiles").unwrap();
        assert_eq!(profiles.safety, "preserve");
        assert!(stats.content.items.iter().any(|item| !item.is_directory && item.kind == "log"));
        fs::remove_dir_all(root.parent().unwrap()).unwrap();
    }

    #[test]
    fn parallel_target_scan_reports_every_target_once() {
        let base = temp_tree("parallel");
        let targets = (0..9).map(|index| {
            let path = base.join(format!("App{index}"));
            fs::create_dir_all(&path).unwrap();
            fs::write(path.join("f.txt"), vec![1u8; index + 1]).unwrap();
            ScanTarget { path, root: "Roaming".into(), parent_path: None, count_bytes: true, loose_only: false }
        }).collect::<Vec<_>>();
        let mut summary = ScanSummary::default();
        let mut seen = Vec::new();
        scan_targets(targets, &[], &AtomicBool::new(false), &mut summary, |result| seen.push(result.path), |_| {});
        assert_eq!(seen.len(), 9);
        assert_eq!(summary.bytes, (1..=9).sum::<u64>());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn references_mark_folders_live_or_dead() {
        let live = SystemReference { kind: "service".into(), name: "Vendor Service".into(), status: "ok".into(),
            target_path: Some(r"C:\ProgramData\Vendor\svc.exe".into()), ..Default::default() };
        let mut result = example_result(None, "unknown", "unknown");
        result.path = r"C:\ProgramData\Vendor".into();
        apply_references(&mut result, std::slice::from_ref(&live));
        assert_eq!(result.orphan_status, "referenced_by_system");
        let dead = SystemReference { status: "dead".into(), kind: "startup_run".into(), name: "OldApp".into(),
            target_path: Some(r"C:\Users\T\AppData\Local\OldApp\old.exe".into()), ..Default::default() };
        let mut result = example_result(None, "unknown", "unknown");
        result.path = r"C:\Users\T\AppData\Local\OldApp".into();
        apply_references(&mut result, &[dead]);
        assert_eq!(result.orphan_status, "possibly_orphaned");
        assert_eq!(result.owner_hint.as_deref(), Some("OldApp"));
    }

    fn example_app(id: &str) -> Application {
        Application { id: id.into(), name: "Example".into(), publisher: None, version: None,
            install_location: None, display_icon_executable: None, package_family_name: None, sources: vec!["registry".into()] }
    }

    fn nested_app(id: &str, name: &str, publisher: &str, version: &str) -> Application {
        Application { id: id.into(), name: name.into(), publisher: Some(publisher.into()),
            version: Some(version.into()), install_location: None, display_icon_executable: None,
            package_family_name: None, sources: vec!["registry".into()] }
    }

    fn example_result(owner: Option<Application>, ownership: &str, status: &str) -> DirectoryResult {
        DirectoryResult { path: r"C:\Users\Test\AppData\Roaming\Example".into(), root: "Roaming".into(), parent_path: None,
            size_bytes: 100, file_count: 1, directory_count: 0, newest_modified_unix: None,
            skipped_entries: 0, owner, owner_hint: None, ownership: ownership.into(), orphan_status: status.into(), evidence: vec![], ..Default::default() }
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
