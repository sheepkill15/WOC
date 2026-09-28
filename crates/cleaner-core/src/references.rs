//! System references: startup entries, scheduled tasks, services, shortcuts,
//! URL protocol handlers, file-type handlers and App Paths.
//!
//! References are collected read-only. Each one records the executable it
//! points to and whether that target still exists. Live references are
//! evidence that a directory is still in use; dead references are evidence
//! that software existed previously and may have left data behind.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY};

use crate::{Application, normalize_name};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SystemReference {
    pub id: String,
    /// startup_run | startup_folder | start_menu_shortcut | service | scheduled_task
    /// | url_protocol | file_handler | app_path
    pub kind: String,
    pub name: String,
    /// Registry key, file path or task path where the reference is defined.
    pub location: String,
    pub command: String,
    #[serde(default)]
    pub target_path: Option<String>,
    /// ok | dead | unresolved
    pub status: String,
    #[serde(default)]
    pub owner: Option<Application>,
    /// True when the reference is defined by a file that can be quarantined (.lnk shortcuts).
    #[serde(default)]
    pub file_backed: bool,
    #[serde(default)]
    pub machine_wide: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReferenceInventory {
    pub references: Vec<SystemReference>,
    pub warnings: Vec<String>,
}

pub fn kind_label(kind: &str) -> &'static str {
    match kind {
        "startup_run" => "Startup registry entry",
        "startup_folder" => "Startup folder shortcut",
        "start_menu_shortcut" => "Start Menu shortcut",
        "service" => "Windows service",
        "scheduled_task" => "Scheduled task",
        "url_protocol" => "URL protocol handler",
        "file_handler" => "File type handler",
        "app_path" => "App Paths registration",
        _ => "System reference",
    }
}

fn expand_environment(value: &str) -> String {
    let mut output = String::new();
    let mut rest = value;
    while let Some(start) = rest.find('%') {
        output.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let Some(end) = after.find('%') else { output.push_str(&rest[start..]); return output; };
        let name = &after[..end];
        match std::env::var(name) {
            Ok(expanded) if !name.is_empty() => output.push_str(&expanded),
            _ => { output.push('%'); output.push_str(name); output.push('%'); }
        }
        rest = &after[end + 1..];
    }
    output.push_str(rest);
    output
}

fn system_root() -> String {
    std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into())
}

const EXECUTABLE_EXTENSIONS: [&str; 6] = [".exe", ".com", ".bat", ".cmd", ".scr", ".dll"];

/// Extracts the executable path from a command line without executing it.
/// Handles quoted paths, unquoted paths containing spaces, rundll32 hosts,
/// environment variables and NT-style service image paths.
pub fn command_target(command: &str) -> Option<String> {
    let expanded = expand_environment(command.trim());
    let mut text = expanded.trim().to_owned();
    if text.is_empty() { return None; }
    let root = system_root();
    if let Some(rest) = text.strip_prefix(r"\??\") { text = rest.to_owned(); }
    let lower = text.to_ascii_lowercase();
    if lower.starts_with(r"\systemroot\") {
        text = format!("{root}{}", &text[11..]);
    } else if lower.starts_with(r"system32\") || lower.starts_with(r"syswow64\") {
        text = format!(r"{root}\{text}");
    }
    let target = if let Some(rest) = text.strip_prefix('"') {
        rest.split_once('"').map(|(path, _)| path.to_owned())?
    } else {
        let lower = text.to_ascii_lowercase();
        let mut best = None;
        for extension in EXECUTABLE_EXTENSIONS {
            let mut search = 0;
            while let Some(found) = lower[search..].find(extension) {
                let end = search + found + extension.len();
                let boundary = lower[end..].chars().next().is_none_or(|ch| ch == ' ' || ch == ',' || ch == '"');
                if boundary {
                    best = Some(best.map_or(end, |current: usize| current.min(end)));
                    break;
                }
                search = end;
            }
        }
        match best {
            Some(end) => text[..end].to_owned(),
            None => text.split_whitespace().next()?.to_owned(),
        }
    };
    // rundll32 host: the interesting target is the DLL argument.
    let file = Path::new(&target).file_name().map(|name| name.to_string_lossy().to_ascii_lowercase());
    if file.as_deref() == Some("rundll32.exe") {
        let remainder = text.to_ascii_lowercase().find("rundll32.exe").map(|index| text[index + 12..].trim_start_matches('"').trim().to_owned())?;
        let dll = remainder.trim_start_matches('"');
        let dll = dll.split(['"', ',']).next()?.trim();
        if !dll.is_empty() { return Some(dll.to_owned()); }
    }
    let target = target.trim().trim_matches('"').to_owned();
    if target.is_empty() { return None; }
    if !Path::new(&target).is_absolute() {
        // Bare names such as "explorer.exe" resolve through the Windows directory.
        let lower = target.to_ascii_lowercase();
        if !lower.contains('\\') && EXECUTABLE_EXTENSIONS.iter().any(|extension| lower.ends_with(extension)) {
            for candidate in [format!(r"{root}\System32\{target}"), format!(r"{root}\{target}")] {
                if Path::new(&candidate).exists() { return Some(candidate); }
            }
        }
        return None;
    }
    Some(target)
}

fn status_for(target: &Option<String>) -> String {
    match target {
        Some(path) if Path::new(path).exists() => "ok",
        Some(_) => "dead",
        None => "unresolved",
    }.into()
}

fn owner_for(target: &Option<String>, apps: &[Application]) -> Option<Application> {
    let target = target.as_deref()?.to_ascii_lowercase();
    let mut best: Option<(&Application, usize)> = None;
    for app in apps {
        if let Some(icon) = app.display_icon_executable.as_deref() {
            if icon.eq_ignore_ascii_case(&target) { return Some(app.clone()); }
        }
        if let Some(location) = app.install_location.as_deref() {
            let location = location.trim_end_matches(['\\', '/']).to_ascii_lowercase();
            if location.len() > 3 && target.starts_with(&format!("{location}\\"))
                && best.is_none_or(|(_, length)| location.len() > length) {
                best = Some((app, location.len()));
            }
        }
    }
    best.map(|(app, _)| app.clone())
}

fn reference(kind: &str, name: String, location: String, command: String, target: Option<String>, apps: &[Application], machine_wide: bool) -> SystemReference {
    let status = status_for(&target);
    let owner = owner_for(&target, apps);
    SystemReference {
        id: format!("{kind}:{}", location.to_ascii_lowercase()),
        kind: kind.into(), name, location, command, target_path: target, status, owner,
        file_backed: matches!(kind, "startup_folder" | "start_menu_shortcut"), machine_wide,
    }
}

fn run_keys(apps: &[Application], out: &mut Vec<SystemReference>, warnings: &mut Vec<String>) {
    for (hive, hive_name) in [(HKEY_CURRENT_USER, "HKCU"), (HKEY_LOCAL_MACHINE, "HKLM")] {
        let views: &[(&str, u32)] = if hive_name == "HKCU" { &[("64", KEY_WOW64_64KEY)] } else { &[("64", KEY_WOW64_64KEY), ("32", KEY_WOW64_32KEY)] };
        for (view, flag) in views {
            for subkey in [r"Software\Microsoft\Windows\CurrentVersion\Run", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"] {
                let key = match RegKey::predef(hive).open_subkey_with_flags(subkey, KEY_READ | flag) {
                    Ok(key) => key,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(_) => { warnings.push(format!("Could not read {hive_name} {view}-bit {subkey}.")); continue; }
                };
                for value in key.enum_values().flatten() {
                    let (name, _) = value;
                    let Ok(command) = key.get_value::<String, _>(&name) else { continue; };
                    let location = format!(r"{hive_name}\{subkey} ({view}-bit) → {name}");
                    let target = command_target(&command);
                    out.push(reference("startup_run", name, location, command, target, apps, hive_name == "HKLM"));
                }
            }
        }
    }
}

fn services(apps: &[Application], out: &mut Vec<SystemReference>, warnings: &mut Vec<String>) {
    let Ok(root) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(r"SYSTEM\CurrentControlSet\Services", KEY_READ) else {
        warnings.push("Could not read the Windows service registry.".into());
        return;
    };
    for name in root.enum_keys().flatten() {
        let Ok(service) = root.open_subkey_with_flags(&name, KEY_READ) else { continue; };
        // Win32 own-process (0x10) and share-process (0x20) services; drivers are out of scope.
        let service_type = service.get_value::<u32, _>("Type").unwrap_or(0);
        if service_type & 0x30 == 0 { continue; }
        let Ok(image) = service.get_value::<String, _>("ImagePath") else { continue; };
        let display = service.get_value::<String, _>("DisplayName").ok()
            .filter(|value| !value.starts_with('@')).unwrap_or_else(|| name.clone());
        let mut target = command_target(&image);
        // Shared svchost services name their real implementation in Parameters\ServiceDll.
        if target.as_deref().is_some_and(|path| path.to_ascii_lowercase().ends_with(r"\svchost.exe")) {
            if let Ok(parameters) = service.open_subkey_with_flags("Parameters", KEY_READ) {
                if let Ok(dll) = parameters.get_value::<String, _>("ServiceDll") {
                    target = command_target(&dll).or(target);
                }
            }
        }
        let location = format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{name}");
        out.push(reference("service", display, location, image, target, apps, true));
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TaskRecord {
    task_name: Option<String>,
    task_path: Option<String>,
    execute: Option<String>,
    arguments: Option<String>,
}

fn scheduled_tasks(apps: &[Application], out: &mut Vec<SystemReference>, warnings: &mut Vec<String>) {
    // Fixed read-only query; nothing found during scanning is executed.
    let script = "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); ConvertTo-Json -Compress -Depth 3 -InputObject @(Get-ScheduledTask | ForEach-Object { $t = $_; @($t.Actions) | Where-Object { $_.Execute } | ForEach-Object { [pscustomobject]@{ TaskName = $t.TaskName; TaskPath = $t.TaskPath; Execute = $_.Execute; Arguments = $_.Arguments } } })";
    let output = match Command::new(crate::powershell_path()).args(["-NoProfile", "-NonInteractive", "-Command", script]).output() {
        Ok(output) if output.status.success() => output,
        _ => { warnings.push("Scheduled tasks could not be listed; task references are missing from this scan.".into()); return; }
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let text = text.trim();
    if text.is_empty() { return; }
    let records: Vec<TaskRecord> = match serde_json::from_str(text) {
        Ok(records) => records,
        Err(_) => { warnings.push("Scheduled task output was unreadable.".into()); return; }
    };
    for record in records {
        let Some(execute) = record.execute.filter(|value| !value.trim().is_empty()) else { continue; };
        let name = record.task_name.unwrap_or_default();
        let path = record.task_path.unwrap_or_default();
        // Built-in Windows tasks are noise for orphan detection.
        if path.to_ascii_lowercase().starts_with(r"\microsoft\windows\") { continue; }
        let quoted = if execute.contains(' ') && !execute.starts_with('"') { format!("\"{execute}\"") } else { execute.clone() };
        let command = match record.arguments.filter(|value| !value.is_empty()) {
            Some(arguments) => format!("{quoted} {arguments}"),
            None => quoted.clone(),
        };
        let target = command_target(&quoted);
        out.push(reference("scheduled_task", name.clone(), format!("{path}{name}"), command, target, apps, true));
    }
}

fn url_protocols_and_handlers(apps: &[Application], out: &mut Vec<SystemReference>) {
    for (hive, hive_name) in [(HKEY_CURRENT_USER, "HKCU"), (HKEY_LOCAL_MACHINE, "HKLM")] {
        let Ok(classes) = RegKey::predef(hive).open_subkey_with_flags(r"Software\Classes", KEY_READ) else { continue; };
        for name in classes.enum_keys().flatten().take(20_000) {
            if name.starts_with('.') || name.starts_with('*') { continue; }
            let Ok(class) = classes.open_subkey_with_flags(&name, KEY_READ) else { continue; };
            let is_protocol = class.get_raw_value("URL Protocol").is_ok();
            // Only per-user ProgIDs are inspected as file handlers; machine-wide ones are dominated by Windows.
            if !is_protocol && hive_name != "HKCU" { continue; }
            let Ok(open) = class.open_subkey_with_flags(r"shell\open\command", KEY_READ) else { continue; };
            let Ok(command) = open.get_value::<String, _>("") else { continue; };
            let target = command_target(&command);
            let kind = if is_protocol { "url_protocol" } else { "file_handler" };
            let label = class.get_value::<String, _>("").ok().filter(|value| !value.trim().is_empty() && !value.starts_with('@'))
                .map(|value| format!("{name} ({value})")).unwrap_or_else(|| name.clone());
            let location = format!(r"{hive_name}\Software\Classes\{name}\shell\open\command");
            out.push(reference(kind, label, location, command, target, apps, hive_name == "HKLM"));
        }
    }
}

fn app_paths(apps: &[Application], out: &mut Vec<SystemReference>) {
    for (hive, hive_name) in [(HKEY_CURRENT_USER, "HKCU"), (HKEY_LOCAL_MACHINE, "HKLM")] {
        let subkey = r"Software\Microsoft\Windows\CurrentVersion\App Paths";
        let Ok(root) = RegKey::predef(hive).open_subkey_with_flags(subkey, KEY_READ) else { continue; };
        for name in root.enum_keys().flatten() {
            let Ok(entry) = root.open_subkey_with_flags(&name, KEY_READ) else { continue; };
            let Ok(command) = entry.get_value::<String, _>("") else { continue; };
            let target = command_target(&command);
            out.push(reference("app_path", name.clone(), format!(r"{hive_name}\{subkey}\{name}"), command, target, apps, hive_name == "HKLM"));
        }
    }
}

// ---------- Shell link (.lnk) parsing ----------

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    data.get(offset..offset + 2).map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    data.get(offset..offset + 4).map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn c_string(data: &[u8], offset: usize) -> Option<String> {
    let bytes = data.get(offset..)?;
    let end = bytes.iter().position(|byte| *byte == 0)?;
    Some(bytes[..end].iter().map(|byte| *byte as char).collect())
}

fn utf16_c_string(data: &[u8], offset: usize) -> Option<String> {
    let mut units = Vec::new();
    let mut position = offset;
    loop {
        let unit = read_u16(data, position)?;
        if unit == 0 { break; }
        units.push(unit);
        position += 2;
        if units.len() > 32_767 { return None; }
    }
    Some(String::from_utf16_lossy(&units))
}

/// Resolves the local target of a Windows shell link from its LinkInfo or,
/// failing that, its relative path. Returns `None` for non-file targets
/// such as shell namespace items or URLs. The link is only read, never invoked.
pub fn parse_shell_link(data: &[u8], link_path: &Path) -> Option<String> {
    if data.len() < 0x4C || read_u32(data, 0)? != 0x4C { return None; }
    let flags = read_u32(data, 0x14)?;
    let has_id_list = flags & 0x1 != 0;
    let has_link_info = flags & 0x2 != 0;
    let has_name = flags & 0x4 != 0;
    let has_relative_path = flags & 0x8 != 0;
    let unicode = flags & 0x80 != 0;
    let mut offset = 0x4C;
    if has_id_list {
        offset += 2 + read_u16(data, offset)? as usize;
    }
    if has_link_info {
        let info = offset;
        let size = read_u32(data, info)? as usize;
        let header_size = read_u32(data, info + 4)? as usize;
        let info_flags = read_u32(data, info + 8)?;
        if info_flags & 0x1 != 0 {
            let base = if header_size >= 0x24 {
                read_u32(data, info + 0x1C).and_then(|unicode_offset| utf16_c_string(data, info + unicode_offset as usize))
            } else { None }.or_else(|| read_u32(data, info + 0x10).and_then(|base_offset| c_string(data, info + base_offset as usize)));
            let suffix = if header_size >= 0x24 {
                read_u32(data, info + 0x20).and_then(|unicode_offset| utf16_c_string(data, info + unicode_offset as usize))
            } else { None }.or_else(|| read_u32(data, info + 0x18).and_then(|suffix_offset| c_string(data, info + suffix_offset as usize)));
            if let Some(base) = base.filter(|base| !base.is_empty()) {
                let suffix = suffix.unwrap_or_default();
                let joined = if suffix.is_empty() { base } else if base.ends_with('\\') { format!("{base}{suffix}") } else { format!(r"{base}\{suffix}") };
                return Some(joined);
            }
        }
        offset = info + size;
    }
    // StringData: NAME_STRING, RELATIVE_PATH, ...
    let read_string = |offset: &mut usize| -> Option<String> {
        let count = read_u16(data, *offset)? as usize;
        let start = *offset + 2;
        let value = if unicode {
            let bytes = data.get(start..start + count * 2)?;
            *offset = start + count * 2;
            String::from_utf16_lossy(&bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect::<Vec<_>>())
        } else {
            let bytes = data.get(start..start + count)?;
            *offset = start + count;
            bytes.iter().map(|byte| *byte as char).collect()
        };
        Some(value)
    };
    if has_name { read_string(&mut offset)?; }
    if has_relative_path {
        let relative = read_string(&mut offset)?;
        let base = link_path.parent()?;
        let joined = base.join(relative.replace('/', "\\"));
        return Some(normalize_dots(&joined));
    }
    None
}

fn normalize_dots(path: &Path) -> String {
    let mut parts: Vec<String> = Vec::new();
    for component in path.to_string_lossy().split('\\') {
        match component {
            "." | "" if !parts.is_empty() => {}
            ".." => { if parts.len() > 1 { parts.pop(); } }
            other => parts.push(other.to_owned()),
        }
    }
    parts.join("\\")
}

fn collect_links(directory: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(directory) else { return; };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(metadata) = std::fs::symlink_metadata(&path) else { continue; };
        if crate::is_reparse_point(&metadata) { continue; }
        if metadata.is_dir() && depth < 4 {
            collect_links(&path, depth + 1, out);
        } else if metadata.is_file() && path.extension().is_some_and(|extension| extension.eq_ignore_ascii_case("lnk")) {
            out.push(path);
            if out.len() > 5_000 { return; }
        }
    }
}

fn shortcuts(apps: &[Application], out: &mut Vec<SystemReference>) {
    let mut seen = std::collections::HashSet::new();
    // Startup folders come first; they also live inside the Start Menu Programs tree.
    let mut directories = crate::shortcut_directories();
    directories.sort_by_key(|(kind, _, _)| *kind != "startup_folder");
    for (kind, directory, machine_wide) in directories {
        let mut links = Vec::new();
        collect_links(&directory, 0, &mut links);
        for link in links {
            if !seen.insert(link.to_string_lossy().to_ascii_lowercase()) { continue; }
            let Ok(data) = std::fs::read(&link) else { continue; };
            if data.len() > 1_048_576 { continue; }
            let target = parse_shell_link(&data, &link);
            // Shortcuts to shell items, URLs or network shares are not file targets we can judge.
            let target = target.filter(|path| Path::new(path).is_absolute() && !path.starts_with(r"\\"));
            if target.is_none() { continue; }
            let name = link.file_stem().map(|stem| stem.to_string_lossy().into_owned()).unwrap_or_default();
            let location = link.to_string_lossy().into_owned();
            let command = target.clone().unwrap_or_default();
            out.push(reference(kind, name, location, command, target, apps, machine_wide));
        }
    }
}

/// Collects all supported references. This takes a few seconds on typical
/// systems because scheduled tasks are listed through PowerShell.
pub fn collect(apps: &[Application]) -> ReferenceInventory {
    let mut references = Vec::new();
    let mut warnings = Vec::new();
    run_keys(apps, &mut references, &mut warnings);
    shortcuts(apps, &mut references);
    services(apps, &mut references, &mut warnings);
    scheduled_tasks(apps, &mut references, &mut warnings);
    url_protocols_and_handlers(apps, &mut references);
    app_paths(apps, &mut references);
    let mut seen = std::collections::HashSet::new();
    references.retain(|reference| seen.insert(reference.id.clone()));
    references.sort_by(|left, right| {
        let rank = |status: &str| match status { "dead" => 0, "unresolved" => 2, _ => 1 };
        rank(&left.status).cmp(&rank(&right.status))
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
    });
    ReferenceInventory { references, warnings }
}

/// True if `path` is `directory` or lies inside it (case-insensitive, Windows separators).
pub fn path_is_within(path: &str, directory: &str) -> bool {
    let path = path.trim_end_matches(['\\', '/']).to_ascii_lowercase().replace('/', "\\");
    let directory = directory.trim_end_matches(['\\', '/']).to_ascii_lowercase().replace('/', "\\");
    !directory.is_empty() && (path == directory || path.starts_with(&format!("{directory}\\")))
}

/// Short human-readable name for a reference's owner, falling back to its own name.
pub fn display_owner(reference: &SystemReference) -> String {
    reference.owner.as_ref().map(|owner| owner.name.clone()).unwrap_or_else(|| reference.name.clone())
}

/// Normalized key used to relate a reference name to directory names.
pub fn reference_name_key(reference: &SystemReference) -> String {
    normalize_name(&reference.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_targets_handle_quotes_spaces_and_hosts() {
        assert_eq!(command_target(r#""C:\Program Files\Foo\foo.exe" --background"#).as_deref(), Some(r"C:\Program Files\Foo\foo.exe"));
        assert_eq!(command_target(r"C:\Program Files\Foo\foo.exe /silent").as_deref(), Some(r"C:\Program Files\Foo\foo.exe"));
        assert_eq!(command_target(r"C:\Tools\a.exe,0").as_deref(), Some(r"C:\Tools\a.exe"));
        let dll = command_target(r#"C:\Windows\System32\rundll32.exe "C:\Old App\helper.dll",Start"#);
        assert_eq!(dll.as_deref(), Some(r"C:\Old App\helper.dll"));
        assert!(command_target("").is_none());
        assert!(command_target("relative.exe --x").is_none() || command_target("relative.exe --x").unwrap().contains('\\'));
    }

    #[test]
    fn service_image_paths_are_normalized() {
        let root = system_root();
        assert_eq!(command_target(r"\SystemRoot\System32\drivers\x.sys").unwrap().to_ascii_lowercase(), format!(r"{root}\System32\drivers\x.sys").to_ascii_lowercase());
        assert_eq!(command_target(r"\??\C:\Vendor\svc.exe").as_deref(), Some(r"C:\Vendor\svc.exe"));
    }

    #[test]
    fn within_is_component_aware() {
        assert!(path_is_within(r"C:\A\B\c.exe", r"C:\a\b"));
        assert!(!path_is_within(r"C:\A\Bc\c.exe", r"C:\a\b"));
    }

    fn link_with_local_path(target: &str) -> Vec<u8> {
        let mut data = vec![0u8; 0x4C];
        data[0..4].copy_from_slice(&0x4Cu32.to_le_bytes());
        data[0x14..0x18].copy_from_slice(&0x2u32.to_le_bytes());
        let base = target.as_bytes();
        let header = 0x1C;
        let size = header + base.len() + 1 + 1;
        let mut info = vec![0u8; header];
        info[0..4].copy_from_slice(&(size as u32).to_le_bytes());
        info[4..8].copy_from_slice(&(header as u32).to_le_bytes());
        info[8..12].copy_from_slice(&1u32.to_le_bytes());
        info[0x10..0x14].copy_from_slice(&(header as u32).to_le_bytes());
        info[0x18..0x1C].copy_from_slice(&((header + base.len() + 1) as u32).to_le_bytes());
        info.extend_from_slice(base);
        info.push(0);
        info.push(0);
        data.extend(info);
        data
    }

    #[test]
    fn shell_link_local_base_path_is_read() {
        let data = link_with_local_path(r"C:\Games\Old\game.exe");
        assert_eq!(parse_shell_link(&data, Path::new(r"C:\Links\x.lnk")).as_deref(), Some(r"C:\Games\Old\game.exe"));
        assert!(parse_shell_link(b"not a link", Path::new(r"C:\x.lnk")).is_none());
    }
}
