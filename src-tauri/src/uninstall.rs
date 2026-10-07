use cleaner_core::{Application, DirectoryResult, Inventory};
use serde::Serialize;
use std::path::{Path, PathBuf};
use winreg::{RegKey, enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY}};

#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UninstallPlan {
    pub application: Application,
    pub executable: String,
    pub arguments: String,
    pub source: String,
    pub folders: Vec<String>,
    pub excluded_folders: Vec<String>,
}

fn normalized(path: &str) -> String { path.replace('/', "\\").trim_end_matches('\\').to_lowercase() }
fn within(path: &str, parent: &str) -> bool { let path = normalized(path); let parent = normalized(parent); path == parent || path.starts_with(&(parent + "\\")) }
fn owns(owner: &Application, app: &Application) -> bool { owner.id.eq_ignore_ascii_case(&app.id) || cleaner_core::normalize_name(&owner.name) == cleaner_core::normalize_name(&app.name) }

/// Never offer a shared/system parent or one containing another application's data.
pub fn folders(app: &Application, results: &[DirectoryResult]) -> (Vec<String>, Vec<String>) {
    let linked: Vec<_> = results.iter().filter(|r| r.owner.as_ref().is_some_and(|owner| owns(owner, app))).collect();
    let mut included = Vec::new();
    let mut excluded = Vec::new();
    for result in linked {
        let protected = matches!(result.location_class.as_deref(), Some("system" | "shared_runtime")) || result.ownership == "shared"
            || results.iter().any(|child| normalized(&child.path) != normalized(&result.path) && within(&child.path, &result.path)
                && (child.owner.as_ref().is_none_or(|owner| !owns(owner, app)) || child.ownership == "shared"));
        if protected { excluded.push(result.path.clone()); } else { included.push(result.path.clone()); }
    }
    let all = included.clone();
    included.retain(|path| !all.iter().any(|parent| path != parent && within(path, parent)));
    (included, excluded)
}

fn expand(value: &str) -> String {
    let mut result = String::new();
    let mut rest = value;
    while let Some(start) = rest.find('%') {
        result.push_str(&rest[..start]);
        let Some(end) = rest[start + 1..].find('%').map(|i| start + 1 + i) else { result.push_str(&rest[start..]); return result; };
        let name = &rest[start + 1..end];
        match std::env::vars().find(|(key, _)| key.eq_ignore_ascii_case(name)) {
            Some((_, replacement)) => result.push_str(&replacement),
            None => result.push_str(&rest[start..=end]),
        }
        rest = &rest[end + 1..];
    }
    result.push_str(rest);
    result
}

fn split_command(value: &str) -> Result<(String, String), String> {
    let expanded = expand(value);
    let command = expanded.trim();
    let (executable, arguments) = if let Some(rest) = command.strip_prefix('"') {
        let (exe, args) = rest.split_once('"').ok_or("Uninstaller command has an unmatched quote.")?;
        (exe.to_owned(), args.trim().to_owned())
    } else {
        // Legacy registry entries often omit quotes around paths containing spaces.
        let end = command.to_lowercase().find(".exe").map(|i| i + 4).ok_or("Uninstaller command does not name an executable.")?;
        (command[..end].to_owned(), command[end..].trim().to_owned())
    };
    let mut path = PathBuf::from(&executable);
    if !path.is_absolute() && path.components().count() == 1 {
        path = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Windows")).join("System32").join(path);
    }
    if !path.is_absolute() || !path.is_file() || executable.starts_with(r"\\") { return Err("The registered uninstaller executable is missing or unsupported.".into()); }
    let arguments = if path.file_name().is_some_and(|n| n.to_string_lossy().eq_ignore_ascii_case("msiexec.exe")) { msi_remove_arguments(&arguments) } else { arguments };
    Ok((path.to_string_lossy().into_owned(), arguments))
}

fn msi_remove_arguments(arguments: &str) -> String {
    let mut quoted = false;
    for (index, ch) in arguments.char_indices() {
        if ch == '"' { quoted = !quoted; }
        if !quoted && ch == '/' && (index == 0 || arguments[..index].ends_with(char::is_whitespace))
            && arguments[index..].get(..2).is_some_and(|prefix| prefix.eq_ignore_ascii_case("/i"))
            && arguments[index + 2..].starts_with(|ch: char| ch.is_whitespace() || ch == '{') {
            return format!("{}/X{}", &arguments[..index], &arguments[index + 2..]);
        }
    }
    arguments.to_owned()
}

pub fn removal_folders(app: &Application, results: &[DirectoryResult], installed: &[Application]) -> (Vec<String>, Vec<String>) {
    let mut measured = results.to_vec();
    // Include exact registered installations even for older scan snapshots.
    for application in std::iter::once(app).chain(installed.iter().filter(|a| !owns(a, app))) {
        if let Some(path) = &application.install_location {
            if Path::new(path).is_absolute() && Path::new(path).is_dir() && !measured.iter().any(|r| r.path.eq_ignore_ascii_case(path)) {
                measured.push(DirectoryResult { path: path.clone(), owner: Some(application.clone()), ..Default::default() });
            }
        }
    }
    let (mut included, mut excluded) = folders(app, &measured);
    included.retain(|path| {
        let shared = installed.iter().any(|other| !owns(other, app) && other.install_location.as_deref().is_some_and(|p| within(p, path)));
        if shared { excluded.push(path.clone()); }
        !shared
    });
    (included, excluded)
}

pub fn plan(app: &Application, results: &[DirectoryResult], installed: &[Application]) -> Result<UninstallPlan, String> {
    let (folders, excluded_folders) = removal_folders(app, results, installed);
    let (executable, arguments, source) = if let Some(family) = &app.package_family_name {
        // Family is supplied via an environment variable, never interpolated into code.
        (cleaner_core::powershell_path().display().to_string(), family.clone(), "Windows package removal".into())
    } else {
        let registry = (|| {
            let mut parts = app.id.splitn(3, ':');
            let hive = match parts.next()? { "HKCU" => HKEY_CURRENT_USER, "HKLM" => HKEY_LOCAL_MACHINE, _ => return None };
            let flags = match parts.next()? { "32" => KEY_WOW64_32KEY, "64" => KEY_WOW64_64KEY, _ => return None };
            let entry = RegKey::predef(hive).open_subkey_with_flags(format!(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{}", parts.next()?), KEY_READ | flags).ok()?;
            entry.get_value::<String, _>("UninstallString").ok().filter(|s| !s.trim().is_empty())
        })();
        if let Some((exe, args)) = registry.as_deref().and_then(|command| split_command(command).ok()) {
            (exe, args, "Windows uninstall registry".into())
        } else {
            let location = app.install_location.as_deref().ok_or("No registered uninstaller or install folder is available.")?;
            let mut detected: Vec<_> = std::fs::read_dir(location).map_err(|e| e.to_string())?.filter_map(Result::ok).filter(|entry| {
                let name = entry.file_name().to_string_lossy().to_lowercase();
                (name == "uninstall.exe" || (name.starts_with("unins") && name.ends_with(".exe")))
                    && entry.file_type().is_ok_and(|kind| kind.is_file() && !kind.is_symlink())
            }).map(|entry| entry.path()).collect();
            detected.sort();
            if detected.len() != 1 { return Err("No unique uninstaller was found in this application's install folder.".into()); }
            (detected[0].display().to_string(), String::new(), "Detected uninstall executable".into())
        }
    };
    Ok(UninstallPlan { application: app.clone(), executable, arguments, source, folders, excluded_folders })
}

pub fn launch(plan: &UninstallPlan) -> Result<(), String> {
    if plan.application.package_family_name.is_some() {
        use std::os::windows::process::CommandExt;
        std::process::Command::new(&plan.executable)
            .args(["-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop'; Get-AppxPackage | Where-Object { $_.PackageFamilyName -eq $env:ORPHAN_CLEANER_REMOVE_FAMILY } | Remove-AppxPackage"])
            .env("ORPHAN_CLEANER_REMOVE_FAMILY", &plan.arguments).creation_flags(0x08000000)
            .spawn().map_err(|e| format!("Package removal could not start: {e}"))?;
    } else {
        use windows::{core::PCWSTR, Win32::{UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOWNORMAL}}};
        let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        let verb = wide("open"); let exe = wide(&plan.executable); let args = wide(&plan.arguments);
        let result = unsafe { ShellExecuteW(None, PCWSTR(verb.as_ptr()), PCWSTR(exe.as_ptr()), PCWSTR(args.as_ptr()), PCWSTR::null(), SW_SHOWNORMAL) };
        if result.0 as isize <= 32 { return Err(format!("Windows could not launch the uninstaller (code {}). Administrator approval may be required.", result.0 as isize)); }
    }
    Ok(())
}

pub fn verify(app: &Application, current: &Inventory) -> Result<(), String> {
    if !current.warnings.is_empty() { return Err("Windows inventory is incomplete; remaining folders cannot be removed yet.".into()); }
    if current.applications.iter().any(|candidate| cleaner_core::same_application(candidate, app)) { return Err("Windows still lists this application. Finish its uninstaller, then check again. No folders have been moved.".into()); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn msi_modify_registration_becomes_uninstall() {
        assert_eq!(msi_remove_arguments("/I{ABC} /passive"), "/X{ABC} /passive");
        assert_eq!(msi_remove_arguments("/i {ABC}"), "/X {ABC}");
        assert_eq!(msi_remove_arguments(r#"/passive /I{ABC} TRANSFORMS="C:\Has  Spaces\file.mst""#), r#"/passive /X{ABC} TRANSFORMS="C:\Has  Spaces\file.mst""#);
    }
    #[test]
    fn shared_parents_are_excluded_but_exclusive_children_remain() {
        let app = Application { id: "a".into(), name: "Example".into(), ..Default::default() };
        let results = vec![DirectoryResult { path: r"C:\Vendor".into(), owner: Some(app.clone()), ..Default::default() }, DirectoryResult { path: r"C:\Vendor\Example".into(), owner: Some(app.clone()), ..Default::default() }, DirectoryResult { path: r"C:\Vendor\Other".into(), ..Default::default() }];
        let (included, excluded) = folders(&app, &results);
        assert_eq!(included, [r"C:\Vendor\Example"]);
        assert_eq!(excluded, [r"C:\Vendor"]);
        assert!(verify(&app, &Inventory { applications: vec![app.clone()], ..Default::default() }).is_err());
        assert!(verify(&app, &Inventory::default()).is_ok());
        assert!(verify(&app, &Inventory { warnings: vec!["incomplete".into()], ..Default::default() }).is_err());
    }
    #[test]
    fn detects_unique_direct_uninstaller_and_includes_unscanned_installation() {
        let root = std::env::temp_dir().join(format!("cleaner-uninstall-detection-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("unins000.exe"), b"fixture, never executed").unwrap();
        let app = Application { id: "fixture".into(), name: "Fixture".into(), install_location: Some(root.display().to_string()), ..Default::default() };
        let review = plan(&app, &[], &[]).unwrap();
        assert_eq!(review.source, "Detected uninstall executable");
        assert_eq!(review.folders, [root.display().to_string()]);
        std::fs::write(root.join("uninstall.exe"), b"fixture, never executed").unwrap();
        assert!(plan(&app, &[], &[]).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn shared_associations_do_not_authorize_uninstall_cleanup() {
        let app = Application { id: "driver".into(), name: "NVIDIA Graphics Driver".into(), ..Default::default() };
        let result = DirectoryResult {
            path: r"C:\Users\Test\AppData\Local\NVIDIA".into(),
            ownership: "shared".into(), orphan_status: "associated_with_installed".into(),
            associated_applications: vec![app.clone()], ..Default::default()
        };
        let (included, _) = folders(&app, &[result]);
        assert!(included.is_empty());
    }
}
