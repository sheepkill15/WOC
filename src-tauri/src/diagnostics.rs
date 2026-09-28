use serde::Serialize;
use serde_json::{Value, json};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::public_data::PublicDataStatus;
use crate::storage::SavedScan;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticsExport {
    pub path: String,
    pub scans: usize,
    pub directories: usize,
}

fn redact_text(value: &str, replacements: &[(String, &'static str)]) -> String {
    let mut redacted = value.to_owned();
    for (sensitive, replacement) in replacements {
        if sensitive.is_empty() { continue; }
        loop {
            let lower = redacted.to_ascii_lowercase();
            let needle = sensitive.to_ascii_lowercase();
            let Some(index) = lower.find(&needle) else { break; };
            redacted.replace_range(index..index + sensitive.len(), replacement);
        }
    }
    redacted
}

fn redact_value(value: &mut Value, replacements: &[(String, &'static str)]) {
    match value {
        Value::String(text) => *text = redact_text(text, replacements),
        Value::Array(items) => items.iter_mut().for_each(|item| redact_value(item, replacements)),
        Value::Object(fields) => fields.values_mut().for_each(|item| redact_value(item, replacements)),
        _ => {}
    }
}

pub const PRIVACY_NOTICE: &str = "Contains installed application names and versions, scanned directory paths with the names of their immediate subfolders, aggregate sizes, counts and file-extension totals, classifier evidence and assessments, executable version metadata (without file names), startup/task/service/shortcut references with their command lines, warnings, up to ten completed scans, and the last 200 application log lines. User-profile and app-local-data path prefixes are redacted. It contains no file contents and no individual file names.";

/// Removes executable file names; version metadata remains for troubleshooting.
fn strip_file_names(value: &mut Value) {
    match value {
        Value::Object(fields) => {
            if let Some(Value::Array(executables)) = fields.get_mut("executables") {
                for executable in executables.iter_mut() {
                    if let Some(object) = executable.as_object_mut() { object.remove("fileName"); }
                }
            }
            fields.values_mut().for_each(strip_file_names);
        }
        Value::Array(items) => items.iter_mut().for_each(strip_file_names),
        _ => {}
    }
}

fn build_bundle(scans: &[SavedScan], status: &PublicDataStatus, app_local_data: &Path) -> Result<Value, String> {
    let generated_at_unix = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|err| err.to_string())?.as_secs();
    let mut public_data = serde_json::to_value(status).map_err(|err| err.to_string())?;
    if let Some(fields) = public_data.as_object_mut() {
        fields.remove("ludusaviEtag");
        fields.remove("winapp2Etag");
    }
    let mut bundle = json!({
        "formatVersion": 2,
        "generatedAtUnix": generated_at_unix,
        "privacyNotice": PRIVACY_NOTICE,
        "publicFolderData": public_data,
        "scans": scans,
        "recentLog": crate::logging::tail(app_local_data, 200),
    });
    strip_file_names(&mut bundle);
    let mut replacements = vec![(app_local_data.to_string_lossy().into_owned(), "%APP_LOCAL_DATA%")];
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        replacements.push((profile.to_string_lossy().into_owned(), "%USERPROFILE%"));
    }
    replacements.sort_by(|left, right| right.0.len().cmp(&left.0.len()));
    redact_value(&mut bundle, &replacements);
    Ok(bundle)
}

pub fn export(downloads: &Path, app_local_data: &Path, scans: &[SavedScan], status: &PublicDataStatus) -> Result<DiagnosticsExport, String> {
    std::fs::create_dir_all(downloads).map_err(|err| format!("Downloads directory is unavailable: {err}"))?;
    let bundle = build_bundle(scans, status, app_local_data)?;
    let bytes = serde_json::to_vec_pretty(&bundle).map_err(|err| err.to_string())?;
    let timestamp = bundle.get("generatedAtUnix").and_then(Value::as_u64).unwrap_or_default();
    let mut destination = PathBuf::new();
    let mut file = None;
    for suffix in 0..100u8 {
        let name = if suffix == 0 {
            format!("orphan-cleaner-diagnostics-{timestamp}.json")
        } else {
            format!("orphan-cleaner-diagnostics-{timestamp}-{suffix}.json")
        };
        destination = downloads.join(name);
        match OpenOptions::new().write(true).create_new(true).open(&destination) {
            Ok(opened) => { file = Some(opened); break; }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("Diagnostics file could not be created: {error}")),
        }
    }
    let mut file = file.ok_or("Could not choose a unique diagnostics filename")?;
    file.write_all(&bytes).map_err(|err| format!("Diagnostics file could not be written: {err}"))?;
    file.sync_all().map_err(|err| format!("Diagnostics file could not be finalized: {err}"))?;
    Ok(DiagnosticsExport {
        path: destination.to_string_lossy().into_owned(),
        scans: scans.len(),
        directories: scans.iter().map(|scan| scan.results.len()).sum(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cleaner_core::{DirectoryResult, Inventory, ScanSummary};

    #[test]
    fn bundle_redacts_profile_and_private_app_data_paths() {
        let app_local = Path::new(r"C:\Users\Private Person\AppData\Local\dev.orphancleaner.desktop");
        let scan = SavedScan {
            captured_at_unix: 1,
            inventory: Inventory { applications: vec![], warnings: vec![] },
            summary: ScanSummary { scanned_roots: vec![r"Local: C:\Users\Private Person\AppData\Local".into()], ..Default::default() },
            results: vec![DirectoryResult {
                path: r"C:\Users\Private Person\AppData\Local\Example".into(), root: "Local".into(),
                parent_path: None,
                size_bytes: 1, file_count: 1, directory_count: 0, newest_modified_unix: None,
                skipped_entries: 0, owner: None, owner_hint: None, ownership: "unknown".into(),
                orphan_status: "unknown".into(), evidence: vec![],
                executables: vec![cleaner_core::ExecutableInfo { file_name: "secret.exe".into(), ..Default::default() }],
                ..Default::default()
            }],
            references: Default::default(),
        };
        let status = PublicDataStatus::default();
        let mut value = build_bundle(&[scan], &status, app_local).unwrap();
        redact_value(&mut value, &[(r"C:\Users\Private Person".into(), "%USERPROFILE%")]);
        let serialized = serde_json::to_string(&value).unwrap();
        assert!(!serialized.contains("Private Person"));
        assert!(serialized.contains("%USERPROFILE%"));
        assert!(!serialized.contains("ludusaviEtag"));
        assert!(!serialized.contains("secret.exe"));
    }

    #[test]
    fn export_creates_unique_readable_json() {
        let directory = std::env::temp_dir().join(format!("orphan-cleaner-diagnostics-test-{}", std::process::id()));
        let downloads = directory.join("Downloads");
        let app_local = directory.join("AppData");
        let status = PublicDataStatus::default();
        let first = export(&downloads, &app_local, &[], &status).unwrap();
        let second = export(&downloads, &app_local, &[], &status).unwrap();
        assert_ne!(first.path, second.path);
        let parsed: Value = serde_json::from_slice(&std::fs::read(&first.path).unwrap()).unwrap();
        assert_eq!(parsed["formatVersion"], 2);
        assert_eq!(parsed["scans"].as_array().unwrap().len(), 0);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
