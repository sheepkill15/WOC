//! Small append-only application log (spec §41). Paths under the user profile
//! are redacted before writing, and the file rotates at 1 MB.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

static LOCK: Mutex<()> = Mutex::new(());
const MAX_BYTES: u64 = 1_048_576;

pub fn log_path(app_local_data: &Path) -> PathBuf {
    app_local_data.join("logs").join("cleaner.log")
}

pub fn redact(text: &str) -> String {
    let mut output = text.to_owned();
    if let Some(profile) = std::env::var_os("USERPROFILE").map(|value| value.to_string_lossy().into_owned()).filter(|value| value.len() > 3) {
        let lower_profile = profile.to_ascii_lowercase();
        loop {
            let lower = output.to_ascii_lowercase();
            let Some(index) = lower.find(&lower_profile) else { break; };
            output.replace_range(index..index + profile.len(), "%USERPROFILE%");
        }
    }
    output
}

pub fn write(app_local_data: &Path, level: &str, message: &str) {
    let _guard = LOCK.lock();
    let path = log_path(app_local_data);
    if let Some(parent) = path.parent() { let _ = std::fs::create_dir_all(parent); }
    if std::fs::metadata(&path).is_ok_and(|metadata| metadata.len() > MAX_BYTES) {
        let _ = std::fs::rename(&path, path.with_extension("log.1"));
    }
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(file, "{} {level:<5} {}", crate::storage::now_unix(), redact(message).replace(['\r', '\n'], " "));
    }
}

pub fn info(app_local_data: &Path, message: &str) { write(app_local_data, "INFO", message); }
pub fn warn(app_local_data: &Path, message: &str) { write(app_local_data, "WARN", message); }

/// Last `lines` lines of the current log, already redacted when written.
pub fn tail(app_local_data: &Path, lines: usize) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(log_path(app_local_data)) else { return Vec::new(); };
    let all = text.lines().collect::<Vec<_>>();
    all[all.len().saturating_sub(lines)..].iter().map(|line| line.to_string()).collect()
}
