use cleaner_core::public_data::FolderKnowledge;

pub type Knowledge = FolderKnowledge;
use reqwest::blocking::Client;
use reqwest::header::{ETAG, IF_NONE_MATCH};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const LUDUSAVI_URL: &str =
    "https://raw.githubusercontent.com/mtkennerly/ludusavi-manifest/master/data/manifest.yaml";
const WINAPP2_URL: &str = "https://raw.githubusercontent.com/MoscaDotTo/Winapp2/master/Winapp2.ini";

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicDataStatus {
    pub updated_at_unix: Option<u64>,
    pub game_directories: usize,
    pub cleaner_directories: usize,
    pub ludusavi_etag: Option<String>,
    pub winapp2_etag: Option<String>,
    pub warnings: Vec<String>,
}

fn paths(directory: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    (
        directory.join("public-folder-index.json"),
        directory.join("public-folder-status.json"),
    )
}

pub fn load(directory: &Path) -> Result<(FolderKnowledge, PublicDataStatus), String> {
    let (index_path, status_path) = paths(directory);
    let knowledge = match fs::read(index_path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|err| format!("Public folder index is unreadable: {err}"))?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => FolderKnowledge::default(),
        Err(err) => return Err(format!("Public folder index could not be read: {err}")),
    };
    let status = match fs::read(status_path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|err| format!("Public folder status is unreadable: {err}"))?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => PublicDataStatus::default(),
        Err(err) => return Err(format!("Public folder status could not be read: {err}")),
    };
    Ok((knowledge, status))
}

fn fetch(
    client: &Client,
    url: &str,
    etag: Option<&str>,
    max_bytes: u64,
) -> Result<Option<(Vec<u8>, Option<String>)>, String> {
    let mut request = client.get(url);
    if let Some(etag) = etag {
        request = request.header(IF_NONE_MATCH, etag);
    }
    let response = request
        .send()
        .map_err(|err| format!("Download failed: {err}"))?;
    if response.status() == reqwest::StatusCode::NOT_MODIFIED {
        return Ok(None);
    }
    if !response.status().is_success() {
        return Err(format!("Server returned HTTP {}", response.status()));
    }
    let new_etag = response
        .headers()
        .get(ETAG)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let mut bytes = Vec::new();
    response
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| format!("Download could not be read: {err}"))?;
    if bytes.len() as u64 > max_bytes {
        return Err("Download exceeded its size limit".into());
    }
    Ok(Some((bytes, new_etag)))
}

pub fn update(directory: &Path) -> Result<PublicDataStatus, String> {
    fs::create_dir_all(directory)
        .map_err(|err| format!("Public data directory could not be created: {err}"))?;
    let (mut knowledge, mut status) = match load(directory) {
        Ok((knowledge, mut status)) => {
            status.warnings.clear();
            (knowledge, status)
        }
        Err(error) => {
            let mut status = PublicDataStatus::default();
            status
                .warnings
                .push(format!("Old cache was reset: {error}"));
            (FolderKnowledge::default(), status)
        }
    };
    let cache_warning = std::mem::take(&mut status.warnings);
    let client = Client::builder()
        .timeout(Duration::from_secs(20))
        .user_agent("WindowsOrphanCleaner/0.1 (https://github.com; public folder index update)")
        .build()
        .map_err(|err| err.to_string())?;
    let mut changed = false;
    let ludusavi_etag = (!knowledge.games.is_empty())
        .then_some(status.ludusavi_etag.as_deref())
        .flatten();
    match fetch(&client, LUDUSAVI_URL, ludusavi_etag, 25_000_000) {
        Ok(Some((bytes, etag))) => match FolderKnowledge::from_ludusavi_yaml(&bytes) {
            Ok(index) => {
                knowledge.games = index;
                status.ludusavi_etag = etag;
                changed = true;
            }
            Err(err) => status.warnings.push(format!("Ludusavi: {err}")),
        },
        Ok(None) => {}
        Err(err) => status.warnings.push(format!("Ludusavi: {err}")),
    }
    let winapp2_etag = (!knowledge.cleaner_rules.is_empty())
        .then_some(status.winapp2_etag.as_deref())
        .flatten();
    match fetch(&client, WINAPP2_URL, winapp2_etag, 5_000_000) {
        Ok(Some((bytes, etag))) => match FolderKnowledge::from_winapp2_ini(&bytes) {
            Ok(index) => {
                knowledge.cleaner_rules = index;
                status.winapp2_etag = etag;
                changed = true;
            }
            Err(err) => status.warnings.push(format!("Winapp2: {err}")),
        },
        Ok(None) => {}
        Err(err) => status.warnings.push(format!("Winapp2: {err}")),
    }
    status.game_directories = knowledge.games.len();
    status.cleaner_directories = knowledge.cleaner_rules.len();
    status.warnings.splice(0..0, cache_warning);
    if changed {
        status.updated_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|time| time.as_secs());
        let (index_path, _) = paths(directory);
        fs::write(
            index_path,
            serde_json::to_vec(&knowledge).map_err(|err| err.to_string())?,
        )
        .map_err(|err| format!("Public folder index could not be saved: {err}"))?;
    }
    let (_, status_path) = paths(directory);
    fs::write(
        status_path,
        serde_json::to_vec(&status).map_err(|err| err.to_string())?,
    )
    .map_err(|err| format!("Public folder status could not be saved: {err}"))?;
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "downloads current public datasets"]
    fn live_public_data_updates_and_reuses_cache() {
        let directory = std::env::temp_dir().join(format!(
            "orphan-cleaner-public-data-test-{}",
            std::process::id()
        ));
        let status = update(&directory).unwrap();
        assert!(status.game_directories > 100);
        assert!(status.cleaner_directories > 100);
        assert!(status.warnings.is_empty(), "{:?}", status.warnings);
        let (knowledge, loaded) = load(&directory).unwrap();
        assert_eq!(knowledge.games.len(), loaded.game_directories);
        assert_eq!(knowledge.cleaner_rules.len(), loaded.cleaner_directories);
        let again = update(&directory).unwrap();
        assert_eq!(again.game_directories, status.game_directories);
        assert_eq!(again.cleaner_directories, status.cleaner_directories);
        assert!(again.warnings.is_empty(), "{:?}", again.warnings);
        fs::remove_dir_all(directory).unwrap();
    }
}
