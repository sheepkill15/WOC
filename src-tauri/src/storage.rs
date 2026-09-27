use cleaner_core::{DirectoryResult, Inventory, ScanSummary};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedScan {
    pub captured_at_unix: u64,
    pub inventory: Inventory,
    pub summary: ScanSummary,
    pub results: Vec<DirectoryResult>,
}

fn initialize_db(conn: &Connection) -> Result<(), String> {
    let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|err| err.to_string())?;
    if version > 1 {
        return Err("Saved scans use a newer database format.".into());
    }
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;
         CREATE TABLE IF NOT EXISTS scan_sessions (
             id INTEGER PRIMARY KEY,
             captured_at_unix INTEGER NOT NULL,
             inventory_json TEXT NOT NULL,
             summary_json TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS scan_results (
             session_id INTEGER NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,
             path TEXT NOT NULL,
             result_json TEXT NOT NULL,
             PRIMARY KEY (session_id, path)
         );
         PRAGMA user_version = 1;"
    ).map_err(|err| err.to_string())
}

fn open_db(path: &Path) -> Result<Connection, String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    let conn = Connection::open(path).map_err(|err| err.to_string())?;
    initialize_db(&conn)?;
    Ok(conn)
}

fn save_to_connection(conn: &mut Connection, scan: &SavedScan) -> Result<(), String> {
    let inventory_json = serde_json::to_string(&scan.inventory).map_err(|err| err.to_string())?;
    let summary_json = serde_json::to_string(&scan.summary).map_err(|err| err.to_string())?;
    let transaction = conn.transaction().map_err(|err| err.to_string())?;
    transaction.execute(
        "INSERT INTO scan_sessions (captured_at_unix, inventory_json, summary_json) VALUES (?1, ?2, ?3)",
        params![scan.captured_at_unix as i64, inventory_json, summary_json],
    ).map_err(|err| err.to_string())?;
    let session_id = transaction.last_insert_rowid();
    {
        let mut statement = transaction.prepare_cached(
            "INSERT INTO scan_results (session_id, path, result_json) VALUES (?1, ?2, ?3)"
        ).map_err(|err| err.to_string())?;
        for result in &scan.results {
            let json = serde_json::to_string(result).map_err(|err| err.to_string())?;
            statement.execute(params![session_id, result.path, json]).map_err(|err| err.to_string())?;
        }
    }
    transaction.execute(
        "DELETE FROM scan_sessions WHERE id NOT IN (SELECT id FROM scan_sessions ORDER BY id DESC LIMIT 10)",
        [],
    ).map_err(|err| err.to_string())?;
    transaction.commit().map_err(|err| err.to_string())
}

fn load_from_connection(conn: &Connection) -> Result<Option<SavedScan>, String> {
    let row: Option<(i64, i64, String, String)> = conn.query_row(
        "SELECT id, captured_at_unix, inventory_json, summary_json FROM scan_sessions ORDER BY id DESC LIMIT 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    ).optional().map_err(|err| err.to_string())?;
    let Some((id, captured_at, inventory_json, summary_json)) = row else { return Ok(None); };
    let mut statement = conn.prepare("SELECT result_json FROM scan_results WHERE session_id = ?1 ORDER BY path")
        .map_err(|err| err.to_string())?;
    let json_rows = statement.query_map([id], |row| row.get::<_, String>(0))
        .map_err(|err| err.to_string())?;
    let mut results = Vec::new();
    for json in json_rows {
        let json = json.map_err(|err| err.to_string())?;
        results.push(serde_json::from_str(&json).map_err(|err| format!("Saved result is unreadable: {err}"))?);
    }
    Ok(Some(SavedScan {
        captured_at_unix: captured_at as u64,
        inventory: serde_json::from_str(&inventory_json).map_err(|err| format!("Saved inventory is unreadable: {err}"))?,
        summary: serde_json::from_str(&summary_json).map_err(|err| format!("Saved summary is unreadable: {err}"))?,
        results,
    }))
}

pub fn save(path: &Path, inventory: Inventory, summary: ScanSummary, results: Vec<DirectoryResult>) -> Result<u64, String> {
    let captured_at_unix = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|err| err.to_string())?.as_secs();
    let scan = SavedScan { captured_at_unix, inventory, summary, results };
    let mut conn = open_db(path)?;
    save_to_connection(&mut conn, &scan)?;
    Ok(captured_at_unix)
}

pub fn load_latest(path: &Path) -> Result<Option<SavedScan>, String> {
    let conn = open_db(path)?;
    load_from_connection(&conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_snapshot_round_trips_and_old_snapshots_are_pruned() {
        let mut conn = Connection::open_in_memory().unwrap();
        initialize_db(&conn).unwrap();
        for i in 0..12 {
            let scan = SavedScan {
                captured_at_unix: i,
                inventory: Inventory { applications: vec![], warnings: vec![] },
                summary: ScanSummary { directories: 1, bytes: i, ..Default::default() },
                results: vec![DirectoryResult {
                    path: format!(r"C:\Test\App{i}"), root: "Local".into(), size_bytes: i,
                    file_count: 1, directory_count: 0, newest_modified_unix: None,
                    skipped_entries: 0, owner: None, ownership: "unknown".into(),
                    orphan_status: "unknown".into(), evidence: vec![],
                }],
            };
            save_to_connection(&mut conn, &scan).unwrap();
        }
        let loaded = load_from_connection(&conn).unwrap().unwrap();
        assert_eq!(loaded.captured_at_unix, 11);
        assert_eq!(loaded.results.len(), 1);
        assert_eq!(loaded.results[0].path, r"C:\Test\App11");
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM scan_sessions", [], |row| row.get(0)).unwrap();
        assert_eq!(count, 10);
        let result_count: i64 = conn.query_row("SELECT COUNT(*) FROM scan_results", [], |row| row.get(0)).unwrap();
        assert_eq!(result_count, 10);
    }
}
