use cleaner_core::{DirectoryResult, Inventory, ReferenceInventory, ScanSummary};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub const RETAINED_SCANS: usize = 10;
const SCHEMA_VERSION: i64 = 3;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedScan {
    pub captured_at_unix: u64,
    pub inventory: Inventory,
    pub summary: ScanSummary,
    pub results: Vec<DirectoryResult>,
    #[serde(default)]
    pub references: ReferenceInventory,
}

/// Inventory-only view of an older scan, used by history comparisons.
#[derive(Clone, Debug)]
pub struct ScanInventory {
    pub captured_at_unix: u64,
    pub inventory: Inventory,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IgnoreRule {
    pub id: i64,
    /// path | application | category | once
    pub kind: String,
    pub value: String,
    pub label: String,
    pub created_at_unix: u64,
    #[serde(default)]
    pub scan_at_unix: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct QuarantineItem {
    pub id: i64,
    pub original_path: String,
    pub quarantine_path: String,
    pub size_bytes: u64,
    pub file_count: u64,
    pub created_at_unix: u64,
    pub owner: Option<String>,
    pub reason: String,
    /// directory | shortcut
    pub item_kind: String,
    /// quarantined | restored | purged
    pub status: String,
    pub updated_at_unix: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    /// Days before quarantined items are permanently deleted; 0 keeps them until purged manually.
    pub quarantine_retention_days: u32,
    pub default_scan_mode: String,
    /// Check for applications removed since the last scan when the app starts.
    pub check_removed_on_launch: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self { quarantine_retention_days: 30, default_scan_mode: "quick".into(), check_removed_on_launch: true }
    }
}

pub fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|time| time.as_secs()).unwrap_or_default()
}

fn err(error: impl ToString) -> String { error.to_string() }

fn initialize_db(conn: &Connection) -> Result<(), String> {
    let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0)).map_err(err)?;
    if version > SCHEMA_VERSION {
        return Err("Saved data uses a newer database format. Update the application.".into());
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
         );"
    ).map_err(err)?;
    if version < 2 {
        let has_references: bool = conn.prepare("SELECT 1 FROM pragma_table_info('scan_sessions') WHERE name = 'references_json'")
            .and_then(|mut statement| statement.exists([])).map_err(err)?;
        if !has_references {
            conn.execute("ALTER TABLE scan_sessions ADD COLUMN references_json TEXT", []).map_err(err)?;
        }
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS ignore_rules (
                 id INTEGER PRIMARY KEY,
                 kind TEXT NOT NULL,
                 value TEXT NOT NULL,
                 label TEXT NOT NULL,
                 created_at_unix INTEGER NOT NULL,
                 scan_at_unix INTEGER,
                 UNIQUE(kind, value)
             );
             CREATE TABLE IF NOT EXISTS quarantine_items (
                 id INTEGER PRIMARY KEY,
                 original_path TEXT NOT NULL,
                 quarantine_path TEXT NOT NULL,
                 size_bytes INTEGER NOT NULL,
                 file_count INTEGER NOT NULL,
                 created_at_unix INTEGER NOT NULL,
                 owner TEXT,
                 reason TEXT NOT NULL,
                 item_kind TEXT NOT NULL,
                 status TEXT NOT NULL,
                 updated_at_unix INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS cleanup_actions (
                 id INTEGER PRIMARY KEY,
                 at_unix INTEGER NOT NULL,
                 action TEXT NOT NULL,
                 path TEXT NOT NULL,
                 outcome TEXT NOT NULL,
                 detail TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS settings (
                 key TEXT PRIMARY KEY,
                 value TEXT NOT NULL
             );"
        ).map_err(err)?;
    }
    if version < 3 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS cleanup_exclusions (
                 path TEXT PRIMARY KEY COLLATE NOCASE,
                 scan_session_id INTEGER NOT NULL
             );
             INSERT OR IGNORE INTO cleanup_exclusions (path, scan_session_id)
             SELECT original_path, COALESCE((SELECT MAX(id) FROM scan_sessions), 0)
             FROM quarantine_items WHERE status IN ('quarantined', 'purged');"
        ).map_err(err)?;
        conn.pragma_update(None, "user_version", SCHEMA_VERSION).map_err(err)?;
    }
    Ok(())
}

pub fn open_db(path: &Path) -> Result<Connection, String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(err)?;
    }
    let conn = Connection::open(path).map_err(err)?;
    conn.busy_timeout(std::time::Duration::from_secs(5)).map_err(err)?;
    initialize_db(&conn)?;
    Ok(conn)
}

fn save_to_connection(conn: &mut Connection, scan: &SavedScan) -> Result<(), String> {
    let inventory_json = serde_json::to_string(&scan.inventory).map_err(err)?;
    let summary_json = serde_json::to_string(&scan.summary).map_err(err)?;
    let references_json = serde_json::to_string(&scan.references).map_err(err)?;
    let transaction = conn.transaction().map_err(err)?;
    transaction.execute(
        "INSERT INTO scan_sessions (captured_at_unix, inventory_json, summary_json, references_json) VALUES (?1, ?2, ?3, ?4)",
        params![scan.captured_at_unix as i64, inventory_json, summary_json, references_json],
    ).map_err(err)?;
    let session_id = transaction.last_insert_rowid();
    {
        let mut statement = transaction.prepare_cached(
            "INSERT OR REPLACE INTO scan_results (session_id, path, result_json) VALUES (?1, ?2, ?3)"
        ).map_err(err)?;
        for result in &scan.results {
            let json = serde_json::to_string(result).map_err(err)?;
            statement.execute(params![session_id, result.path, json]).map_err(err)?;
        }
    }
    transaction.execute(
        "DELETE FROM scan_sessions WHERE id NOT IN (SELECT id FROM scan_sessions ORDER BY id DESC LIMIT ?1)",
        [RETAINED_SCANS as i64],
    ).map_err(err)?;
    transaction.commit().map_err(err)
}

fn load_scan(conn: &Connection, id: i64, captured_at: i64, inventory_json: String, summary_json: String, references_json: Option<String>) -> Result<SavedScan, String> {
    let mut statement = conn.prepare("SELECT result_json FROM scan_results WHERE session_id = ?1 ORDER BY path").map_err(err)?;
    let json_rows = statement.query_map([id], |row| row.get::<_, String>(0)).map_err(err)?;
    let mut results = Vec::new();
    for json in json_rows {
        let json = json.map_err(err)?;
        results.push(serde_json::from_str(&json).map_err(|error| format!("Saved result is unreadable: {error}"))?);
    }
    Ok(SavedScan {
        captured_at_unix: captured_at as u64,
        inventory: serde_json::from_str(&inventory_json).map_err(|error| format!("Saved inventory is unreadable: {error}"))?,
        summary: serde_json::from_str(&summary_json).map_err(|error| format!("Saved summary is unreadable: {error}"))?,
        results,
        references: references_json.and_then(|json| serde_json::from_str(&json).ok()).unwrap_or_default(),
    })
}

type SessionRow = (i64, i64, String, String, Option<String>);

fn session_rows(conn: &Connection, limit: usize) -> Result<Vec<SessionRow>, String> {
    let mut statement = conn.prepare(
        "SELECT id, captured_at_unix, inventory_json, summary_json, references_json FROM scan_sessions ORDER BY id DESC LIMIT ?1"
    ).map_err(err)?;
    let rows = statement.query_map([limit as i64], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))
    }).map_err(err)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(err)
}

fn load_recent_from_connection(conn: &Connection, limit: usize) -> Result<Vec<SavedScan>, String> {
    session_rows(conn, limit)?.into_iter()
        .map(|(id, captured_at, inventory, summary, references)| load_scan(conn, id, captured_at, inventory, summary, references))
        .collect()
}

fn load_from_connection(conn: &Connection) -> Result<Option<SavedScan>, String> {
    Ok(load_recent_from_connection(conn, 1)?.into_iter().next())
}

pub fn save(path: &Path, inventory: Inventory, summary: ScanSummary, results: Vec<DirectoryResult>, references: ReferenceInventory) -> Result<u64, String> {
    let captured_at_unix = now_unix();
    let scan = SavedScan { captured_at_unix, inventory, summary, results, references };
    let mut conn = open_db(path)?;
    save_to_connection(&mut conn, &scan)?;
    Ok(captured_at_unix)
}

pub fn load_latest(path: &Path) -> Result<Option<SavedScan>, String> {
    let conn = open_db(path)?;
    load_from_connection(&conn)
}

pub fn load_recent(path: &Path, limit: usize) -> Result<Vec<SavedScan>, String> {
    let conn = open_db(path)?;
    load_recent_from_connection(&conn, limit)
}

/// Latest scan in full plus the inventories of older retained scans. Avoids
/// parsing every retained directory result for history comparisons.
pub fn load_history_inputs(path: &Path) -> Result<(Option<SavedScan>, Vec<ScanInventory>), String> {
    let conn = open_db(path)?;
    let mut rows = session_rows(&conn, RETAINED_SCANS)?.into_iter();
    let Some((id, captured_at, inventory, summary, references)) = rows.next() else { return Ok((None, Vec::new())); };
    let latest = load_scan(&conn, id, captured_at, inventory, summary, references)?;
    let mut inventories = vec![ScanInventory { captured_at_unix: latest.captured_at_unix, inventory: latest.inventory.clone() }];
    for (_, captured_at, inventory_json, _, _) in rows {
        let inventory = serde_json::from_str(&inventory_json).map_err(|error| format!("Saved inventory is unreadable: {error}"))?;
        inventories.push(ScanInventory { captured_at_unix: captured_at as u64, inventory });
    }
    Ok((Some(latest), inventories))
}

// ---------- Ignore rules ----------

pub fn list_ignore_rules(path: &Path) -> Result<Vec<IgnoreRule>, String> {
    let conn = open_db(path)?;
    let mut statement = conn.prepare("SELECT id, kind, value, label, created_at_unix, scan_at_unix FROM ignore_rules ORDER BY created_at_unix DESC, id DESC").map_err(err)?;
    let rows = statement.query_map([], |row| Ok(IgnoreRule {
        id: row.get(0)?, kind: row.get(1)?, value: row.get(2)?, label: row.get(3)?,
        created_at_unix: row.get::<_, i64>(4)? as u64, scan_at_unix: row.get::<_, Option<i64>>(5)?.map(|value| value as u64),
    })).map_err(err)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(err)
}

pub fn add_ignore_rule(path: &Path, kind: &str, value: &str, label: &str, scan_at_unix: Option<u64>) -> Result<IgnoreRule, String> {
    if !matches!(kind, "path" | "application" | "category" | "once") {
        return Err(format!("Unsupported ignore rule kind: {kind}"));
    }
    let value = value.trim();
    if value.is_empty() || value.len() > 2048 { return Err("Ignore rule value is empty or too long.".into()); }
    let conn = open_db(path)?;
    let created = now_unix();
    conn.execute(
        "INSERT INTO ignore_rules (kind, value, label, created_at_unix, scan_at_unix) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(kind, value) DO UPDATE SET label = excluded.label, created_at_unix = excluded.created_at_unix, scan_at_unix = excluded.scan_at_unix",
        params![kind, value, label, created as i64, scan_at_unix.map(|value| value as i64)],
    ).map_err(err)?;
    let id: i64 = conn.query_row("SELECT id FROM ignore_rules WHERE kind = ?1 AND value = ?2", params![kind, value], |row| row.get(0)).map_err(err)?;
    Ok(IgnoreRule { id, kind: kind.into(), value: value.into(), label: label.into(), created_at_unix: created, scan_at_unix })
}

pub fn remove_ignore_rule(path: &Path, id: i64) -> Result<(), String> {
    let conn = open_db(path)?;
    conn.execute("DELETE FROM ignore_rules WHERE id = ?1", [id]).map_err(err)?;
    Ok(())
}

// ---------- Quarantine ----------

fn quarantine_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<QuarantineItem> {
    Ok(QuarantineItem {
        id: row.get(0)?, original_path: row.get(1)?, quarantine_path: row.get(2)?,
        size_bytes: row.get::<_, i64>(3)? as u64, file_count: row.get::<_, i64>(4)? as u64,
        created_at_unix: row.get::<_, i64>(5)? as u64, owner: row.get(6)?, reason: row.get(7)?,
        item_kind: row.get(8)?, status: row.get(9)?, updated_at_unix: row.get::<_, i64>(10)? as u64,
    })
}

const QUARANTINE_COLUMNS: &str = "id, original_path, quarantine_path, size_bytes, file_count, created_at_unix, owner, reason, item_kind, status, updated_at_unix";

pub fn insert_quarantine(conn: &Connection, item: &QuarantineItem) -> Result<i64, String> {
    let transaction = conn.unchecked_transaction().map_err(err)?;
    transaction.execute(
        "INSERT INTO quarantine_items (original_path, quarantine_path, size_bytes, file_count, created_at_unix, owner, reason, item_kind, status, updated_at_unix)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![item.original_path, item.quarantine_path, item.size_bytes as i64, item.file_count as i64, item.created_at_unix as i64,
            item.owner, item.reason, item.item_kind, item.status, item.updated_at_unix as i64],
    ).map_err(err)?;
    let id = transaction.last_insert_rowid();
    exclude_cleaned_path(&transaction, &item.original_path)?;
    transaction.commit().map_err(err)?;
    Ok(id)
}

pub fn list_quarantine(conn: &Connection, include_history: bool) -> Result<Vec<QuarantineItem>, String> {
    let sql = if include_history {
        format!("SELECT {QUARANTINE_COLUMNS} FROM quarantine_items ORDER BY id DESC LIMIT 500")
    } else {
        format!("SELECT {QUARANTINE_COLUMNS} FROM quarantine_items WHERE status = 'quarantined' ORDER BY id DESC")
    };
    let mut statement = conn.prepare(&sql).map_err(err)?;
    let rows = statement.query_map([], quarantine_row).map_err(err)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(err)
}

pub fn get_quarantine(conn: &Connection, id: i64) -> Result<Option<QuarantineItem>, String> {
    conn.query_row(&format!("SELECT {QUARANTINE_COLUMNS} FROM quarantine_items WHERE id = ?1"), [id], quarantine_row)
        .optional().map_err(err)
}

pub fn set_quarantine_status(conn: &Connection, id: i64, status: &str) -> Result<(), String> {
    conn.execute("UPDATE quarantine_items SET status = ?1, updated_at_unix = ?2 WHERE id = ?3", params![status, now_unix() as i64, id]).map_err(err)?;
    Ok(())
}

pub fn exclude_cleaned_path(conn: &Connection, path: &str) -> Result<(), String> {
    conn.execute(
        "INSERT INTO cleanup_exclusions (path, scan_session_id) VALUES (?1, COALESCE((SELECT MAX(id) FROM scan_sessions), 0))
         ON CONFLICT(path) DO UPDATE SET scan_session_id = excluded.scan_session_id", [path],
    ).map_err(err)?;
    Ok(())
}

pub fn restore_cleaned_path(conn: &Connection, path: &str) -> Result<(), String> {
    conn.execute("DELETE FROM cleanup_exclusions WHERE path = ?1", [path]).map_err(err)?;
    Ok(())
}

pub fn cleaned_paths(conn: &Connection) -> Result<Vec<String>, String> {
    let mut statement = conn.prepare("SELECT path FROM cleanup_exclusions WHERE scan_session_id >= COALESCE((SELECT MAX(id) FROM scan_sessions), 0) ORDER BY path").map_err(err)?;
    statement.query_map([], |row| row.get(0)).map_err(err)?.collect::<Result<Vec<String>, _>>().map_err(err)
}

pub fn record_action(conn: &Connection, action: &str, path: &str, outcome: &str, detail: &str) {
    let _ = conn.execute(
        "INSERT INTO cleanup_actions (at_unix, action, path, outcome, detail) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![now_unix() as i64, action, path, outcome, detail],
    );
    let _ = conn.execute("DELETE FROM cleanup_actions WHERE id NOT IN (SELECT id FROM cleanup_actions ORDER BY id DESC LIMIT 2000)", []);
}

// ---------- Settings ----------

pub fn load_settings(path: &Path) -> Result<Settings, String> {
    let conn = open_db(path)?;
    let json: Option<String> = conn.query_row("SELECT value FROM settings WHERE key = 'settings'", [], |row| row.get(0)).optional().map_err(err)?;
    Ok(json.and_then(|json| serde_json::from_str(&json).ok()).unwrap_or_default())
}

pub fn save_settings(path: &Path, settings: &Settings) -> Result<(), String> {
    if cleaner_core::ScanMode::parse(&settings.default_scan_mode).is_none() {
        return Err("Unknown scan mode.".into());
    }
    if settings.quarantine_retention_days > 3650 {
        return Err("Retention must be at most 3650 days.".into());
    }
    let conn = open_db(path)?;
    let json = serde_json::to_string(settings).map_err(err)?;
    conn.execute("INSERT INTO settings (key, value) VALUES ('settings', ?1) ON CONFLICT(key) DO UPDATE SET value = excluded.value", [json]).map_err(err)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(i: u64) -> SavedScan {
        SavedScan {
            captured_at_unix: i,
            inventory: Inventory { applications: vec![], warnings: vec![] },
            summary: ScanSummary { directories: 1, bytes: i, ..Default::default() },
            results: vec![DirectoryResult {
                path: format!(r"C:\Test\App{i}"), root: "Local".into(), size_bytes: i, file_count: 1,
                ownership: "unknown".into(), orphan_status: "unknown".into(), ..Default::default()
            }],
            references: ReferenceInventory::default(),
        }
    }

    #[test]
    fn complete_snapshot_round_trips_and_old_snapshots_are_pruned() {
        let mut conn = Connection::open_in_memory().unwrap();
        initialize_db(&conn).unwrap();
        for i in 0..12 { save_to_connection(&mut conn, &scan(i)).unwrap(); }
        let loaded = load_from_connection(&conn).unwrap().unwrap();
        assert_eq!(loaded.captured_at_unix, 11);
        assert_eq!(loaded.results.len(), 1);
        assert_eq!(loaded.results[0].path, r"C:\Test\App11");
        let recent = load_recent_from_connection(&conn, 3).unwrap();
        assert_eq!(recent.iter().map(|scan| scan.captured_at_unix).collect::<Vec<_>>(), [11, 10, 9]);
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM scan_sessions", [], |row| row.get(0)).unwrap();
        assert_eq!(count, 10);
        let result_count: i64 = conn.query_row("SELECT COUNT(*) FROM scan_results", [], |row| row.get(0)).unwrap();
        assert_eq!(result_count, 10);
    }

    #[test]
    fn version_one_database_is_upgraded_in_place() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE scan_sessions (id INTEGER PRIMARY KEY, captured_at_unix INTEGER NOT NULL, inventory_json TEXT NOT NULL, summary_json TEXT NOT NULL);
             CREATE TABLE scan_results (session_id INTEGER NOT NULL, path TEXT NOT NULL, result_json TEXT NOT NULL, PRIMARY KEY (session_id, path));
             INSERT INTO scan_sessions VALUES (1, 5, '{\"applications\":[],\"warnings\":[]}', '{\"directories\":0,\"bytes\":0,\"skippedEntries\":0,\"canceled\":false,\"scannedRoots\":[],\"warnings\":[]}');
             PRAGMA user_version = 1;"
        ).unwrap();
        initialize_db(&conn).unwrap();
        let loaded = load_from_connection(&conn).unwrap().unwrap();
        assert_eq!(loaded.captured_at_unix, 5);
        assert!(loaded.references.references.is_empty());
        let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0)).unwrap();
        assert_eq!(version, 3);
    }

    #[test]
    fn ignore_rules_and_settings_persist() {
        let directory = std::env::temp_dir().join(format!("orphan-cleaner-storage-{}-{}", std::process::id(), now_unix()));
        let database = directory.join("scans.sqlite3");
        let rule = add_ignore_rule(&database, "path", r"C:\X", "X", None).unwrap();
        add_ignore_rule(&database, "path", r"C:\X", "X again", None).unwrap();
        let rules = list_ignore_rules(&database).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].label, "X again");
        remove_ignore_rule(&database, rule.id).unwrap();
        assert!(list_ignore_rules(&database).unwrap().is_empty());
        assert!(add_ignore_rule(&database, "bogus", "v", "l", None).is_err());
        let mut settings = load_settings(&database).unwrap();
        assert_eq!(settings, Settings::default());
        settings.quarantine_retention_days = 7;
        save_settings(&database, &settings).unwrap();
        assert_eq!(load_settings(&database).unwrap().quarantine_retention_days, 7);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn cleanup_exclusions_survive_purge_until_a_new_snapshot_and_restore_clears_them() {
        let mut conn = Connection::open_in_memory().unwrap();
        initialize_db(&conn).unwrap();
        save_to_connection(&mut conn, &scan(1)).unwrap();
        exclude_cleaned_path(&conn, r"C:\Test\App1").unwrap();
        assert_eq!(cleaned_paths(&conn).unwrap(), vec![r"C:\Test\App1"]);
        // The next snapshot has the same timestamp: session identity still advances.
        save_to_connection(&mut conn, &scan(1)).unwrap();
        assert!(cleaned_paths(&conn).unwrap().is_empty());
        exclude_cleaned_path(&conn, r"C:\Test\App1").unwrap();
        restore_cleaned_path(&conn, r"c:\test\app1").unwrap();
        assert!(cleaned_paths(&conn).unwrap().is_empty());
    }
}
