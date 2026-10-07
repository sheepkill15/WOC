use cleaner_core::{Application, DirectoryResult, Evidence, Inventory};
use serde::{Deserialize, Serialize};
use std::path::Path;
use rusqlite::params;
use crate::storage;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderLink { pub path: String, pub application: Application }

pub fn list(database: &Path) -> Result<Vec<FolderLink>, String> {
    let conn = storage::open_db(database)?;
    list_from(&conn)
}

pub fn list_from(conn: &rusqlite::Connection) -> Result<Vec<FolderLink>, String> {
    let mut statement = conn.prepare("SELECT path, application_json FROM folder_links ORDER BY path").map_err(|e| e.to_string())?;
    let rows = statement.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))).map_err(|e| e.to_string())?;
    rows.map(|row| {
        let (path, json) = row.map_err(|e| e.to_string())?;
        Ok(FolderLink { path, application: serde_json::from_str(&json).map_err(|e| e.to_string())? })
    }).collect()
}

pub fn save(database: &Path, path: &str, application: Option<&Application>) -> Result<(), String> {
    let conn = storage::open_db(database)?;
    if let Some(application) = application {
        conn.execute("INSERT OR REPLACE INTO folder_links (path, application_json) VALUES (?1, ?2)", params![path, serde_json::to_string(application).map_err(|e| e.to_string())?]).map_err(|e| e.to_string())?;
    } else {
        conn.execute("DELETE FROM folder_links WHERE path = ?1", [path]).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Exact paths only. A link changes ownership evidence, never content safety.
pub fn apply(result: &mut DirectoryResult, links: &[FolderLink], inventory: &Inventory) {
    let Some(link) = links.iter().find(|link| link.path.eq_ignore_ascii_case(&result.path)) else { return; };
    let installed = inventory.applications.iter().find(|app| cleaner_core::same_application(app, &link.application));
    result.owner = Some(installed.unwrap_or(&link.application).clone());
    result.owner_hint = Some(link.application.name.clone());
    result.ownership = "manual".into();
    result.orphan_status = if installed.is_some() { "not_orphaned" } else if inventory.warnings.is_empty() { "probable_orphan" } else { "unknown" }.into();
    result.evidence.retain(|e| !matches!(e.kind.as_str(), "manual_owner" | "historical_owner" | "missing_installed_app"));
    result.evidence.push(Evidence { kind: "manual_owner".into(), description: format!("You connected this exact folder to {}.", link.application.name), strength: "strong".into() });
    if installed.is_none() && inventory.warnings.is_empty() {
        result.evidence.push(Evidence { kind: "historical_owner".into(), description: format!("The application you connected, {}, is no longer installed.", link.application.name), strength: "strong".into() });
    }
    cleaner_core::finalize(result);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_links_survive_removal_without_changing_content_protection() {
        let app = Application { id: "app".into(), name: "Example".into(), ..Default::default() };
        let links = [FolderLink { path: r"C:\Data\Example".into(), application: app.clone() }];
        let mut result = DirectoryResult { path: r"c:\data\example".into(), location_class: Some("user_data".into()), ..Default::default() };
        apply(&mut result, &links, &Inventory { applications: vec![app], ..Default::default() });
        assert_eq!(result.orphan_status, "not_orphaned");
        apply(&mut result, &links, &Inventory::default());
        assert_eq!(result.orphan_status, "probable_orphan");
        assert_eq!(result.location_class.as_deref(), Some("user_data"));
        let mut child = DirectoryResult { path: r"C:\Data\Example\Other".into(), ..Default::default() };
        apply(&mut child, &links, &Inventory::default());
        assert!(child.owner.is_none());
    }
    #[test]
    fn links_persist_and_can_be_removed() {
        let dir = std::env::temp_dir().join(format!("cleaner-links-{}", std::process::id()));
        let db = dir.join("test.sqlite3");
        let app = Application { id: "app".into(), ..Default::default() };
        storage::save(&db, Inventory { applications: vec![app.clone()], ..Default::default() }, Default::default(), vec![DirectoryResult { path: r"C:\Example".into(), ..Default::default() }], Default::default()).unwrap();
        save(&db, r"C:\Example", Some(&app)).unwrap();
        assert_eq!(list(&db).unwrap().len(), 1);
        assert_eq!(storage::load_latest(&db).unwrap().unwrap().results[0].owner.as_ref().unwrap().id, "app");
        save(&db, r"c:\example", None).unwrap();
        assert!(list(&db).unwrap().is_empty());
        assert!(storage::load_latest(&db).unwrap().unwrap().results[0].owner.is_none());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
