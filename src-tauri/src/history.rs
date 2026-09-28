use cleaner_core::{Application, DirectoryResult, same_application};
use serde::Serialize;

use crate::storage::SavedScan;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoricalDirectory {
    pub path: String,
    pub root: String,
    pub size_bytes: u64,
    pub orphan_status: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoricalApplication {
    pub application: Application,
    pub last_seen_at_unix: Option<u64>,
    pub first_missing_at_unix: Option<u64>,
    pub newly_missing: bool,
    pub remaining_bytes: u64,
    pub confidence: String,
    pub directories: Vec<HistoricalDirectory>,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryReport {
    pub complete_scans: usize,
    pub current_scan_at_unix: Option<u64>,
    pub applications: Vec<HistoricalApplication>,
}

fn has_historical_owner(result: &DirectoryResult) -> bool {
    matches!(result.orphan_status.as_str(), "probable_orphan" | "possibly_orphaned")
        && result.evidence.iter().any(|item| item.kind == "historical_owner")
        && result.owner.is_some()
}

fn inventory_contains(scan: &SavedScan, application: &Application) -> bool {
    scan.inventory.applications.iter().any(|candidate| same_application(candidate, application))
}

pub fn build(scans: &[SavedScan]) -> HistoryReport {
    let Some(current) = scans.first() else { return HistoryReport::default(); };
    let mut grouped: Vec<(Application, Vec<&DirectoryResult>)> = Vec::new();
    for result in current.results.iter().filter(|result| has_historical_owner(result)) {
        let owner = result.owner.as_ref().expect("historical owner checked above");
        if let Some((_, directories)) = grouped.iter_mut()
            .find(|(application, _)| same_application(application, owner)) {
            directories.push(result);
        } else {
            grouped.push((owner.clone(), vec![result]));
        }
    }

    let mut applications = grouped.into_iter().map(|(application, results)| {
        let last_seen_index = scans.iter().enumerate().skip(1)
            .find_map(|(index, scan)| inventory_contains(scan, &application).then_some(index));
        let last_seen_at_unix = last_seen_index.map(|index| scans[index].captured_at_unix);
        let first_missing_at_unix = last_seen_index
            .and_then(|index| index.checked_sub(1))
            .map(|index| scans[index].captured_at_unix);
        let newly_missing = last_seen_index == Some(1);
        let remaining_bytes = results.iter()
            .fold(0u64, |total, result| total.saturating_add(result.size_bytes));
        let confidence = if results.iter().any(|result| result.orphan_status == "probable_orphan") {
            "probable"
        } else {
            "possible"
        };
        let mut directories = results.into_iter().map(|result| HistoricalDirectory {
            path: result.path.clone(),
            root: result.root.clone(),
            size_bytes: result.size_bytes,
            orphan_status: result.orphan_status.clone(),
        }).collect::<Vec<_>>();
        directories.sort_by(|left, right| right.size_bytes.cmp(&left.size_bytes).then_with(|| left.path.cmp(&right.path)));
        HistoricalApplication {
            application,
            last_seen_at_unix,
            first_missing_at_unix,
            newly_missing,
            remaining_bytes,
            confidence: confidence.into(),
            directories,
        }
    }).collect::<Vec<_>>();
    applications.sort_by(|left, right| right.newly_missing.cmp(&left.newly_missing)
        .then_with(|| right.remaining_bytes.cmp(&left.remaining_bytes))
        .then_with(|| left.application.name.cmp(&right.application.name)));
    HistoryReport {
        complete_scans: scans.len(),
        current_scan_at_unix: Some(current.captured_at_unix),
        applications,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cleaner_core::{Evidence, Inventory, ScanSummary};

    fn app(id: &str) -> Application {
        Application { id: id.into(), name: "Example App".into(), publisher: Some("Example Co".into()),
            version: None, install_location: None, display_icon_executable: None,
            package_family_name: None, sources: vec!["test".into()] }
    }

    fn scan(time: u64, installed: Vec<Application>, result_owner: Option<Application>) -> SavedScan {
        let results = result_owner.into_iter().map(|owner| DirectoryResult {
            path: r"C:\Users\Test\AppData\Roaming\Example App".into(), root: "Roaming".into(),
            size_bytes: 4096, file_count: 2, directory_count: 1, newest_modified_unix: None,
            skipped_entries: 0, owner: Some(owner), owner_hint: None,
            ownership: "historical_confirmed".into(), orphan_status: "probable_orphan".into(),
            evidence: vec![Evidence { kind: "historical_owner".into(), description: "Previously linked".into(), strength: "strong".into() }],
        }).collect();
        SavedScan { captured_at_unix: time, inventory: Inventory { applications: installed, warnings: vec![] },
            summary: ScanSummary::default(), results }
    }

    #[test]
    fn groups_recently_missing_application_and_totals_remaining_data() {
        let application = app("old-key");
        let report = build(&[
            scan(200, vec![], Some(application.clone())),
            scan(100, vec![application], None),
        ]);
        assert_eq!(report.complete_scans, 2);
        assert_eq!(report.applications.len(), 1);
        let missing = &report.applications[0];
        assert!(missing.newly_missing);
        assert_eq!(missing.last_seen_at_unix, Some(100));
        assert_eq!(missing.first_missing_at_unix, Some(200));
        assert_eq!(missing.remaining_bytes, 4096);
        assert_eq!(missing.directories.len(), 1);
    }

    #[test]
    fn retained_leftover_is_not_reported_as_new_each_scan() {
        let application = app("old-key");
        let report = build(&[
            scan(300, vec![], Some(application.clone())),
            scan(200, vec![], Some(application.clone())),
            scan(100, vec![application], None),
        ]);
        let missing = &report.applications[0];
        assert!(!missing.newly_missing);
        assert_eq!(missing.last_seen_at_unix, Some(100));
        assert_eq!(missing.first_missing_at_unix, Some(200));
    }

    #[test]
    fn curated_possible_leftovers_without_history_are_excluded() {
        let mut current = scan(200, vec![], None);
        current.results.push(DirectoryResult {
            path: r"C:\Users\Test\AppData\Roaming\Image-Line".into(), root: "Roaming".into(),
            size_bytes: 10, file_count: 1, directory_count: 0, newest_modified_unix: None,
            skipped_entries: 0, owner: None, owner_hint: Some("Image-Line".into()),
            ownership: "known_location".into(), orphan_status: "possibly_orphaned".into(), evidence: vec![],
        });
        assert!(build(&[current]).applications.is_empty());
    }
}
