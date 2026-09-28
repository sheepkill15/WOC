//! Cleanup candidate grouping (spec §23–25, §28, §44).
//!
//! Groups directory results by what they represent to the user: leftovers of
//! an uninstalled application, an old product version, a possible leftover,
//! an unregistered application, regenerable caches of installed software, or
//! large unknown data. Ignore rules are applied here so every surface agrees.

use cleaner_core::references::path_is_within;
use cleaner_core::{DirectoryResult, Reason, normalize_name};
use cleaner_core::content::{LIKELY_SAFE, SAFE, safety_rank};
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};

use crate::storage::{IgnoreRule, SavedScan};

const CACHE_GROUP_MIN_BYTES: u64 = 100 * 1024 * 1024;
const UNKNOWN_GROUP_MIN_BYTES: u64 = 500 * 1024 * 1024;
const MAX_CACHE_GROUPS: usize = 15;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentSelection {
    pub name: String,
    pub path: String,
    pub kind: String,
    pub safety: String,
    pub size_bytes: u64,
    pub selectable: bool,
    pub default_selected: bool,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidateItem {
    pub path: String,
    pub root: String,
    pub size_bytes: u64,
    pub newest_modified_unix: Option<u64>,
    pub orphan_confidence: String,
    pub deletion_safety: String,
    pub recommended_action: String,
    /// The whole directory may be selected (the user still confirms).
    pub selectable_whole: bool,
    pub default_selected: bool,
    pub content: Vec<ContentSelection>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidateGroup {
    pub id: String,
    /// uninstalled | old_version | possible_leftover | unregistered | regenerable_cache | tool_cache | unknown_large
    pub kind: String,
    pub title: String,
    pub summary: String,
    pub owner_name: Option<String>,
    pub owner_key: Option<String>,
    pub confidence: String,
    pub safety: String,
    pub recommended_action: String,
    pub total_bytes: u64,
    pub reclaimable_bytes: u64,
    pub retained_bytes: u64,
    /// Priority bucket for display: high | review | info
    pub priority: String,
    pub items: Vec<CandidateItem>,
    pub reasons: Vec<Reason>,
    pub ignored_by: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidateReport {
    pub scan_at_unix: Option<u64>,
    pub groups: Vec<CandidateGroup>,
    pub ignored_groups: Vec<CandidateGroup>,
    pub recommended_bytes: u64,
    pub review_bytes: u64,
    pub ignored_paths: usize,
    pub quarantined_paths: usize,
}

fn child_path(parent: &str, name: &str) -> String {
    format!("{}\\{}", parent.trim_end_matches('\\'), name)
}

fn owner_name(result: &DirectoryResult) -> Option<String> {
    result.owner.as_ref().map(|owner| owner.name.clone()).or_else(|| result.owner_hint.clone())
}

fn has(result: &DirectoryResult, kind: &str) -> bool {
    result.evidence.iter().any(|item| item.kind == kind)
}

struct Rules<'a> {
    quarantined: &'a [String],
    paths: Vec<&'a IgnoreRule>,
    applications: Vec<&'a IgnoreRule>,
    categories: HashSet<String>,
}

impl<'a> Rules<'a> {
    fn new(rules: &'a [IgnoreRule], scan_at: u64, quarantined: &'a [String]) -> Self {
        Self {
            quarantined,
            paths: rules.iter().filter(|rule| rule.kind == "path" || (rule.kind == "once" && rule.scan_at_unix == Some(scan_at))).collect(),
            applications: rules.iter().filter(|rule| rule.kind == "application").collect(),
            categories: rules.iter().filter(|rule| rule.kind == "category").map(|rule| rule.value.clone()).collect(),
        }
    }

    fn path_rule(&self, path: &str) -> Option<&'a IgnoreRule> {
        self.paths.iter().copied().find(|rule| path_is_within(path, &rule.value))
    }

    fn application_rule(&self, key: &str) -> Option<&'a IgnoreRule> {
        self.applications.iter().copied().find(|rule| normalize_name(&rule.value) == key)
    }
}

fn selections(result: &DirectoryResult, rules: &Rules<'_>, select_safe: bool, only_safe_selectable: bool) -> Vec<ContentSelection> {
    result.content.items.iter()
        .filter(|item| !rules.categories.contains(&item.kind))
        .filter(|item| !rules.quarantined.iter().any(|path| path_is_within(&child_path(&result.path, &item.name), path)))
        .map(|item| {
        let safe = matches!(item.safety.as_str(), SAFE | LIKELY_SAFE);
        let path = child_path(&result.path, &item.name);
        let ignored = rules.path_rule(&path).is_some();
        let selectable = item.is_directory && !ignored && (!only_safe_selectable || safe);
        ContentSelection {
            name: item.name.clone(),
            path,
            kind: item.kind.clone(),
            safety: item.safety.clone(),
            size_bytes: item.size_bytes,
            selectable,
            default_selected: selectable && select_safe && safe,
            reason: item.reason.clone(),
        }
    }).collect()
}

fn item_for(result: &DirectoryResult, rules: &Rules<'_>, whole_allowed: bool, only_safe_selectable: bool) -> CandidateItem {
    let assessment = &result.assessment;
    let moved: u64 = result.content.items.iter()
        .filter(|item| rules.quarantined.iter().any(|path| path_is_within(&child_path(&result.path, &item.name), path)))
        .map(|item| item.size_bytes).sum();
    let has_kept_category = result.content.items.iter().any(|item| rules.categories.contains(&item.kind));
    // Moving the whole folder would also move anything the user chose to keep inside it.
    let strictly_inside = |inner: &str| path_is_within(inner, &result.path) && !inner.trim_end_matches('\\').eq_ignore_ascii_case(result.path.trim_end_matches('\\'));
    let has_kept_inside = rules.paths.iter().any(|rule| strictly_inside(&rule.value)) || rules.quarantined.iter().any(|path| strictly_inside(path));
    let selectable_whole = whole_allowed && !has_kept_category && !has_kept_inside;
    let default_whole = selectable_whole && assessment.recommended_action == "clean";
    let select_safe = !default_whole && assessment.recommended_action == "clean_selected";
    CandidateItem {
        path: result.path.clone(),
        root: result.root.clone(),
        size_bytes: result.size_bytes.saturating_sub(moved),
        newest_modified_unix: result.newest_modified_unix,
        orphan_confidence: assessment.orphan_confidence.clone(),
        deletion_safety: assessment.deletion_safety.clone(),
        recommended_action: assessment.recommended_action.clone(),
        selectable_whole,
        default_selected: default_whole,
        content: selections(result, rules, select_safe, only_safe_selectable),
    }
}

fn confidence_rank(confidence: &str) -> u8 {
    match confidence { "confirmed" => 4, "very_likely" => 3, "likely" => 2, "uncertain" => 1, _ => 0 }
}

fn action_rank(action: &str) -> u8 {
    match action { "clean" => 3, "clean_selected" => 2, "review" => 1, _ => 0 }
}

struct Draft {
    kind: &'static str,
    owner_name: Option<String>,
    owner_key: Option<String>,
    results: Vec<(DirectoryResult, CandidateItem)>,
    newly_missing: bool,
}

fn finish(draft: Draft) -> CandidateGroup {
    let mut items = draft.results;
    items.sort_by(|left, right| right.0.size_bytes.cmp(&left.0.size_bytes));
    let total_bytes: u64 = items.iter().map(|(_, item)| item.size_bytes).sum();
    let reclaimable_bytes: u64 = items.iter().map(|(result, item)| {
        if item.default_selected { item.size_bytes.min(result.size_bytes) } else { item.content.iter().filter(|content| content.default_selected).map(|content| content.size_bytes).sum() }
    }).sum();
    // Without a default selection, show what could be selected at low risk.
    let reclaimable_potential: u64 = items.iter().map(|(_, item)| item.content.iter()
        .filter(|content| content.selectable && matches!(content.safety.as_str(), SAFE | LIKELY_SAFE))
        .map(|content| content.size_bytes).sum::<u64>()).sum();
    let retained_bytes: u64 = items.iter().map(|(result, _)| result.assessment.retained_bytes).sum();
    let confidence = items.iter().map(|(result, _)| result.assessment.orphan_confidence.clone())
        .max_by_key(|confidence| confidence_rank(confidence)).unwrap_or_else(|| "unknown".into());
    let safety = items.iter().map(|(result, _)| result.assessment.deletion_safety.clone())
        .max_by_key(|safety| safety_rank(safety)).unwrap_or_else(|| "unknown".into());
    let mut recommended_action = items.iter().map(|(result, _)| result.assessment.recommended_action.clone())
        .max_by_key(|action| action_rank(action)).unwrap_or_else(|| "review".into());
    let name = draft.owner_name.clone().unwrap_or_else(|| "Unknown application".into());
    let count = items.len();
    let folders = if count == 1 { "1 folder".to_string() } else { format!("{count} folders") };
    let (title, summary) = match draft.kind {
        "uninstalled" => (format!("{name} leftovers"), format!("{name} is no longer installed{}. {folders} previously linked to it remain.", if draft.newly_missing { " (removed since the previous scan)" } else { "" })),
        "old_version" => (format!("{name} — older version data"), format!("A newer version is installed. {folders} belonged to the older version.")),
        "possible_leftover" => (format!("{name} data"), format!("{name} does not appear to be installed. This is a weaker, first-run inference; launcher-managed or portable installs may still use it.")),
        "unregistered" => (format!("{name} (unregistered)"), "Contains an application without an uninstall registration — possibly a portable app. Keep it unless you no longer use it.".into()),
        "regenerable_cache" => (format!("{name} caches"), format!("{name} is installed. Only its regenerable caches are selectable; the app recreates them as needed.")),
        "tool_cache" => (format!("{name} cache"), "Developer tool cache. Tools download or rebuild this data again when needed.".into()),
        _ => ("Unknown application data".into(), format!("{folders} with no identified owner. Shown for review only; unknown does not mean unnecessary.")),
    };
    if matches!(draft.kind, "regenerable_cache" | "tool_cache") {
        recommended_action = "review".into();
    }
    let priority = match (draft.kind, recommended_action.as_str()) {
        ("unknown_large", _) => "info",
        (_, "clean" | "clean_selected") => "high",
        _ => "review",
    };
    let mut reasons: Vec<Reason> = Vec::new();
    for (result, _) in &items {
        for reason in &result.assessment.reasons {
            if reasons.len() < 8 && !reasons.iter().any(|existing| existing.text == reason.text) {
                reasons.push(reason.clone());
            }
        }
    }
    let id = format!("{}:{}", draft.kind, draft.owner_key.clone().unwrap_or_else(|| items.first().map(|(result, _)| result.path.to_lowercase()).unwrap_or_default()));
    CandidateGroup {
        id,
        kind: draft.kind.into(),
        title,
        summary,
        owner_name: draft.owner_name,
        owner_key: draft.owner_key,
        confidence,
        safety,
        recommended_action,
        total_bytes,
        reclaimable_bytes: if reclaimable_bytes > 0 { reclaimable_bytes } else { reclaimable_potential.min(total_bytes) },
        retained_bytes,
        priority: priority.into(),
        items: items.into_iter().map(|(_, item)| item).collect(),
        reasons,
        ignored_by: None,
    }
}

/// Builds the grouped cleanup report from the latest saved scan.
pub fn build(scan: &SavedScan, rules: &[IgnoreRule], quarantined: &[String], newly_missing_keys: &HashSet<String>) -> CandidateReport {
    let rules = Rules::new(rules, scan.captured_at_unix, quarantined);
    let mut drafts: BTreeMap<String, Draft> = BTreeMap::new();
    let mut ignored_paths = 0usize;
    let mut quarantined_paths = 0usize;
    let mut cache_drafts: Vec<Draft> = Vec::new();
    let mut unknown: Vec<(DirectoryResult, CandidateItem)> = Vec::new();

    for result in &scan.results {
        if quarantined.iter().any(|path| path_is_within(&result.path, path)) { quarantined_paths += 1; continue; }
        if rules.path_rule(&result.path).is_some() { ignored_paths += 1; continue; }
        if matches!(result.location_class.as_deref(), Some("system" | "shared_runtime")) { continue; }
        // Nested results are only candidates when their parent is not already one.
        let name = owner_name(result);
        let key = name.as_deref().map(normalize_name).filter(|key| !key.is_empty());
        let historical = has(result, "historical_owner");
        let kind: Option<&'static str> = match result.orphan_status.as_str() {
            "probable_orphan" => Some("uninstalled"),
            "possibly_orphaned" if result.ownership == "historical_version" => Some("old_version"),
            "possibly_orphaned" if historical => Some("uninstalled"),
            "possibly_orphaned" => Some("possible_leftover"),
            "unregistered_application" => Some("unregistered"),
            _ => None,
        };
        if let Some(kind) = kind {
            let whole_allowed = true;
            let item = item_for(result, &rules, whole_allowed, false);
            let group_key = format!("{kind}:{}", key.clone().unwrap_or_else(|| result.path.to_lowercase()));
            let newly = key.as_ref().is_some_and(|key| newly_missing_keys.contains(key));
            drafts.entry(group_key).or_insert_with(|| Draft { kind, owner_name: name.clone(), owner_key: key.clone(), results: Vec::new(), newly_missing: newly })
                .results.push((result.clone(), item));
            continue;
        }
        let cache_bytes: u64 = result.content.items.iter()
            .filter(|item| item.is_directory && matches!(item.safety.as_str(), SAFE | LIKELY_SAFE) && !rules.categories.contains(&item.kind))
            .map(|item| item.size_bytes).sum();
        let tool_cache = result.location_class.as_deref() == Some("tool_cache");
        if cache_bytes >= CACHE_GROUP_MIN_BYTES && result.orphan_status != "unknown" {
            let item = item_for(result, &rules, false, true);
            cache_drafts.push(Draft {
                kind: if tool_cache { "tool_cache" } else { "regenerable_cache" },
                owner_name: name.clone().or_else(|| result.path.rsplit('\\').next().map(str::to_owned)),
                owner_key: key.clone().map(|key| format!("{key}:{}", result.path.to_lowercase())),
                results: vec![(result.clone(), item)],
                newly_missing: false,
            });
            continue;
        }
        if result.orphan_status == "unknown" && result.parent_path.is_none() && result.size_bytes >= UNKNOWN_GROUP_MIN_BYTES {
            let mut item = item_for(result, &rules, false, true);
            item.content.iter_mut().for_each(|content| { content.selectable = false; content.default_selected = false; });
            unknown.push((result.clone(), item));
        }
    }

    let mut groups: Vec<CandidateGroup> = Vec::new();
    let mut ignored_groups = Vec::new();
    for (_, draft) in drafts {
        let rule = draft.owner_key.as_deref().and_then(|key| rules.application_rule(key)).map(|rule| rule.label.clone());
        let mut group = finish(draft);
        if let Some(label) = rule { group.ignored_by = Some(label); ignored_groups.push(group); } else { groups.push(group); }
    }
    cache_drafts.sort_by(|left, right| right.results[0].0.assessment.reclaimable_bytes.cmp(&left.results[0].0.assessment.reclaimable_bytes));
    for draft in cache_drafts.into_iter().take(MAX_CACHE_GROUPS) {
        let rule = draft.owner_name.as_deref().map(normalize_name).and_then(|key| rules.application_rule(&key)).map(|rule| rule.label.clone());
        let mut group = finish(draft);
        if let Some(label) = rule { group.ignored_by = Some(label); ignored_groups.push(group); } else { groups.push(group); }
    }
    if !unknown.is_empty() {
        groups.push(finish(Draft { kind: "unknown_large", owner_name: None, owner_key: Some("unknown".into()), results: unknown, newly_missing: false }));
    }
    let priority_rank = |priority: &str| match priority { "high" => 0, "review" => 1, _ => 2 };
    groups.sort_by(|left, right| priority_rank(&left.priority).cmp(&priority_rank(&right.priority))
        .then_with(|| right.reclaimable_bytes.cmp(&left.reclaimable_bytes))
        .then_with(|| right.total_bytes.cmp(&left.total_bytes)));
    let recommended_bytes = groups.iter().filter(|group| group.priority == "high").map(|group| group.reclaimable_bytes).sum();
    let review_bytes = groups.iter().filter(|group| group.priority == "review").map(|group| group.total_bytes).sum();
    CandidateReport {
        scan_at_unix: Some(scan.captured_at_unix),
        groups,
        ignored_groups,
        recommended_bytes,
        review_bytes,
        ignored_paths,
        quarantined_paths,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cleaner_core::{Application, Assessment, ContentItem, ContentProfile, Evidence, Inventory, ScanSummary};

    fn result(path: &str, status: &str, owner: Option<&str>, size: u64) -> DirectoryResult {
        let mut result = DirectoryResult {
            path: path.into(), root: "Roaming".into(), size_bytes: size, orphan_status: status.into(),
            ownership: if status == "probable_orphan" { "historical_confirmed".into() } else { "likely".into() },
            owner: owner.map(|name| Application { id: name.into(), name: name.into(), ..Default::default() }),
            evidence: if status == "probable_orphan" { vec![Evidence { kind: "historical_owner".into(), ..Default::default() }] } else { vec![] },
            content: ContentProfile { items: vec![
                ContentItem { name: "Cache".into(), is_directory: true, kind: "cache".into(), safety: "safe".into(), size_bytes: size / 2, ..Default::default() },
                ContentItem { name: "Saves".into(), is_directory: true, kind: "save_game".into(), safety: "preserve".into(), size_bytes: size / 2, ..Default::default() },
            ], ..Default::default() },
            ..Default::default()
        };
        result.assessment = cleaner_core::assess(&result, 0);
        result
    }

    fn scan(results: Vec<DirectoryResult>) -> SavedScan {
        SavedScan { captured_at_unix: 10, inventory: Inventory::default(), summary: ScanSummary::default(), results, references: Default::default() }
    }

    #[test]
    fn uninstalled_app_folders_group_and_preselect_only_safe_content() {
        let report = build(&scan(vec![
            result(r"C:\R\OldGame", "probable_orphan", Some("OldGame"), 1000),
            result(r"C:\L\OldGame", "probable_orphan", Some("OldGame"), 2000),
            result(r"C:\R\Active", "not_orphaned", Some("Active"), 10),
        ]), &[], &[], &HashSet::new());
        assert_eq!(report.groups.len(), 1);
        let group = &report.groups[0];
        assert_eq!(group.kind, "uninstalled");
        assert_eq!(group.items.len(), 2);
        assert_eq!(group.total_bytes, 3000);
        assert_eq!(group.reclaimable_bytes, 1500);
        assert!(group.items.iter().all(|item| !item.default_selected));
        assert!(group.items[0].content.iter().any(|content| content.name == "Cache" && content.default_selected));
        assert!(group.items[0].content.iter().any(|content| content.name == "Saves" && !content.default_selected));
    }

    #[test]
    fn ignore_rules_hide_paths_apps_and_categories() {
        let base = vec![result(r"C:\R\OldGame", "probable_orphan", Some("OldGame"), 1000)];
        let rule = |kind: &str, value: &str| IgnoreRule { id: 1, kind: kind.into(), value: value.into(), label: value.into(), created_at_unix: 0, scan_at_unix: Some(10) };
        assert!(build(&scan(base.clone()), &[rule("path", r"c:\r\oldgame")], &[], &HashSet::new()).groups.is_empty());
        let report = build(&scan(base.clone()), &[rule("application", "OldGame")], &[], &HashSet::new());
        assert!(report.groups.is_empty());
        assert_eq!(report.ignored_groups.len(), 1);
        let report = build(&scan(base.clone()), &[rule("category", "save_game")], &[], &HashSet::new());
        let item = &report.groups[0].items[0];
        assert!(!item.selectable_whole, "a folder containing kept data cannot be removed whole");
        assert!(item.content.iter().all(|content| content.kind != "save_game"));
        let report = build(&scan(base.clone()), &[rule("once", r"C:\R\OldGame")], &[], &HashSet::new());
        assert!(report.groups.is_empty());
        let report = build(&scan(base), &[rule("path", r"C:\R\OldGame\Saves")], &[], &HashSet::new());
        let item = &report.groups[0].items[0];
        assert!(!item.selectable_whole && !item.default_selected, "an ignored child blocks whole-folder selection");
        assert!(item.content.iter().find(|content| content.name == "Saves").is_some_and(|content| !content.selectable));
    }

    #[test]
    fn active_app_caches_are_review_only_with_safe_children() {
        let mut active = result(r"C:\R\Active", "not_orphaned", Some("Active"), 400 * 1024 * 1024);
        active.assessment = Assessment { recommended_action: "keep".into(), ..cleaner_core::assess(&active, 0) };
        let report = build(&scan(vec![active]), &[], &[], &HashSet::new());
        let group = &report.groups[0];
        assert_eq!(group.kind, "regenerable_cache");
        assert_eq!(group.recommended_action, "review");
        assert!(!group.items[0].selectable_whole);
        assert!(group.items[0].content.iter().all(|content| !content.default_selected));
        assert!(group.items[0].content.iter().find(|content| content.name == "Saves").is_some_and(|content| !content.selectable));
    }

    #[test]
    fn quarantined_paths_are_excluded() {
        let report = build(&scan(vec![result(r"C:\R\OldGame", "probable_orphan", Some("OldGame"), 1000)]), &[], &[r"C:\R\OldGame".into()], &HashSet::new());
        assert!(report.groups.is_empty());
        assert_eq!(report.quarantined_paths, 1);
        let report = build(&scan(vec![result(r"C:\R\OldGame", "probable_orphan", Some("OldGame"), 1000)]), &[], &[r"C:\R\OldGame\Cache".into()], &HashSet::new());
        let group = &report.groups[0];
        assert_eq!(group.total_bytes, 500, "quarantined content no longer counts");
        assert!(group.items[0].content.iter().all(|content| content.name != "Cache"));
    }
}
