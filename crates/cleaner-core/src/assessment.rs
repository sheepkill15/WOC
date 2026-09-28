//! Separates ownership, orphan confidence, content safety and recommendation
//! (spec §15, §17, §19, §34). Every conclusion carries plain-language reasons.

use serde::{Deserialize, Serialize};

use crate::content::{self, LIKELY_SAFE, PRESERVE, REVIEW, SAFE, UNKNOWN};
use crate::DirectoryResult;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Assessment {
    /// confirmed | very_likely | likely | uncertain | not_orphaned | unknown
    pub orphan_confidence: String,
    /// safe | likely_safe | review | preserve | unknown
    pub deletion_safety: String,
    /// exclusive | shared | system | unknown
    pub ownership_class: String,
    /// clean | clean_selected | review | keep
    pub recommended_action: String,
    /// Bytes in individually selectable items classified safe or likely safe.
    pub reclaimable_bytes: u64,
    /// Bytes in items that should be reviewed or preserved.
    pub retained_bytes: u64,
    pub reasons: Vec<Reason>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Reason {
    /// positive (supports cleanup) | negative (argues against) | neutral
    pub tone: String,
    pub text: String,
}

fn reason(tone: &str, text: impl Into<String>) -> Reason {
    Reason { tone: tone.into(), text: text.into() }
}

fn has(result: &DirectoryResult, kind: &str) -> bool {
    result.evidence.iter().any(|item| item.kind == kind)
}

const SECONDS_PER_DAY: u64 = 86_400;

/// Computes the assessment. `now_unix` is injected for reproducible tests.
pub fn assess(result: &DirectoryResult, now_unix: u64) -> Assessment {
    let mut reasons = Vec::new();
    let owner_name = result.owner.as_ref().map(|owner| owner.name.clone())
        .or_else(|| result.owner_hint.clone()).unwrap_or_else(|| "The owner".into());
    let live_reference = has(result, "active_reference");
    let dead_reference = has(result, "dead_reference");

    // ---- Ownership class ----
    let location_class = result.location_class.as_deref().unwrap_or_default();
    let system_managed = location_class == "system" || result.ownership == "system";
    let shared_runtime = location_class == "shared_runtime" || result.ownership == "shared_runtime";
    let ownership_class = if system_managed {
        "system"
    } else if shared_runtime || matches!(result.ownership.as_str(), "shared" | "product_family") || result.orphan_status == "associated_with_installed" {
        "shared"
    } else if result.owner.is_some() {
        "exclusive"
    } else {
        "unknown"
    };
    if result.orphan_status == "known_application_data" {
        let label = result.owner_hint.clone().unwrap_or_else(|| "a known application".into());
        reasons.push(reason("neutral", format!("Recognized as {label} data. Recognition alone says nothing about whether it is still needed.")));
    }

    // ---- Orphan confidence ----
    let mut orphan_confidence = match result.orphan_status.as_str() {
        "probable_orphan" => {
            if has(result, "install_location_removed") {
                reasons.push(reason("positive", format!("{owner_name} was previously installed here and its installation folder has since disappeared.")));
                "confirmed"
            } else {
                "very_likely"
            }
        }
        "possibly_orphaned" => {
            let observed = has(result, "historical_owner") || has(result, "historical_version_owner");
            if observed || dead_reference { "likely" } else { "uncertain" }
        }
        "not_orphaned" | "associated_with_installed" | "referenced_by_system" => "not_orphaned",
        "unregistered_application" => "unknown",
        _ => "unknown",
    };
    if has(result, "historical_owner") {
        reasons.push(reason("positive", format!("A previous scan linked this exact folder to {owner_name}, which is no longer in the installed-application inventory.")));
    }
    if has(result, "newer_product_version_installed") {
        reasons.push(reason("positive", "A strictly newer version of the same product is installed."));
    }
    if has(result, "known_location") && result.orphan_status == "possibly_orphaned" {
        reasons.push(reason("neutral", format!("This is known {owner_name} data, but no matching installation was found. That is a weak, first-run inference.")));
    }
    if has(result, "known_definition") && result.orphan_status == "possibly_orphaned" {
        reasons.push(reason("neutral", format!("An application definition identifies this as {owner_name} data, and no matching installation was found.")));
    }
    if dead_reference {
        reasons.push(reason("positive", "A startup entry, shortcut, task or service still points into this folder, but its executable is missing."));
    }
    if live_reference {
        reasons.push(reason("negative", "An existing startup entry, shortcut, scheduled task or service still uses a file in this folder."));
        if matches!(orphan_confidence, "confirmed" | "very_likely" | "likely") {
            orphan_confidence = "uncertain";
        }
    }
    if result.orphan_status == "not_orphaned" {
        reasons.push(reason("negative", format!("{owner_name} is currently installed and linked to this folder.")));
    } else if result.orphan_status == "associated_with_installed" {
        reasons.push(reason("negative", "The folder is associated with installed software from the same vendor or family; it may be shared."));
    } else if result.orphan_status == "unregistered_application" {
        reasons.push(reason("neutral", "The folder contains application executables but no uninstall registration. It may be a portable application, not leftovers."));
    } else if result.orphan_status == "unknown" {
        reasons.push(reason("neutral", "No reliable owner was identified. Unknown does not mean unnecessary."));
    }

    // ---- Age ----
    if let Some(newest) = result.newest_modified_unix {
        let days = now_unix.saturating_sub(newest) / SECONDS_PER_DAY;
        if days >= 180 {
            reasons.push(reason("neutral", format!("Nothing inside changed for {days} days. Age is only a reason to inspect, never proof.")));
        } else if days <= 7 && matches!(orphan_confidence, "confirmed" | "very_likely" | "likely" | "uncertain") {
            let when = match days { 0 => "today".to_string(), 1 => "yesterday".to_string(), _ => format!("{days} days ago") };
            reasons.push(reason("negative", format!("Files changed {when}; something may still be writing here.")));
            if orphan_confidence == "confirmed" { orphan_confidence = "very_likely"; }
        }
    }

    // ---- Deletion safety (independent of orphan confidence) ----
    let mut deletion_safety = content::overall_safety(&result.content);
    let mut reclaimable_bytes = 0u64;
    let mut retained_bytes = 0u64;
    for item in &result.content.items {
        if item.is_directory && matches!(item.safety.as_str(), SAFE | LIKELY_SAFE) {
            reclaimable_bytes = reclaimable_bytes.saturating_add(item.size_bytes);
        } else if matches!(item.safety.as_str(), REVIEW | PRESERVE | UNKNOWN) {
            retained_bytes = retained_bytes.saturating_add(item.size_bytes);
        }
    }
    let preserve_items = result.content.items.iter().filter(|item| item.safety == PRESERVE)
        .map(|item| item.name.as_str()).take(4).collect::<Vec<_>>();
    if !preserve_items.is_empty() {
        reasons.push(reason("negative", format!("Contains data worth keeping: {}.", preserve_items.join(", "))));
    }
    if has(result, "ludusavi_game_data") {
        deletion_safety = PRESERVE;
        reasons.push(reason("negative", "Public game-save data lists save or settings paths here."));
    }
    if system_managed || shared_runtime {
        deletion_safety = PRESERVE;
        reasons.push(reason("negative", "Windows or a shared runtime manages this location; it is excluded from cleanup."));
    } else if ownership_class == "shared" && content::safety_rank(deletion_safety) < content::safety_rank(REVIEW) {
        deletion_safety = REVIEW;
    }
    if result.content.executable_count > 0 && content::safety_rank(deletion_safety) < content::safety_rank(REVIEW) {
        deletion_safety = REVIEW;
    }
    if result.content.items.is_empty() && result.file_count == 0 && result.size_bytes == 0 {
        reasons.push(reason("neutral", "The folder is empty."));
    }

    // ---- Recommendation ----
    let strong_orphan = matches!(orphan_confidence, "confirmed" | "very_likely");
    let orphan = strong_orphan || orphan_confidence == "likely";
    let recommended_action = if system_managed || shared_runtime {
        "keep"
    } else if strong_orphan && matches!(deletion_safety, SAFE | LIKELY_SAFE) {
        "clean"
    } else if orphan && reclaimable_bytes > 0 {
        "clean_selected"
    } else if orphan || orphan_confidence == "uncertain" || result.orphan_status == "unregistered_application" {
        "review"
    } else {
        "keep"
    };
    match recommended_action {
        "clean" => reasons.push(reason("positive", "Strong orphan evidence and only regenerable content: recommended for cleanup.")),
        "clean_selected" => reasons.push(reason("neutral", "Only the regenerable parts are recommended; review the rest.")),
        _ => {}
    }

    Assessment {
        orphan_confidence: orphan_confidence.into(),
        deletion_safety: deletion_safety.into(),
        ownership_class: ownership_class.into(),
        recommended_action: recommended_action.into(),
        reclaimable_bytes,
        retained_bytes,
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::{ContentItem, ContentProfile};
    use crate::Evidence;

    fn item(name: &str, safety: &str, size: u64) -> ContentItem {
        ContentItem { name: name.into(), is_directory: true, kind: "cache".into(), safety: safety.into(), size_bytes: size, ..Default::default() }
    }

    fn evidence(kind: &str) -> Evidence {
        Evidence { kind: kind.into(), description: String::new(), strength: "strong".into() }
    }

    #[test]
    fn strong_orphan_with_only_cache_is_clean() {
        let result = DirectoryResult {
            orphan_status: "probable_orphan".into(), ownership: "historical_confirmed".into(),
            evidence: vec![evidence("historical_owner")],
            content: ContentProfile { items: vec![item("Cache", SAFE, 10)], ..Default::default() },
            ..Default::default()
        };
        let assessment = assess(&result, 0);
        assert_eq!(assessment.orphan_confidence, "very_likely");
        assert_eq!(assessment.deletion_safety, SAFE);
        assert_eq!(assessment.recommended_action, "clean");
        assert_eq!(assessment.reclaimable_bytes, 10);
    }

    #[test]
    fn orphan_with_saves_only_recommends_selected_items() {
        let result = DirectoryResult {
            orphan_status: "probable_orphan".into(), ownership: "historical_confirmed".into(),
            content: ContentProfile { items: vec![item("Cache", SAFE, 10), item("Saves", PRESERVE, 5)], ..Default::default() },
            ..Default::default()
        };
        let assessment = assess(&result, 0);
        assert_eq!(assessment.deletion_safety, PRESERVE);
        assert_eq!(assessment.recommended_action, "clean_selected");
        assert_eq!(assessment.retained_bytes, 5);
    }

    #[test]
    fn live_reference_downgrades_confidence() {
        let result = DirectoryResult {
            orphan_status: "probable_orphan".into(), ownership: "historical_confirmed".into(),
            evidence: vec![evidence("active_reference")],
            content: ContentProfile { items: vec![item("Cache", SAFE, 10)], ..Default::default() },
            ..Default::default()
        };
        let assessment = assess(&result, 0);
        assert_eq!(assessment.orphan_confidence, "uncertain");
        assert_eq!(assessment.recommended_action, "review");
    }

    #[test]
    fn unknown_owner_is_never_recommended_for_cleanup() {
        let result = DirectoryResult {
            orphan_status: "unknown".into(), ownership: "unknown".into(), newest_modified_unix: Some(0),
            content: ContentProfile { items: vec![item("Cache", SAFE, 10)], ..Default::default() },
            ..Default::default()
        };
        let assessment = assess(&result, 10_000 * SECONDS_PER_DAY);
        assert_eq!(assessment.recommended_action, "keep");
    }

    #[test]
    fn system_locations_are_kept() {
        let result = DirectoryResult { orphan_status: "known_application_data".into(), ownership: "known_location".into(), location_class: Some("system".into()), ..Default::default() };
        let assessment = assess(&result, 0);
        assert_eq!(assessment.ownership_class, "system");
        assert_eq!(assessment.deletion_safety, PRESERVE);
        assert_eq!(assessment.recommended_action, "keep");
    }
}
