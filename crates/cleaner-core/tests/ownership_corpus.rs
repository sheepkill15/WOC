use cleaner_core::{Application, classify_directory};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CorpusCase {
    id: String,
    rationale: String,
    path: String,
    root: String,
    #[serde(default)]
    applications: Vec<CorpusApplication>,
    expected: ExpectedClassification,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CorpusApplication {
    id: String,
    name: String,
    #[serde(default)]
    publisher: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    install_location: Option<String>,
    #[serde(default)]
    package_family_name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExpectedClassification {
    #[serde(default)]
    owner_id: Option<String>,
    #[serde(default)]
    owner_hint: Option<String>,
    ownership: String,
    orphan_status: String,
    evidence_kinds: Vec<String>,
}

impl From<CorpusApplication> for Application {
    fn from(value: CorpusApplication) -> Self {
        Self {
            id: value.id,
            name: value.name,
            publisher: value.publisher,
            version: value.version,
            install_location: value.install_location,
            display_icon_executable: None,
            package_family_name: value.package_family_name,
            sources: vec!["validation corpus".into()],
        }
    }
}

#[test]
fn ownership_corpus_matches_reviewed_expectations() {
    let cases: Vec<CorpusCase> =
        serde_json::from_str(include_str!("fixtures/ownership_cases.json"))
            .expect("ownership corpus must be valid JSON");
    assert!(
        cases.len() >= 10,
        "the corpus should cover more than isolated examples"
    );

    for case in cases {
        assert!(
            !case.rationale.trim().is_empty(),
            "{} needs an audit rationale",
            case.id
        );
        let applications = case
            .applications
            .into_iter()
            .map(Application::from)
            .collect::<Vec<_>>();
        let result = classify_directory(Path::new(&case.path), &case.root, &applications);
        let evidence_kinds = result
            .evidence
            .iter()
            .map(|item| item.kind.clone())
            .collect::<Vec<_>>();

        assert_eq!(
            result.owner.as_ref().map(|owner| owner.id.as_str()),
            case.expected.owner_id.as_deref(),
            "{}: owner; {}",
            case.id,
            case.rationale
        );
        assert_eq!(
            result.owner_hint.as_deref(),
            case.expected.owner_hint.as_deref(),
            "{}: owner hint; {}",
            case.id,
            case.rationale
        );
        assert_eq!(
            result.ownership, case.expected.ownership,
            "{}: ownership; {}",
            case.id, case.rationale
        );
        assert_eq!(
            result.orphan_status, case.expected.orphan_status,
            "{}: orphan status; {}",
            case.id, case.rationale
        );
        assert_eq!(
            evidence_kinds, case.expected.evidence_kinds,
            "{}: evidence; {}",
            case.id, case.rationale
        );
    }
}
