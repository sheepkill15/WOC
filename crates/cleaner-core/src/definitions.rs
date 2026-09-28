//! Optional known-application definitions (spec §22).
//!
//! A definition names a product, the executables that identify it, and data
//! paths with a content type. Definitions only refine content classification
//! and add evidence; inference still works without any definition. Users can
//! add their own YAML files; built-in definitions are embedded below.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

use crate::content::{safety_for_kind, kind_label};
use crate::{Application, DirectoryResult, Evidence, normalize_name, product_name_without_version};

#[derive(Clone, Debug, Deserialize)]
pub struct DefinitionPath {
    pub path: String,
    #[serde(rename = "type")]
    pub kind: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct DefinitionIdentifiers {
    #[serde(default)]
    pub executables: Vec<String>,
    #[serde(default)]
    pub names: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Definition {
    pub id: String,
    #[serde(default)]
    pub vendor: Option<String>,
    pub product: String,
    #[serde(default)]
    pub identifiers: DefinitionIdentifiers,
    #[serde(default)]
    pub paths: Vec<DefinitionPath>,
    #[serde(skip)]
    pub source: String,
}

#[derive(Clone, Debug, Default)]
pub struct Definitions {
    pub definitions: Vec<Definition>,
    pub warnings: Vec<String>,
    /// (root label, lowercase directory name) → (definition index, lowercase child name or "", kind)
    index: HashMap<(String, String), Vec<(usize, String, String)>>,
}

const BUILT_IN: &str = include_str!("definitions.yaml");

fn root_for_variable(variable: &str) -> Option<&'static str> {
    match variable.to_ascii_uppercase().as_str() {
        "%LOCALAPPDATA%" => Some("Local"),
        "%APPDATA%" => Some("Roaming"),
        "%LOCALAPPDATALOW%" | "%USERPROFILE%\\APPDATA\\LOCALLOW" => Some("LocalLow"),
        "%PROGRAMDATA%" => Some("ProgramData"),
        _ => None,
    }
}

fn normalize_kind(kind: &str) -> String {
    kind.trim().to_ascii_lowercase().replace([' ', '-'], "_")
}

impl Definitions {
    pub fn built_in() -> Self {
        let mut definitions = Self::default();
        definitions.add_yaml(BUILT_IN, "built-in");
        definitions
    }

    /// Loads built-in definitions plus every `.yaml`/`.yml` file in `directory`.
    pub fn load(directory: &Path) -> Self {
        let mut definitions = Self::built_in();
        let Ok(entries) = std::fs::read_dir(directory) else { return definitions; };
        let mut files = entries.flatten().map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|extension| extension.eq_ignore_ascii_case("yaml") || extension.eq_ignore_ascii_case("yml")))
            .collect::<Vec<_>>();
        files.sort();
        for file in files.into_iter().take(500) {
            match std::fs::read_to_string(&file) {
                Ok(text) if text.len() <= 1_000_000 => {
                    let name = file.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
                    definitions.add_yaml(&text, &name);
                }
                Ok(_) => definitions.warnings.push(format!("{} is larger than 1 MB and was skipped.", file.display())),
                Err(error) => definitions.warnings.push(format!("{} could not be read: {error}", file.display())),
            }
        }
        definitions
    }

    pub fn user_definition_count(&self) -> usize {
        self.definitions.iter().filter(|definition| definition.source != "built-in").count()
    }

    fn add_yaml(&mut self, text: &str, source: &str) {
        // A file may hold one definition, a list, or several YAML documents.
        let mut parsed = Vec::new();
        for document in serde_yaml::Deserializer::from_str(text) {
            let value = match serde_yaml::Value::deserialize(document) {
                Ok(value) => value,
                Err(error) => { self.warnings.push(format!("{source}: {error}")); return; }
            };
            if value.is_null() { continue; }
            let items = if value.is_sequence() { serde_yaml::from_value::<Vec<Definition>>(value) } else { serde_yaml::from_value::<Definition>(value).map(|definition| vec![definition]) };
            match items {
                Ok(items) => parsed.extend(items),
                Err(error) => { self.warnings.push(format!("{source}: {error}")); return; }
            }
        }
        for mut definition in parsed {
            definition.source = source.into();
            let index = self.definitions.len();
            for entry in &definition.paths {
                let normalized = entry.path.replace('/', "\\");
                let Some((variable, rest)) = normalized.split_once('\\') else { continue; };
                let Some(root) = root_for_variable(variable) else {
                    self.warnings.push(format!("{source}: {} uses an unsupported root; use %LOCALAPPDATA%, %APPDATA%, %LOCALAPPDATALOW% or %PROGRAMDATA%.", entry.path));
                    continue;
                };
                let mut parts = rest.split('\\').filter(|part| !part.is_empty());
                let Some(directory) = parts.next() else { continue; };
                let child = parts.next().unwrap_or_default().to_ascii_lowercase();
                if parts.next().is_some() {
                    self.warnings.push(format!("{source}: {} is deeper than one child folder; only the first two levels are used.", entry.path));
                }
                self.index.entry((root.into(), directory.to_ascii_lowercase())).or_default()
                    .push((index, child, normalize_kind(&entry.kind)));
            }
            self.definitions.push(definition);
        }
    }

    fn product_installed(definition: &Definition, apps: &[Application]) -> bool {
        let mut names = definition.identifiers.names.iter().map(|name| normalize_name(name)).collect::<Vec<_>>();
        names.push(normalize_name(&definition.product));
        let executables = definition.identifiers.executables.iter().map(|name| name.to_ascii_lowercase()).collect::<Vec<_>>();
        apps.iter().any(|app| {
            let product = normalize_name(&product_name_without_version(&app.name));
            names.iter().any(|name| !name.is_empty() && (*name == product || *name == normalize_name(&app.name)))
                || app.display_icon_executable.as_deref().and_then(|icon| Path::new(icon).file_name())
                    .is_some_and(|file| executables.contains(&file.to_string_lossy().to_ascii_lowercase()))
        })
    }

    /// Applies matching definitions to a measured directory: refines content items
    /// and, for otherwise unknown directories, records the known product as a hint.
    pub fn annotate(&self, result: &mut DirectoryResult, apps: &[Application]) {
        let Some(name) = Path::new(&result.path).file_name().map(|name| name.to_string_lossy().to_ascii_lowercase()) else { return; };
        // Nested targets (Vendor\Product) are keyed by their top-level container plus child.
        let key = if let Some(parent) = result.parent_path.as_deref().and_then(|parent| Path::new(parent).file_name()) {
            (result.root.clone(), parent.to_string_lossy().to_ascii_lowercase())
        } else {
            (result.root.clone(), name.clone())
        };
        let Some(entries) = self.index.get(&key) else { return; };
        let nested_child = result.parent_path.is_some().then(|| name.clone());
        let mut matched: Option<usize> = None;
        let mut refined = Vec::new();
        for (definition_index, child, kind) in entries {
            match &nested_child {
                Some(nested) => {
                    if child != nested { continue; }
                    matched = Some(*definition_index);
                }
                None => {
                    matched = Some(*definition_index);
                    if child.is_empty() { continue; }
                    if let Some(item) = result.content.items.iter_mut().find(|item| item.is_directory && item.name.eq_ignore_ascii_case(child)) {
                        item.kind = kind.clone();
                        item.safety = safety_for_kind(kind).into();
                        item.source = "definition".into();
                        item.reason = format!("The {} definition lists this folder as {}.", self.definitions[*definition_index].product, kind_label(kind).to_lowercase());
                        refined.push(item.name.clone());
                    }
                }
            }
        }
        let Some(definition_index) = matched else { return; };
        let definition = &self.definitions[definition_index];
        let installed = Self::product_installed(definition, apps);
        let refined_text = if refined.is_empty() { String::new() } else { format!(" Classified: {}.", refined.join(", ")) };
        result.evidence.push(Evidence {
            kind: "known_definition".into(),
            description: format!("The {} application definition ({}) describes this location.{refined_text}", definition.product, definition.source),
            strength: "medium".into(),
        });
        if result.orphan_status == "unknown" && result.owner.is_none() {
            result.owner_hint = Some(definition.product.clone());
            result.ownership = "known_definition".into();
            if installed {
                result.orphan_status = "known_application_data".into();
            } else {
                result.orphan_status = "possibly_orphaned".into();
                result.evidence.push(Evidence {
                    kind: "missing_installed_app".into(),
                    description: format!("No installed registration or registered executable matching {} was found. Launcher-managed or portable installations may still use this data.", definition.product),
                    strength: "weak".into(),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::{ContentItem, ContentProfile};

    fn result(path: &str, root: &str) -> DirectoryResult {
        DirectoryResult { path: path.into(), root: root.into(), ownership: "unknown".into(), orphan_status: "unknown".into(), ..Default::default() }
    }

    #[test]
    fn built_in_definitions_parse() {
        let definitions = Definitions::built_in();
        assert!(definitions.warnings.is_empty(), "{:?}", definitions.warnings);
        assert!(definitions.definitions.len() >= 10);
    }

    #[test]
    fn definition_refines_items_and_marks_missing_product_as_possible() {
        let definitions = Definitions::built_in();
        let mut discord = result(r"C:\Users\Test\AppData\Roaming\discord", "Roaming");
        discord.content = ContentProfile { items: vec![ContentItem { name: "Cache".into(), is_directory: true, kind: "unknown".into(), safety: "unknown".into(), ..Default::default() }], ..Default::default() };
        definitions.annotate(&mut discord, &[]);
        assert_eq!(discord.content.items[0].kind, "cache");
        assert_eq!(discord.content.items[0].safety, "safe");
        assert_eq!(discord.orphan_status, "possibly_orphaned");
        assert_eq!(discord.owner_hint.as_deref(), Some("Discord"));
    }

    #[test]
    fn user_yaml_accepts_lists_and_reports_errors() {
        let mut definitions = Definitions::default();
        definitions.add_yaml("- id: a\n  product: A\n  paths:\n    - path: \"%APPDATA%\\\\A\\\\Cache\"\n      type: CACHE\n", "a.yaml");
        assert_eq!(definitions.definitions.len(), 1);
        definitions.add_yaml("id: [", "broken.yaml");
        assert_eq!(definitions.warnings.len(), 1);
    }
}
