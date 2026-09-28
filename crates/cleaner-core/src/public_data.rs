use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// An indexed, read-only subset of public path definitions. A match describes
/// a possible use of a directory, never its installed state or deletion safety.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FolderKnowledge {
    pub games: BTreeMap<String, Vec<GamePath>>,
    pub cleaner_rules: BTreeMap<String, Vec<String>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct GamePath {
    pub game: String,
    pub path: String,
    pub tags: Vec<String>,
}

fn indexed_path(path: &str) -> Option<(String, String)> {
    let path = path.replace('\\', "/");
    let (root, tail) = [
        ("<winLocalAppDataLow>", "LocalLow"),
        ("<winLocalAppData>", "Local"),
        ("<winAppData>", "Roaming"),
        ("<winProgramData>", "ProgramData"),
        ("%LocalAppData%", "Local"),
        ("%AppData%", "Roaming"),
        ("%ProgramData%", "ProgramData"),
    ]
    .into_iter()
    .find_map(|(prefix, root)| {
        path.get(..prefix.len())
            .filter(|part| part.eq_ignore_ascii_case(prefix))
            .and_then(|_| path.get(prefix.len()..)?.strip_prefix('/'))
            .map(|tail| (root, tail))
    })?;
    if tail.split('/').any(|part| part == ".." || part == ".") {
        return None;
    }
    let first = tail.split('/').next()?.trim();
    if first.is_empty()
        || first == "."
        || first == ".."
        || first.chars().any(|ch| {
            matches!(
                ch,
                '*' | '?' | '[' | ']' | '{' | '}' | '<' | '>' | '%' | ':'
            )
        })
    {
        return None;
    }
    Some((format!("{root}|{}", first.to_lowercase()), tail.to_owned()))
}

fn yaml_string(value: &serde_yaml::Value) -> Option<&str> {
    value.as_str()
}

fn windows_applicable(data: &serde_yaml::Value) -> bool {
    let Some(conditions) = data.get("when").and_then(serde_yaml::Value::as_sequence) else {
        return true;
    };
    conditions.is_empty()
        || conditions.iter().any(|condition| {
            condition
                .get("os")
                .and_then(yaml_string)
                .is_none_or(|os| os == "windows")
        })
}

fn existing_game_prefix(directory: &std::path::Path, relative: &str) -> bool {
    let mut prefix = directory.to_path_buf();
    for component in relative.split('/').skip(1) {
        if component
            .chars()
            .any(|ch| matches!(ch, '*' | '?' | '[' | ']' | '{' | '}' | '<' | '>' | '%'))
        {
            break;
        }
        prefix.push(component);
        if !prefix.exists() {
            return false;
        }
    }
    true
}

impl FolderKnowledge {
    pub fn from_ludusavi_yaml(bytes: &[u8]) -> Result<BTreeMap<String, Vec<GamePath>>, String> {
        let manifest: serde_yaml::Value = serde_yaml::from_slice(bytes)
            .map_err(|err| format!("Game manifest is invalid: {err}"))?;
        let games = manifest
            .as_mapping()
            .ok_or("Game manifest has no game mapping")?;
        let mut indexed: BTreeMap<String, BTreeSet<GamePath>> = BTreeMap::new();
        for (name, game) in games {
            let Some(game_name) = yaml_string(name) else {
                continue;
            };
            let Some(files) = game.get("files").and_then(serde_yaml::Value::as_mapping) else {
                continue;
            };
            for (path, details) in files {
                let Some(path) = yaml_string(path) else {
                    continue;
                };
                if !windows_applicable(details) {
                    continue;
                }
                let Some((key, relative)) = indexed_path(path) else {
                    continue;
                };
                let tags = details
                    .get("tags")
                    .and_then(serde_yaml::Value::as_sequence)
                    .map(|values| {
                        values
                            .iter()
                            .filter_map(yaml_string)
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default();
                indexed.entry(key).or_default().insert(GamePath {
                    game: game_name.to_owned(),
                    path: relative,
                    tags,
                });
            }
        }
        if indexed.is_empty() {
            return Err("Game manifest contains no supported Windows paths".into());
        }
        Ok(indexed
            .into_iter()
            .map(|(key, paths)| (key, paths.into_iter().collect()))
            .collect())
    }

    pub fn from_winapp2_ini(bytes: &[u8]) -> Result<BTreeMap<String, Vec<String>>, String> {
        let source = String::from_utf8_lossy(bytes);
        let mut indexed: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut section = String::new();
        for line in source.lines() {
            let line = line.trim();
            if line.starts_with(';') || line.is_empty() {
                continue;
            }
            if let Some(title) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                section = title.trim_end_matches(" *").to_owned();
                continue;
            }
            let Some((field, value)) = line.split_once('=') else {
                continue;
            };
            if section.is_empty() || !(field.starts_with("FileKey") || field == "DetectFile") {
                continue;
            }
            let path = value.split('|').next().unwrap_or_default().trim();
            if let Some((key, _)) = indexed_path(path) {
                indexed.entry(key).or_default().insert(section.clone());
            }
        }
        if indexed.is_empty() {
            return Err("Winapp2 contains no supported AppData paths".into());
        }
        Ok(indexed
            .into_iter()
            .map(|(key, rules)| (key, rules.into_iter().collect()))
            .collect())
    }

    pub fn annotate(&self, result: &mut crate::DirectoryResult) {
        let Some(name) = std::path::Path::new(&result.path).file_name() else {
            return;
        };
        let key = format!("{}|{}", result.root, name.to_string_lossy().to_lowercase());
        let directory = std::path::Path::new(&result.path);
        if let Some(paths) = self
            .games
            .get(&key)
            .map(|paths| {
                paths
                    .iter()
                    .filter(|path| existing_game_prefix(directory, &path.path))
                    .collect::<Vec<_>>()
            })
            .filter(|paths| !paths.is_empty())
        {
            let games: BTreeSet<_> = paths.iter().map(|path| path.game.as_str()).collect();
            let examples = paths
                .iter()
                .take(3)
                .map(|path| {
                    let kind = if path.tags.is_empty() {
                        "game data".to_owned()
                    } else {
                        path.tags.join("/")
                    };
                    format!("{}: {} ({kind})", path.game, path.path)
                })
                .collect::<Vec<_>>()
                .join("; ");
            result.evidence.push(crate::Evidence {
                kind: "ludusavi_game_data".into(),
                description: format!("Ludusavi lists {} Windows game data path(s) under this directory, covering {} game(s). Examples: {examples}. These paths may contain valuable user data; this does not establish installation or deletion safety.", paths.len(), games.len()),
                strength: "medium".into(),
            });
            if result.orphan_status == "unknown" {
                result.orphan_status = "known_application_data".into();
                result.ownership = "public_path_catalog".into();
                result.owner_hint = Some(if games.len() == 1 {
                    games.iter().next().unwrap().to_string()
                } else {
                    format!("Game data ({} games)", games.len())
                });
            }
        }
        if let Some(rules) = self.cleaner_rules.get(&key) {
            let examples = rules.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
            result.evidence.push(crate::Evidence {
                kind: "winapp2_path_rules".into(),
                description: format!("Winapp2 defines {} cleaning rule(s) with paths under this directory (for example, {examples}). Rules may target only selected caches or logs, not the whole directory. No cleanup action is inferred.", rules.len()),
                strength: "weak".into(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn game_paths_keep_saves_and_skip_other_platforms_or_globbed_parents() {
        let yaml = br#"Game One:
  files:
    <winLocalAppDataLow>/Studio/Game/save.dat:
      tags: [save]
      when: [{os: windows}]
    <winAppData>/*/save.dat: {tags: [save]}
    <winAppData>/LinuxOnly: {when: [{os: linux}]}
"#;
        let index = FolderKnowledge::from_ludusavi_yaml(yaml).unwrap();
        assert_eq!(index.len(), 1);
        assert_eq!(index["LocalLow|studio"][0].tags, ["save"]);
    }

    #[test]
    fn winapp_rules_do_not_expand_wildcard_parents() {
        let ini = b"[App Cache *]\nFileKey1=%LocalAppData%\\Studio\\Cache|*\nFileKey2=%AppData%\\*\\Cache|*\n";
        let index = FolderKnowledge::from_winapp2_ini(ini).unwrap();
        assert_eq!(index["Local|studio"], ["App Cache"]);
        assert_eq!(index.len(), 1);
    }

    #[test]
    fn nested_game_path_requires_an_existing_child() {
        let folder = std::env::temp_dir().join(format!(
            "orphan-cleaner-catalog-prefix-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&folder).unwrap();
        assert!(!existing_game_prefix(&folder, "Studio/Game/save.dat"));
        std::fs::create_dir_all(folder.join("Game")).unwrap();
        assert!(existing_game_prefix(&folder, "Studio/Game/*.sav"));
        std::fs::remove_dir_all(folder).unwrap();
    }
}
