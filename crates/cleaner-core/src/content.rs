//! Deterministic content classification.
//!
//! Classification uses only directory names, file extensions, sizes and
//! timestamps collected while measuring a directory. File contents are never
//! read. Every category maps to a fixed deletion-safety class, and user-data
//! markers found anywhere below a child directory escalate that child to
//! `preserve`, including folders named Cache. Cached images remain regenerable.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const SAFE: &str = "safe";
pub const LIKELY_SAFE: &str = "likely_safe";
pub const REVIEW: &str = "review";
pub const PRESERVE: &str = "preserve";
pub const UNKNOWN: &str = "unknown";

/// Maximum number of child directories tracked individually per measured directory.
pub const MAX_TRACKED_CHILDREN: usize = 256;
/// Maximum number of content items reported per directory.
const MAX_REPORTED_ITEMS: usize = 40;
/// Files at least this large are counted as large files.
pub const LARGE_FILE_BYTES: u64 = 100 * 1024 * 1024;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ContentItem {
    /// Child directory name, or a descriptive label for grouped loose files.
    pub name: String,
    /// True when `name` is a real child directory that can be selected individually.
    pub is_directory: bool,
    pub kind: String,
    pub safety: String,
    pub size_bytes: u64,
    pub file_count: u64,
    #[serde(default)]
    pub newest_modified_unix: Option<u64>,
    /// Why the kind or safety was chosen.
    #[serde(default)]
    pub reason: String,
    /// Source of the classification: "name", "extension", "marker", "definition", "location".
    #[serde(default)]
    pub source: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionStat {
    pub extension: String,
    pub size_bytes: u64,
    pub file_count: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ContentProfile {
    pub items: Vec<ContentItem>,
    pub extensions: Vec<ExtensionStat>,
    pub executable_count: u64,
    pub database_count: u64,
    pub large_file_count: u64,
    pub large_file_bytes: u64,
    /// Child directories that were not tracked individually (beyond the tracking cap).
    #[serde(default)]
    pub untracked_children: u64,
    /// All observed categories, including small or grouped items omitted from the UI.
    #[serde(default)]
    pub categories: Vec<String>,
}

impl ContentProfile {
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// Safety class for a content category.
pub fn safety_for_kind(kind: &str) -> &'static str {
    match kind {
        "cache" | "temporary" | "log" | "crash_dump" | "shader_cache" | "thumbnail_cache" | "empty" => SAFE,
        "update_cache" | "installer_cache" | "downloaded_asset" | "generated_data" => LIKELY_SAFE,
        "configuration" | "application_state" | "session_data" | "account_data" | "plugin"
        | "database" | "application_binaries" => REVIEW,
        "save_game" | "mod" | "project" | "document" | "media" => PRESERVE,
        _ => UNKNOWN,
    }
}

pub fn safety_rank(safety: &str) -> u8 {
    match safety {
        SAFE => 0,
        LIKELY_SAFE => 1,
        UNKNOWN => 2,
        REVIEW => 3,
        PRESERVE => 4,
        _ => 2,
    }
}

pub fn kind_label(kind: &str) -> &'static str {
    match kind {
        "cache" => "Cache",
        "temporary" => "Temporary files",
        "log" => "Logs",
        "crash_dump" => "Crash dumps",
        "update_cache" => "Update cache",
        "installer_cache" => "Installer cache",
        "shader_cache" => "Shader cache",
        "thumbnail_cache" => "Thumbnail cache",
        "downloaded_asset" => "Downloaded assets",
        "generated_data" => "Generated data",
        "configuration" => "Configuration",
        "application_state" => "Application state",
        "session_data" => "Session data",
        "account_data" => "Account data",
        "plugin" => "Plugins / extensions",
        "mod" => "Mods",
        "save_game" => "Save games",
        "database" => "Database",
        "project" => "Projects",
        "document" => "Documents",
        "media" => "Media",
        "application_binaries" => "Application files",
        "empty" => "Empty folder",
        _ => "Unclassified",
    }
}

/// Classifies a child directory by its name. Returns the category and an optional
/// safety override for names whose category is broad but whose content is riskier.
pub fn kind_for_directory_name(name: &str) -> Option<(&'static str, Option<&'static str>)> {
    let lower = name.trim().to_ascii_lowercase();
    let compact: String = lower.chars().filter(|ch| ch.is_ascii_alphanumeric()).collect();
    let kind = match compact.as_str() {
        "cache" | "caches" | "codecache" | "cachestorage" | "cachedata" | "cached" | "cacheddata"
        | "webcache" | "inetcache" | "httpcache" | "mediacache" | "componentcrxcache" | "jscache"
        | "scriptcache" | "cachedextensionvsixs" | "cachedprofilesdata" | "blobcache" | "imagecache"
        | "iconcache" | "fontcache" | "netcache" | "diskcache" | "webcachev01" | "htmlcache" => "cache",
        "gpucache" | "grshadercache" | "shadercache" | "dawncache" | "dawngraphitecache"
        | "dawnwebgpucache" | "nvcache" | "dxcache" | "glcache" | "vkcache" | "pipelinecache"
        | "shaders" | "shadercachedir" | "d3dscache" => "shader_cache",
        "thumbnails" | "thumbcache" | "thumbs" | "thumbnailcache" => "thumbnail_cache",
        "logs" | "log" | "logfiles" | "logging" | "tracing" | "traces" | "diagnostics" | "telemetry" => "log",
        "crashpad" | "crashdumps" | "crashreports" | "crashes" | "crash" | "dumps" | "minidumps"
        | "minidump" | "crashreporter" | "pendingcrashes" | "reportarchive" | "reportqueue" => "crash_dump",
        "temp" | "tmp" | "temporary" | "temporaryfiles" | "scratch" | "squirreltemp" => "temporary",
        "updates" | "update" | "updater" | "updatecache" | "pendingupdate" | "pending" | "patches"
        | "packagesdownload" | "deltas" | "staging" => "update_cache",
        "installer" | "installers" | "packagecache" | "setup" | "setupfiles" | "msi" | "redist" => "installer_cache",
        "downloads" | "download" | "downloadcache" => return Some(("downloaded_asset", Some(REVIEW))),
        "config" | "configs" | "configuration" | "settings" | "preferences" | "prefs" | "options"
        | "keybindings" | "user" | "usersettings" | "globalstorage" | "workspacestorage" => "configuration",
        "localstorage" | "indexeddb" | "databases" | "state" | "storage" | "sharedprotodb"
        | "webstorage" | "leveldb" | "filesystem" | "serviceworker" | "blobstorage" | "localstate"
        | "partitions" | "history" => "application_state",
        "sessionstorage" | "sessions" | "session" | "network" | "cookies" => "session_data",
        "userdata" | "profiles" | "profile" | "accounts" | "account" | "default" | "credentials"
        | "identity" | "tokens" | "keys" | "certificates" | "wallet" | "wallets" => "account_data",
        "plugins" | "plugin" | "extensions" | "addons" | "vstplugins" | "vst" | "vst3" | "components" => "plugin",
        "mods" | "mod" | "modpacks" | "workshop" => "mod",
        "saves" | "save" | "savegames" | "savegame" | "savedgames" | "savedata" | "savefiles"
        | "gamesaves" | "playerdata" | "worlds" => "save_game",
        "projects" | "project" | "myprojects" | "workspace" | "workspaces" | "sessionsaves"
        | "templates" | "presets" | "userpresets" | "backup" | "backups" => "project",
        "documents" | "mydocuments" | "notes" | "journals" | "exports" => "document",
        "screenshots" | "recordings" | "videos" | "pictures" | "photos" | "music" | "samples"
        | "clips" | "captures" | "wallpapers" | "images" | "avatars" | "sounds" | "audio" => "media",
        "bin" | "lib" | "resources" | "locales" | "swiftshader" | "runtime" | "runtimes" | "app" => "application_binaries",
        _ => {
            // Squirrel/Electron application version folders, e.g. "app-1.2.3".
            if lower.starts_with("app-") && lower[4..].chars().next().is_some_and(|ch| ch.is_ascii_digit()) {
                "application_binaries"
            } else {
                return None;
            }
        }
    };
    Some((kind, None))
}

/// Category for a file extension (lowercase, without dot).
pub fn kind_for_extension(extension: &str) -> Option<&'static str> {
    Some(match extension {
        "log" | "etl" | "trace" | "evtx" | "log1" | "log2" | "old" => "log",
        "dmp" | "mdmp" | "hdmp" | "wer" => "crash_dump",
        "tmp" | "temp" | "part" | "crdownload" | "partial" | "download" | "bak~" => "temporary",
        "sqlite" | "sqlite3" | "db" | "db3" | "mdb" | "accdb" | "sdf" | "realm" | "edb" => "database",
        "ldb" | "leveldb" => "application_state",
        "ini" | "cfg" | "conf" | "json" | "xml" | "yaml" | "yml" | "toml" | "reg" | "plist"
        | "config" | "prefs" | "settings" | "properties" => "configuration",
        "sav" | "save" | "sv" | "sl2" | "ess" | "savegame" | "sfs" | "rpgsave" | "dat_save" => "save_game",
        "flp" | "als" | "cpr" | "ptx" | "rpp" | "song" | "psd" | "blend" | "kra" | "xcf"
        | "sln" | "prproj" | "aep" | "veg" | "drp" | "fcpx" | "logicx" | "ptf" | "bwproject"
        | "fxp" | "fxb" | "nksf" | "h2p" | "vital" | "serumpreset" => "project",
        "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "pdf" | "odt" | "ods" | "rtf" | "epub" | "one" => "document",
        "png" | "jpg" | "jpeg" | "gif" | "bmp" | "webp" | "heic" | "mp4" | "mkv" | "mov" | "avi"
        | "mp3" | "wav" | "flac" | "ogg" | "aiff" | "aif" | "m4a" | "tif" | "tiff" | "raw" => "media",
        "exe" | "dll" | "sys" | "pak" | "asar" | "node" | "so" => "application_binaries",
        "msi" | "msp" | "cab" | "msix" | "appx" | "msu" => "installer_cache",
        "cache" | "blob" | "idx" | "cached" => "cache",
        "nupkg" | "whl" | "jar" | "tgz" | "crate" => "downloaded_asset",
        _ => return None,
    })
}

fn is_user_data_marker_name(name: &str) -> Option<&'static str> {
    let compact: String = name.to_ascii_lowercase().chars().filter(|ch| ch.is_ascii_alphanumeric()).collect();
    match compact.as_str() {
        "saves" | "savegames" | "savegame" | "savedgames" | "savedata" | "gamesaves" => Some("save-game folder"),
        "screenshots" | "recordings" => Some("screenshot or recording folder"),
        "projects" | "myprojects" => Some("project folder"),
        "presets" | "userpresets" => Some("user preset folder"),
        "mods" => Some("mod folder"),
        "backups" => Some("backup folder"),
        _ => None,
    }
}

/// Accumulates measurements for one immediate child directory, or for all loose
/// files of one extension category directly inside the measured directory.
#[derive(Default, Clone)]
pub struct ChildAccumulator {
    pub name: String,
    pub size: u64,
    pub files: u64,
    pub newest: Option<u64>,
    kind_bytes: BTreeMap<&'static str, u64>,
    markers: BTreeSet<&'static str>,
    directory_kinds: BTreeSet<&'static str>,
}

impl ChildAccumulator {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into(), ..Default::default() }
    }

    pub fn add_file(&mut self, extension: &str, size: u64, modified: Option<u64>) {
        self.size = self.size.saturating_add(size);
        self.files += 1;
        if let Some(modified) = modified {
            self.newest = Some(self.newest.map_or(modified, |old| old.max(modified)));
        }
        if let Some(kind) = kind_for_extension(extension) {
            *self.kind_bytes.entry(kind).or_default() += size.max(1);
            match kind {
                "save_game" => { self.markers.insert("save-game files"); }
                "project" => { self.markers.insert("project or preset files"); }
                "document" => { self.markers.insert("document files"); }
                _ => {}
            }
        }
    }

    pub fn add_directory_name(&mut self, name: &str) {
        if let Some((kind, _)) = kind_for_directory_name(name) { self.directory_kinds.insert(kind); }
        if let Some(marker) = is_user_data_marker_name(name) {
            self.markers.insert(marker);
        }
    }

    pub fn categories(&self) -> BTreeSet<String> {
        let mut kinds: BTreeSet<String> = self.kind_bytes.keys().chain(self.directory_kinds.iter()).map(|kind| (*kind).to_owned()).collect();
        if let Some((kind, _)) = kind_for_directory_name(&self.name) { kinds.insert(kind.to_owned()); }
        kinds
    }

    fn dominant_kind(&self) -> Option<(&'static str, u64)> {
        self.kind_bytes.iter().max_by_key(|(_, bytes)| **bytes).map(|(kind, bytes)| (*kind, *bytes))
    }

    /// Converts the accumulated observations into a reported item.
    pub fn into_item(self, is_directory: bool) -> ContentItem {
        if is_directory && self.files == 0 && self.markers.is_empty() {
            return ContentItem {
                name: self.name, is_directory, kind: "empty".into(), safety: SAFE.into(), size_bytes: 0, file_count: 0,
                newest_modified_unix: None, reason: "Contains no files.".into(), source: "measurement".into(),
            };
        }
        let named = if is_directory { kind_for_directory_name(&self.name) } else { None };
        let dominant = self.dominant_kind();
        let classified_bytes: u64 = self.kind_bytes.values().sum();
        let (mut kind, mut safety_override, mut source, mut reason) = if let Some((kind, safety)) = named {
            (kind, safety, "name", format!("Folder name “{}” is a common {} location.", self.name, kind_label(kind).to_lowercase()))
        } else if let Some((kind, bytes)) = dominant.filter(|(_, bytes)| *bytes * 10 >= self.size.max(1) * 7) {
            let share = (bytes as f64 / self.size.max(1) as f64 * 100.0).round().clamp(0.0, 100.0);
            (kind, None, "extension", format!("About {share:.0}% of the bytes are {} files by extension.", kind_label(kind).to_lowercase()))
        } else {
            let detail = if classified_bytes == 0 { "no recognizable file types" } else { "a mix of file types" };
            ("unknown", None, "extension", format!("Contains {detail}; the purpose could not be determined."))
        };
        // Media inside a named cache stays cache (thumbnails, image caches). Media
        // elsewhere is only user data when it dominates an otherwise unknown folder.
        if !self.markers.is_empty() {
            let markers = self.markers.iter().copied().collect::<Vec<_>>().join(", ");
            if safety_for_kind(kind) != PRESERVE {
                reason = format!("{reason} It also contains {markers}, so it is treated as user data.");
                safety_override = Some(PRESERVE);
                source = "marker";
                if kind == "unknown" { kind = "document"; }
            }
        }
        let safety = safety_override.unwrap_or_else(|| safety_for_kind(kind));
        ContentItem {
            name: self.name,
            is_directory,
            kind: kind.into(),
            safety: safety.into(),
            size_bytes: self.size,
            file_count: self.files,
            newest_modified_unix: self.newest,
            reason,
            source: source.into(),
        }
    }
}

/// Builds the reported content profile from per-child accumulators.
pub fn build_profile(
    children: Vec<ChildAccumulator>,
    loose: BTreeMap<&'static str, ChildAccumulator>,
    extensions: BTreeMap<String, (u64, u64)>,
    executable_count: u64,
    database_count: u64,
    large_file_count: u64,
    large_file_bytes: u64,
    untracked_children: u64,
) -> ContentProfile {
    let mut categories: BTreeSet<String> = children.iter().chain(loose.values()).flat_map(ChildAccumulator::categories).collect();
    let mut items: Vec<ContentItem> = children.into_iter().map(|child| child.into_item(true)).collect();
    for (kind, accumulator) in loose {
        let mut item = accumulator.into_item(false);
        item.name = format!("Loose files: {}", kind_label(kind).to_lowercase());
        item.kind = kind.into();
        item.safety = safety_for_kind(kind).into();
        item.source = "extension".into();
        item.reason = "Files stored directly in this folder, grouped by extension. They cannot be selected individually.".into();
        items.push(item);
    }
    categories.extend(items.iter().map(|item| item.kind.clone()));
    items.sort_by(|left, right| right.size_bytes.cmp(&left.size_bytes).then_with(|| left.name.cmp(&right.name)));
    if items.len() > MAX_REPORTED_ITEMS {
        let rest = items.split_off(MAX_REPORTED_ITEMS - 1);
        let worst = rest.iter().max_by_key(|item| safety_rank(&item.safety)).map(|item| item.safety.clone()).unwrap_or_else(|| UNKNOWN.into());
        items.push(ContentItem {
            name: format!("{} smaller items", rest.len()),
            is_directory: false,
            kind: "unknown".into(),
            safety: worst,
            size_bytes: rest.iter().map(|item| item.size_bytes).sum(),
            file_count: rest.iter().map(|item| item.file_count).sum(),
            newest_modified_unix: rest.iter().filter_map(|item| item.newest_modified_unix).max(),
            reason: "Smaller items grouped for readability; the most restrictive safety class among them is shown.".into(),
            source: "grouped".into(),
        });
    }
    let mut extension_stats: Vec<ExtensionStat> = extensions.into_iter()
        .map(|(extension, (size_bytes, file_count))| ExtensionStat { extension, size_bytes, file_count })
        .collect();
    extension_stats.sort_by(|left, right| right.size_bytes.cmp(&left.size_bytes));
    extension_stats.truncate(8);
    ContentProfile {
        items,
        extensions: extension_stats,
        executable_count,
        database_count,
        large_file_count,
        large_file_bytes,
        untracked_children,
        categories: categories.into_iter().collect(),
    }
}

/// Most restrictive safety across content items. An empty profile is unknown.
pub fn overall_safety(profile: &ContentProfile) -> &'static str {
    let mut worst = None::<&'static str>;
    for item in &profile.items {
        let safety = match item.safety.as_str() {
            SAFE => SAFE,
            LIKELY_SAFE => LIKELY_SAFE,
            REVIEW => REVIEW,
            PRESERVE => PRESERVE,
            _ => UNKNOWN,
        };
        if worst.is_none_or(|current| safety_rank(safety) > safety_rank(current)) {
            worst = Some(safety);
        }
    }
    worst.unwrap_or(UNKNOWN)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_names_map_to_expected_safety() {
        assert_eq!(kind_for_directory_name("GPUCache").unwrap().0, "shader_cache");
        assert_eq!(kind_for_directory_name("Code Cache").unwrap().0, "cache");
        assert_eq!(kind_for_directory_name("SaveGames").unwrap().0, "save_game");
        assert_eq!(kind_for_directory_name("Session Storage").unwrap().0, "session_data");
        assert_eq!(kind_for_directory_name("app-1.4.2").unwrap().0, "application_binaries");
        assert!(kind_for_directory_name("Random Folder").is_none());
        assert_eq!(kind_for_directory_name("Downloads").unwrap().1, Some(REVIEW));
    }

    #[test]
    fn user_data_markers_escalate_even_named_caches() {
        let mut child = ChildAccumulator::new("Profiles");
        child.add_file("json", 100, None);
        child.add_directory_name("SaveGames");
        let item = child.into_item(true);
        assert_eq!(item.safety, PRESERVE);

        let mut cache = ChildAccumulator::new("Cache");
        cache.add_file("sav", 100, None);
        assert_eq!(cache.into_item(true).safety, PRESERVE, "a cache name cannot hide save files");
        let mut thumbnails = ChildAccumulator::new("Cache");
        thumbnails.add_file("png", 100, None);
        assert_eq!(thumbnails.into_item(true).safety, SAFE, "cached images remain regenerable");
    }

    #[test]
    fn dominant_extension_classifies_unknown_folder() {
        let mut child = ChildAccumulator::new("abc");
        child.add_file("log", 900, None);
        child.add_file("bin", 100, None);
        let item = child.into_item(true);
        assert_eq!(item.kind, "log");
        assert_eq!(item.safety, SAFE);
    }

    #[test]
    fn overall_safety_is_most_restrictive() {
        let profile = ContentProfile { items: vec![
            ContentItem { safety: SAFE.into(), ..Default::default() },
            ContentItem { safety: REVIEW.into(), ..Default::default() },
        ], ..Default::default() };
        assert_eq!(overall_safety(&profile), REVIEW);
        assert_eq!(overall_safety(&ContentProfile::default()), UNKNOWN);
    }
}
