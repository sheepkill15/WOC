/// How a known location should be treated by safety analysis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocationClass {
    /// Ordinary application data with a known identity.
    AppData,
    /// Windows-managed storage. Never a cleanup target.
    System,
    /// Runtime or component shared by many applications (spec §19).
    SharedRuntime,
    /// Regenerable package-manager or build-tool cache.
    ToolCache,
    /// Storage likely to hold user files (WSL disks, save folders).
    UserData,
}

impl LocationClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AppData => "app_data",
            Self::System => "system",
            Self::SharedRuntime => "shared_runtime",
            Self::ToolCache => "tool_cache",
            Self::UserData => "user_data",
        }
    }
}

pub struct KnownLocation {
    pub label: &'static str,
    pub description: &'static str,
    pub possible_former: bool,
    pub class: LocationClass,
    /// Content category applied to otherwise unclassified items inside this location.
    pub content_kind: Option<&'static str>,
}

pub fn lookup(root: &str, name: &str) -> Option<KnownLocation> {
    use LocationClass::*;
    let key = name.to_ascii_lowercase();
    let (label, description, possible_former, class, content_kind) = match (root, key.as_str()) {
        ("Local", "wsl") => ("Windows Subsystem for Linux", "WSL distribution storage can contain entire Linux filesystems and user files.", false, UserData, None),
        ("Local" | "LocalLow", "temp") => ("Windows temporary data", "Shared temporary storage can contain files still in use.", false, System, Some("temporary")),
        ("ProgramData", "package cache") => ("Application installer package cache", "Installers may need these packages for repair or uninstall.", false, SharedRuntime, Some("installer_cache")),
        ("Local", "pnpm" | "pnpm-cache" | "pnpm-state") => ("pnpm", "Shared JavaScript package-manager data, not one installed application's private data.", false, ToolCache, Some("cache")),
        ("Local" | "Roaming", "nuget") => ("NuGet", "Shared .NET package-manager data.", false, ToolCache, Some("cache")),
        ("Local", "npm-cache") | ("Roaming", "npm") => ("npm", "Shared JavaScript package-manager data.", false, ToolCache, Some("cache")),
        ("Local", "pub") => ("Dart Pub", "Shared Dart and Flutter package-manager data.", false, ToolCache, Some("cache")),
        ("Local", "pip") => ("Python pip", "Shared Python package-manager data.", false, ToolCache, Some("cache")),
        ("Local", "yarn") => ("Yarn", "Shared JavaScript package-manager cache.", false, ToolCache, Some("cache")),
        ("Local", "gradle") => ("Gradle", "Build-tool cache data.", false, ToolCache, Some("cache")),
        ("Local", "go-build") => ("Go build cache", "Regenerable Go compiler cache.", false, ToolCache, Some("cache")),
        ("Local", "ms-playwright") => ("Playwright browsers", "Downloaded browser builds for Playwright tests; tools download them again when needed.", false, ToolCache, Some("downloaded_asset")),
        ("Local", "docker") | ("Roaming", "docker" | "docker desktop") => ("Docker", "Docker Desktop data can include container images and volumes with user data.", false, UserData, None),
        ("Local", "unity") | ("LocalLow", "unity") => ("Unity", "Unity editor and player data; may contain caches and licensing data.", false, AppData, None),
        ("Local", "unrealengine") => ("Unreal Engine", "Unreal Engine derived data cache and editor settings.", false, AppData, None),
        ("Local", "crashdumps") => ("Windows Error Reporting crash dumps", "Crash dumps may contain application or user data.", false, AppData, Some("crash_dump")),
        ("Local", "d3dscache") => ("Direct3D shader cache", "Windows graphics cache shared by applications and drivers.", false, SharedRuntime, Some("shader_cache")),
        ("Local" | "Roaming", "electron") => ("Electron", "Shared Electron framework data; no single application owner is implied.", false, SharedRuntime, None),
        ("Local", "electron-builder") => ("electron-builder", "Development-tool cache and build data.", false, ToolCache, Some("cache")),
        ("LocalLow", "unfrozen") => ("Unfrozen game data", "This publisher directory may contain game saves and settings.", false, UserData, None),
        ("Roaming", "easyanticheat") | ("ProgramFiles" | "ProgramFilesX86", "easyanticheat" | "easyanticheat_eos") => ("Easy Anti-Cheat", "Shared game anti-cheat data; installed games may still depend on it.", false, SharedRuntime, None),
        ("ProgramFiles" | "ProgramFilesX86" | "ProgramData", "battleye" | "common battleye") => ("BattlEye", "Shared game anti-cheat component.", false, SharedRuntime, None),
        ("Roaming", "amd") => ("AMD application data", "AMD software data; a driver or related component may still use it.", false, AppData, None),
        ("Local", "amdsoftwareinstaller") => ("AMD Software Installer", "Installer data may be needed for repair or updates.", false, AppData, Some("installer_cache")),
        ("Local", "comms") => ("Windows communications data", "Windows-managed communication and account data.", false, System, None),
        ("Local", "connecteddevicesplatform" | "microsoft" | "publishers" | "virtualstore" | "d3dscache_" | "history" | "packages") => ("Windows-managed data", "Windows and built-in components manage this folder.", false, System, None),
        ("Roaming", "microsoft") => ("Windows-managed data", "Windows and built-in components manage this folder, including credentials and Start Menu data.", false, System, None),
        ("ProgramData", "microsoft" | "packages" | "regid" | "windowsholographicdevices" | "device stage" | "ssh" | "usoprivate" | "usoshared" | "softwaredistribution" | "whesvc") => match key.as_str() {
            "softwaredistribution" => ("Windows Update storage", "Windows manages this directory for update download, installation, and servicing state. Do not treat it as ordinary application leftovers.", false, System, None),
            "usoprivate" | "usoshared" => ("Windows Update Orchestrator", "Update Orchestrator service state and logs are Windows-managed and may be required for update operations.", false, System, None),
            "whesvc" => ("Windows Health and Optimized Experiences", "Windows health and reliability summary data managed by the whesvc service.", false, System, None),
            "ssh" => ("OpenSSH machine configuration", "Machine-wide OpenSSH data may include host configuration and private host keys; preserve it.", false, System, None),
            _ => ("Windows-managed data", "Windows and built-in components manage this folder.", false, System, None),
        },
        ("ProgramData", "windows app certification kit") => ("Windows App Certification Kit", "Windows development-tool data.", false, AppData, None),
        ("ProgramData", name) if name.starts_with("regid.") => ("Software identification records", "This registration identifier directory stores software-identification tags used for inventory or licensing; it is not deletion evidence.", false, System, None),
        ("ProgramData" | "ProgramFiles" | "ProgramFilesX86", "nvidia gpu computing toolkit") => ("NVIDIA CUDA toolkit", "Shared GPU compute runtime used by many applications.", false, SharedRuntime, None),
        ("Local" | "Roaming", "jetbrains") => ("JetBrains", "JetBrains IDE data; version folders are inspected individually.", false, AppData, None),
        // Program Files entries that Windows or shared runtimes manage.
        ("ProgramFiles" | "ProgramFilesX86", "common files" | "windows defender" | "windows defender advanced threat protection" | "windows mail" | "windows media player"
            | "windows multimedia platform" | "windows nt" | "windows photo viewer" | "windows portable devices" | "windows security" | "windows sidebar"
            | "windowsapps" | "windowspowershell" | "modifiablewindowsapps" | "internet explorer" | "uninstall information" | "reference assemblies"
            | "microsoft update health tools" | "microsoft.net" | "msbuild" | "windows kits" | "microsoft sdks" | "microsoft visual studio"
            | "dotnet" | "iis" | "iis express" | "microsoft sql server" | "package cache" | "microsoft office" | "microsoft office 15" | "microsoft onedrive"
            | "microsoft" | "microsoft vs code" | "powershell" | "windows sdks") => match key.as_str() {
            "dotnet" | "microsoft.net" | "reference assemblies" | "msbuild" | "microsoft sdks" | "windows kits" | "windows sdks" | "common files" | "package cache" | "powershell" =>
                ("Shared runtime or SDK", "Shared runtimes, SDKs and common components are used by many applications and are excluded from orphan analysis.", false, SharedRuntime, None),
            _ => ("Windows or Microsoft component", "This Program Files entry belongs to Windows or a Microsoft product and is managed by its installer.", false, System, None),
        },
        ("ProgramFiles" | "ProgramFilesX86", "java" | "python" | "nodejs" | "git" | "vulkanrt" | "vulkansdk" | "directx" | "openal" | "microsoft visual c++ redistributable" | "microsoft xna" | "physx") =>
            ("Shared runtime", "Language runtimes and graphics components can be used by many applications.", false, SharedRuntime, None),
        // Developer folders in the user profile (deep scan only).
        ("UserProfile", ".gradle") => ("Gradle user home", "Gradle caches and wrapper distributions; caches are regenerable but builds download them again.", false, ToolCache, Some("cache")),
        ("UserProfile", ".m2") => ("Maven repository", "Local Maven artifact repository; regenerable but may include locally installed artifacts.", false, ToolCache, Some("downloaded_asset")),
        ("UserProfile", ".cargo") => ("Rust Cargo home", "Contains the registry cache and installed Cargo binaries; binaries are not regenerable automatically.", false, ToolCache, None),
        ("UserProfile", ".rustup") => ("Rust toolchains", "Installed Rust toolchains managed by rustup.", false, SharedRuntime, None),
        ("UserProfile", ".nuget") => ("NuGet packages", "Global NuGet package folder; restored again on build.", false, ToolCache, Some("downloaded_asset")),
        ("UserProfile", ".npm") => ("npm cache", "npm cache data; regenerable.", false, ToolCache, Some("cache")),
        ("UserProfile", ".yarn") => ("Yarn", "Yarn cache and global data.", false, ToolCache, Some("cache")),
        ("UserProfile", ".pnpm-store") => ("pnpm store", "Content-addressable pnpm package store; regenerable.", false, ToolCache, Some("cache")),
        ("UserProfile", ".android") => ("Android SDK user data", "Emulator images (avd) and debug keys; debug keystores and emulator state may be valuable.", false, UserData, None),
        ("UserProfile", ".conda" | "anaconda3" | "miniconda3") => ("Conda", "Conda environments and package cache; environments may be referenced by projects.", false, SharedRuntime, None),
        ("UserProfile", ".docker") => ("Docker CLI configuration", "Docker CLI settings and credentials references.", false, UserData, None),
        ("UserProfile", ".vscode") => ("VS Code extensions", "Installed VS Code extensions.", false, AppData, Some("plugin")),
        ("UserProfile", ".cache") => ("Shared tool cache", "Generic cache directory used by cross-platform developer tools.", false, ToolCache, Some("cache")),
        ("UserProfile", ".ivy2" | ".sbt" | ".coursier") => ("JVM build caches", "Ivy/sbt/Coursier caches; regenerable.", false, ToolCache, Some("cache")),
        ("UserProfile", ".dotnet") => (".NET user data", ".NET tool installs and first-run data.", false, ToolCache, None),
        ("UserProfile", ".nvm" | ".volta") => ("Node version manager", "Installed Node.js versions managed by a version manager.", false, SharedRuntime, None),
        ("Roaming", "image-line") => ("Image-Line", "Known Image-Line application data; no matching installed product was found in this inventory.", true, AppData, None),
        ("Local", "aion2") => ("AION 2", "Known AION 2 application data; no matching installed product was found in this inventory.", true, AppData, None),
        _ => return None,
    };
    Some(KnownLocation { label, description, possible_former, class, content_kind })
}

/// Developer folders inspected in the user profile during a deep scan.
pub const USER_PROFILE_DEVELOPER_FOLDERS: [&str; 20] = [
    ".gradle", ".m2", ".cargo", ".rustup", ".nuget", ".npm", ".yarn", ".pnpm-store", ".android", ".conda",
    "anaconda3", "miniconda3", ".docker", ".vscode", ".cache", ".ivy2", ".sbt", ".coursier", ".dotnet", ".nvm",
];
