pub struct KnownLocation {
    pub label: &'static str,
    pub description: &'static str,
    pub possible_former: bool,
}

pub fn lookup(root: &str, name: &str) -> Option<KnownLocation> {
    let key = name.to_ascii_lowercase();
    let (label, description, possible_former) = match (root, key.as_str()) {
        ("Local", "wsl") => ("Windows Subsystem for Linux", "WSL distribution storage can contain entire Linux filesystems and user files.", false),
        ("Local" | "LocalLow", "temp") => ("Windows temporary data", "Shared temporary storage can contain files still in use.", false),
        ("ProgramData", "package cache") => ("Application installer package cache", "Installers may need these packages for repair or uninstall.", false),
        ("Local", "pnpm" | "pnpm-cache" | "pnpm-state") => ("pnpm", "Shared JavaScript package-manager data, not one installed application's private data.", false),
        ("Local" | "Roaming", "nuget") => ("NuGet", "Shared .NET package-manager data.", false),
        ("Local", "npm-cache") | ("Roaming", "npm") => ("npm", "Shared JavaScript package-manager data.", false),
        ("Local", "pub") => ("Dart Pub", "Shared Dart and Flutter package-manager data.", false),
        ("Local", "pip") => ("Python pip", "Shared Python package-manager data.", false),
        ("Local", "crashdumps") => ("Windows Error Reporting crash dumps", "Crash dumps may contain application or user data.", false),
        ("Local", "d3dscache") => ("Direct3D shader cache", "Windows graphics cache shared by applications and drivers.", false),
        ("Local" | "Roaming", "electron") => ("Electron", "Shared Electron framework data; no single application owner is implied.", false),
        ("Local", "electron-builder") => ("electron-builder", "Development-tool cache and build data.", false),
        ("LocalLow", "unfrozen") => ("Unfrozen game data", "This publisher directory may contain game saves and settings.", false),
        ("Roaming", "easyanticheat") => ("Easy Anti-Cheat", "Shared game anti-cheat data; installed games may still depend on it.", false),
        ("Roaming", "amd") => ("AMD application data", "AMD software data; a driver or related component may still use it.", false),
        ("Local", "amdsoftwareinstaller") => ("AMD Software Installer", "Installer data may be needed for repair or updates.", false),
        ("Local", "comms") => ("Windows communications data", "Windows-managed communication and account data.", false),
        ("ProgramData", "windows app certification kit") => ("Windows App Certification Kit", "Windows development-tool data.", false),
        ("ProgramData", "softwaredistribution") => ("Windows Update storage", "Windows manages this directory for update download, installation, and servicing state. Do not treat it as ordinary application leftovers.", false),
        ("ProgramData", "usoprivate" | "usoshared") => ("Windows Update Orchestrator", "Update Orchestrator service state and logs are Windows-managed and may be required for update operations.", false),
        ("ProgramData", "whesvc") => ("Windows Health and Optimized Experiences", "Windows health and reliability summary data managed by the whesvc service.", false),
        ("ProgramData", "ssh") => ("OpenSSH machine configuration", "Machine-wide OpenSSH data may include host configuration and private host keys; preserve it.", false),
        ("ProgramData", name) if name.starts_with("regid.") => ("Software identification records", "This registration identifier directory stores software-identification tags used for inventory or licensing; it is not deletion evidence.", false),
        ("Roaming", "image-line") => ("Image-Line", "Known Image-Line application data; no matching installed product was found in this inventory.", true),
        ("Local", "aion2") => ("AION 2", "Known AION 2 application data; no matching installed product was found in this inventory.", true),
        _ => return None,
    };
    Some(KnownLocation { label, description, possible_former })
}
