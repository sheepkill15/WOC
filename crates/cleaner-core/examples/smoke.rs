use cleaner_core::{installed_applications, scan};
use std::sync::atomic::{AtomicBool, Ordering};

fn main() {
    let inventory = installed_applications();
    println!("Installed applications: {}", inventory.applications.len());
    for warning in &inventory.warnings { println!("Inventory warning: {warning}"); }
    let cancel = AtomicBool::new(false);
    let mut seen = 0;
    let summary = scan(&inventory.applications, &cancel, |result| {
        println!("{} | {} bytes | {} | {} skipped", result.path, result.size_bytes,
            result.owner.as_ref().map(|app| app.name.as_str()).unwrap_or("unknown"), result.skipped_entries);
        seen += 1;
        if seen >= 5 { cancel.store(true, Ordering::Relaxed); }
    }, |_| {});
    println!("Inspected {} directories; canceled: {}", summary.directories, summary.canceled);
}
