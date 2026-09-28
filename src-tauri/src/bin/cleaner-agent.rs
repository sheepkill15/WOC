#[tokio::main]
async fn main() {
    if let Err(error) = windows_orphan_cleaner::run_agent().await {
        eprintln!("Cleaner agent failed: {error}");
        std::process::exit(1);
    }
}
