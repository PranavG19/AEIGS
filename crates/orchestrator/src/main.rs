use aegis_orchestrator::pipeline::{collect_recon_ops, run_scan};
use aegis_orchestrator::scan_config::ScanConfig;
use clap::Parser;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() > 1 && args[1] == "recon" {
        run_recon_command(&args[2..]);
        return;
    }

    let config = ScanConfig::parse();

    if config.verbose {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .init();
    }

    match run_scan(config).await {
        Ok(summary) => {
            println!(
                "Scan complete: {} findings across {} phases",
                summary.total_findings, summary.phases_completed
            );
            println!("SARIF report: {}", summary.sarif_path);
        }
        Err(e) => {
            eprintln!("Scan failed: {e}");
            std::process::exit(1);
        }
    }
}

fn run_recon_command(args: &[String]) {
    let source_dir = args
        .windows(2)
        .find(|w| w[0] == "--source-dir")
        .map(|w| std::path::PathBuf::from(&w[1]));

    match collect_recon_ops(&source_dir) {
        Ok(ops) => {
            println!("Recon complete: {} operations discovered", ops.len());
        }
        Err(e) => {
            eprintln!("Recon failed: {e}");
            std::process::exit(1);
        }
    }
}
