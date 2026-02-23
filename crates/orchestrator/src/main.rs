use aegis_orchestrator::attest::{parse_attest_args, run_attest};
use aegis_orchestrator::pipeline::run_scan;
use aegis_orchestrator::run_recon_standalone;
use aegis_orchestrator::scan_config::ScanConfig;
use aegis_orchestrator::update_db::{parse_update_db_args, run_update_db};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() > 1 && args[1] == "recon" {
        run_recon_command(&args[2..]);
        return;
    }

    if args.len() > 1 && args[1] == "attest" {
        run_attest_command(&args[2..]);
        return;
    }

    if args.len() > 1 && args[1] == "update-db" {
        run_update_db_command(&args[2..]);
        return;
    }

    let config = ScanConfig::parse_and_apply_preset();

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
            if let Some(ref path) = summary.telemetry_path {
                println!("Telemetry: {path}");
            }
            if let Some(verified) = summary.audit_verified {
                if verified {
                    println!("Audit log integrity: verified");
                } else {
                    eprintln!("WARNING: Audit log integrity check FAILED");
                }
            }
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

    match run_recon_standalone(&source_dir, None) {
        Ok(ops) => {
            println!("Recon complete: {} operations discovered", ops.len());
        }
        Err(e) => {
            eprintln!("Recon failed: {e}");
            std::process::exit(1);
        }
    }
}

fn run_attest_command(args: &[String]) {
    match parse_attest_args(args) {
        Ok(attest_args) => match run_attest(&attest_args) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("Attestation failed: {e}");
                std::process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("Attestation failed: {e}");
            std::process::exit(1);
        }
    }
}

fn run_update_db_command(args: &[String]) {
    match parse_update_db_args(args) {
        Ok(update_args) => match run_update_db(&update_args) {
            Ok(summary) => {
                println!(
                    "Vulnerability database updated: {} new records ({} total)",
                    summary.new_records, summary.total_records
                );
                println!("Queried {} packages", summary.packages_queried);
                println!("Database: {}", summary.db_path.display());
            }
            Err(e) => {
                eprintln!("Update failed: {e}");
                std::process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("Update failed: {e}");
            std::process::exit(1);
        }
    }
}
