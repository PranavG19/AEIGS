use aegis_daemon_launcher::{DaemonLauncher, DaemonType};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber;

#[derive(Parser)]
#[command(name = "aegis-daemon-launcher")]
#[command(about = "Launch specialized autonomous daemons for high-ROI AEGIS modules")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Launch all four specialized daemons
    LaunchAll {
        /// Base working directory for all daemons
        #[arg(short, long, default_value = "/tmp/aegis_daemons")]
        work_dir: PathBuf,
        
        /// Target URL to scan/attack
        #[arg(short, long, default_value = "http://127.0.0.1:8080")]
        target: String,
        
        /// Enable verbose logging
        #[arg(short, long)]
        verbose: bool,
    },
    
    /// Launch a specific daemon type
    Launch {
        /// Type of daemon to launch
        #[arg(value_enum)]
        daemon_type: DaemonTypeEnum,
        
        /// Working directory for the daemon
        #[arg(short, long, default_value = "/tmp/aegis_daemon_single")]
        work_dir: PathBuf,
        
        /// Target URL to scan/attack
        #[arg(short, long, default_value = "http://127.0.0.1:8080")]
        target: String,
        
        /// Enable verbose logging
        #[arg(short, long)]
        verbose: bool,
    },
    
    /// Stop all running daemons
    StopAll {
        /// Base working directory where daemons were launched
        #[arg(short, long, default_value = "/tmp/aegis_daemons")]
        work_dir: PathBuf,
    },
}

#[derive(clap::ValueEnum, Clone)]
enum DaemonTypeEnum {
    GhostProtocol,
    CachePoisoning,
    SchemaGrammar,
    H2Continuation,
}

impl From<DaemonTypeEnum> for DaemonType {
    fn from(daemon_type: DaemonTypeEnum) -> Self {
        match daemon_type {
            DaemonTypeEnum::GhostProtocol => DaemonType::GhostProtocol,
            DaemonTypeEnum::CachePoisoning => DaemonType::CachePoisoning,
            DaemonTypeEnum::SchemaGrammar => DaemonType::SchemaGrammar,
            DaemonTypeEnum::H2Continuation => DaemonType::H2Continuation,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    
    let cli = Cli::parse();
    
    match cli.command {
        Commands::LaunchAll { work_dir, target, verbose } => {
            tracing::info!("Launching all daemons...");
            
            let launcher = DaemonLauncher::new(work_dir);
            let launched = launcher.launch_all_optimal().await?;
            
            tracing::info!("Successfully launched {} daemons:", launched.len());
            for daemon_id in launched {
                tracing::info!("  - {}", daemon_id);
            }
            
            // Keep the launcher running
            tokio::signal::ctrl_c().await?;
            tracing::info!("Shutting down daemons...");
            launcher.stop_all().await?;
        }
        
        Commands::Launch { daemon_type, work_dir, target, verbose } => {
            tracing::info!("Launching {} daemon...", daemon_type.into());
            
            let launcher = DaemonLauncher::new(work_dir.clone());
            
            // Create a single daemon config
            let config = aegis_daemon_launcher::daemon_config::DaemonConfig {
                id: format!("single-{}", uuid::Uuid::new_v4().to_string()[..8].to_string()),
                daemon_type: daemon_type.into(),
                target_url: target,
                work_dir,
                verbose,
                max_concurrent: 5,
                custom_params: serde_json::json!({}),
            };
            
            match launcher.launch_daemon(config).await {
                Ok(daemon_id) => {
                    tracing::info!("Successfully launched daemon: {}", daemon_id);
                }
                Err(e) => {
                    tracing::error!("Failed to launch daemon: {}", e);
                    std::process::exit(1);
                }
            }
        }
        
        Commands::StopAll { work_dir } => {
            tracing::info!("Stopping all daemons...");
            let launcher = DaemonLauncher::new(work_dir);
            launcher.stop_all().await?;
            tracing::info!("All daemons stopped.");
        }
    }
    
    Ok(())
}