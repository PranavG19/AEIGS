//! Main entry point for the Cache Poisoning Daemon

use aegis_cache_poisoning_daemon::CachePoisoningDaemon;
use clap::Parser;
use std::path::PathBuf;
use tracing_subscriber;

#[derive(Parser)]
#[clap(name = "aegis-cache-poisoning-daemon", version = "0.1.0")]
struct Args {
    #[clap(long, default_value = "cache_001")]
    id: String,
    
    #[clap(long, default_value = "/tmp/aegis_agents/cache_poisoning_001")]
    workspace: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    
    let args = Args::parse();
    
    let config = aegis_cache_poisoning_daemon::DaemonConfig {
        target_success_rate: 0.90,
        daily_vector_target: 500,
        false_positive_limit: 0.02,
        high_impact_targets: vec![
            "/api/cache".to_string(),
            "/cdn/assets".to_string(),
            "/proxy/endpoint".to_string(),
        ],
    };
    
    let daemon = CachePoisoningDaemon::new(
        args.id,
        args.workspace,
        config,
    );
    
    daemon.run().await
}