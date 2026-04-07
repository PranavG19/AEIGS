//! Main entry point for the Ghost Protocol Daemon

use aegis_ghost_protocol_daemon::{GhostProtocolDaemon, DaemonConfig};
use clap::Parser;
use std::path::PathBuf;
use tracing_subscriber;

#[derive(Parser)]
#[clap(name = "aegis-ghost-protocol-daemon", version = "0.1.0")]
struct Args {
    #[clap(long, default_value = "ghost_001")]
    id: String,
    
    #[clap(long, default_value = "/tmp/aegis_agents/ghost_protocol_001")]
    workspace: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    
    let args = Args::parse();
    
    let config = DaemonConfig {
        target_modules: vec![
            "header_transformer".to_string(),
            "encoding_transformer".to_string(),
            "timing_controller".to_string(),
            "tls_fingerprinter".to_string(),
            "session_manager".to_string(),
        ],
        success_threshold: 0.85,
        daily_payload_target: 1000,
        false_positive_limit: 0.05,
    };
    
    let daemon = GhostProtocolDaemon::new(
        args.id,
        args.workspace,
        config,
    );
    
    daemon.run().await
}