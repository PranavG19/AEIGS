//! Main entry point for the HTTP/2 CONTINUATION Flood Daemon

use aegis_h2_continuation_daemon::Http2FloodDaemon;
use clap::Parser;
use std::path::PathBuf;
use tracing_subscriber;

#[derive(Parser)]
#[clap(name = "aegis-h2-continuation-daemon", version = "0.1.0")]
struct Args {
    #[clap(long, default_value = "http2_001")]
    id: String,
    
    #[clap(long, default_value = "/tmp/aegis_agents/http2_flood_001")]
    workspace: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    
    let args = Args::parse();
    
    let config = aegis_h2_continuation_daemon::DaemonConfig {
        target_frame_rate: 10000,
        success_rate_threshold: 0.95,
        connection_drop_limit: 0.01,
        high_impact_targets: vec![
            "/api/http2".to_string(),
            "/stream/data".to_string(),
            "/realtime/events".to_string(),
        ],
    };
    
    let daemon = Http2FloodDaemon::new(
        args.id,
        args.workspace,
        config,
    );
    
    daemon.run().await
}