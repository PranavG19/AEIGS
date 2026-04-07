//! Main entry point for the Schema-Grammar Pipeline Daemon

use aegis_schema_grammar_daemon::SchemaGrammarDaemon;
use clap::Parser;
use std::path::PathBuf;
use tracing_subscriber;

#[derive(Parser)]
#[clap(name = "aegis-schema-grammar-daemon", version = "0.1.0")]
struct Args {
    #[clap(long, default_value = "schema_001")]
    id: String,
    
    #[clap(long, default_value = "/tmp/aegis_agents/schema_grammar_001")]
    workspace: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    
    let args = Args::parse();
    
    let config = aegis_schema_grammar_daemon::DaemonConfig {
        daily_schema_target: 100,
        fuzz_input_target: 1000,
        accuracy_threshold: 0.80,
        max_processing_time_ms: 100,
    };
    
    let daemon = SchemaGrammarDaemon::new(
        args.id,
        args.workspace,
        config,
    );
    
    daemon.run().await
}