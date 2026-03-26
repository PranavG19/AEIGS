use clap::Parser;
use tracing_subscriber::EnvFilter;

mod dashboard;
mod export_api;
mod graph_api;
mod scan_bridge;
mod server;
mod state;

#[cfg(test)]
#[path = "main_test.rs"]
mod main_test;

/// AEGIS Web UI — Real-time attack graph dashboard
#[derive(Parser, Debug, Clone)]
#[command(name = "aegis-web-ui", about = "Live attack graph visualization")]
pub struct CliArgs {
    /// Target URL to scan
    #[arg(long)]
    pub target: Option<String>,

    /// Port to serve the dashboard on
    #[arg(long, default_value = "7777")]
    pub port: u16,

    /// Scan profile: quick, thorough, paranoid
    #[arg(long, default_value = "quick")]
    pub profile: String,

    /// Run in demo mode with simulated scan data
    #[arg(long)]
    pub demo: bool,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let args = CliArgs::parse();

    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(async move {
        let addr = format!("0.0.0.0:{}", args.port);
        tracing::info!("AEGIS Web UI starting on http://localhost:{}", args.port);

        if args.demo {
            tracing::info!("Running in DEMO mode — simulated scan data");
        } else if let Some(ref target) = args.target {
            tracing::info!("Target: {}", target);
        } else {
            tracing::warn!("No --target specified and --demo not set. Use --demo for simulated data.");
        }

        let app = server::build_router(args.clone());

        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .expect("failed to bind address");
        tracing::info!("Dashboard ready at http://localhost:{}", args.port);
        axum::serve(listener, app).await.expect("server error");
    });
}
