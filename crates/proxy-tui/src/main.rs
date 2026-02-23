use clap::Parser;

#[derive(Parser)]
#[command(name = "aegis-proxy-tui", about = "Interactive proxy with TUI")]
pub struct Args {
    #[arg(long, default_value = "127.0.0.1:8080", help = "Proxy listen address")]
    pub listen: String,

    #[arg(long, help = "Import endpoints from a knowledge graph DB")]
    pub import_graph: Option<String>,

    #[arg(long, help = "Path to proxy SQLite database")]
    pub db: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    println!("AEGIS Proxy TUI");
    println!("  Listen: {}", args.listen);
    if let Some(db) = &args.db {
        println!("  DB: {db}");
    }
    if let Some(graph) = &args.import_graph {
        println!("  Import graph: {graph}");
    }
    Ok(())
}
