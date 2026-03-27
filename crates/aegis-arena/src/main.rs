use aegis_arena::arena_controller::{
    format_duration, CycleOutcome, InfiniteConfig, InfiniteController, InfiniteState, SpeedPreset,
};
use clap::Parser;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// AEGIS Arena — Adversarial Red vs Blue CTF platform.
#[derive(Parser, Debug)]
#[command(name = "aegis-arena", about = "Infinite adversarial evolution arena")]
struct Cli {
    /// Run in infinite mode (no round limit).
    #[arg(long)]
    infinite: bool,

    /// Resume from saved state.
    #[arg(long)]
    resume: bool,

    /// Speed preset: "normal" or "fast".
    #[arg(long, default_value = "normal")]
    speed: String,

    /// Verbose output every cycle.
    #[arg(long)]
    watch: bool,

    /// Port for the target server.
    #[arg(long, default_value = "9999")]
    port: u16,

    /// Workspace directory.
    #[arg(long, default_value = "/tmp/aegis-arena")]
    workspace: String,

    /// LLM model to use.
    #[arg(long, default_value = "sonnet")]
    model: String,
}

fn main() {
    let cli = Cli::parse();

    if cli.infinite {
        let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
        rt.block_on(run_infinite_mode(cli));
    } else {
        println!("aegis-arena: use --infinite to start infinite mode");
        println!("  aegis-arena --infinite                    # run forever");
        println!("  aegis-arena --infinite --resume           # resume from saved state");
        println!("  aegis-arena --infinite --speed fast       # shorter timeouts");
        println!("  aegis-arena --infinite --watch            # verbose output every cycle");
    }
}

async fn run_infinite_mode(cli: Cli) {
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = Arc::clone(&shutdown);

    // Ctrl+C handler
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        shutdown_clone.store(true, Ordering::Relaxed);
    });

    let speed = match cli.speed.as_str() {
        "fast" => SpeedPreset::Fast,
        _ => SpeedPreset::Normal,
    };

    let timeout = match speed {
        SpeedPreset::Fast => Duration::from_secs(60),
        SpeedPreset::Normal => Duration::from_secs(120),
    };

    let config = InfiniteConfig {
        timeout_per_turn: timeout,
        port: cli.port,
        model: cli.model,
        workspace: cli.workspace.clone().into(),
        resume: cli.resume,
        min_cycle_duration: Duration::from_secs(2),
        max_cycle_duration: Duration::from_secs(600),
        endpoint_escalation_interval: 10,
        capability_escalation_interval: 25,
        speed,
        watch: cli.watch,
    };

    // Try to resume from saved state
    let state_path = std::path::PathBuf::from(&cli.workspace).join("arena_result.json");
    let mut controller = if cli.resume {
        if let Some(state) = InfiniteState::load(&state_path).await {
            println!("Resuming from cycle {}...", state.cycle);
            InfiniteController::with_state(config, state, Arc::clone(&shutdown))
        } else {
            println!("No saved state found, starting fresh.");
            InfiniteController::new(config, Arc::clone(&shutdown))
        }
    } else {
        InfiniteController::new(config, Arc::clone(&shutdown))
    };

    let start = Instant::now();
    print_header();

    // Real opencode runner
    let runner = RealOpencodeRunner;

    loop {
        if controller.should_shutdown() {
            break;
        }

        let result = controller.run_cycle(&runner).await;
        match result {
            Some(cycle_result) => {
                print_dashboard(controller.state(), &cycle_result.outcome, start.elapsed());
                if cli.watch {
                    print_cycle_detail(&cycle_result.outcome, cycle_result.cycle);
                }
            }
            None => break,
        }
    }

    // Final summary
    println!("{}", controller.final_summary());
}

fn print_header() {
    println!();
    println!("  ═══ AEGIS ARENA — INFINITE MODE ═══");
    println!();
}

fn print_dashboard(state: &InfiniteState, outcome: &CycleOutcome, uptime: Duration) {
    let maturity = state.security_maturity();
    let uptime_str = format_duration(uptime);

    // Clear line and print compact dashboard
    print!("\r\x1b[2K");
    let outcome_icon = match outcome {
        CycleOutcome::RedCapture => "FLAG!",
        CycleOutcome::RedBlocked => "BLOCK",
        CycleOutcome::Stalemate => "STALE",
    };

    println!(
        "  Cycle {:>5} | {} | RED: {:>3} flags {:>3} blocked | BLUE: {:>3} blocks {:>3} bypassed | Maturity: {:>3.0} | Esc: {} | {}",
        state.cycle,
        uptime_str,
        state.red_flags,
        state.red_blocked,
        state.blue_blocks,
        state.blue_bypassed,
        maturity,
        state.escalation_level,
        outcome_icon,
    );
}

fn print_cycle_detail(outcome: &CycleOutcome, cycle: usize) {
    match outcome {
        CycleOutcome::RedCapture => {
            println!("  --> Cycle {cycle}: Red captured the flag. Blue must respond.");
        }
        CycleOutcome::RedBlocked => {
            println!("  --> Cycle {cycle}: Red was blocked. Blue's defenses hold.");
        }
        CycleOutcome::Stalemate => {
            println!("  --> Cycle {cycle}: Stalemate. Neither scored.");
        }
    }
}

/// Real opencode runner — spawns `opencode run` as a subprocess.
struct RealOpencodeRunner;

impl aegis_arena::red_agent::OpencodeRunner for RealOpencodeRunner {
    async fn run(
        &self,
        workspace: &std::path::Path,
        prompt: &str,
        model: &str,
        timeout: Duration,
    ) -> std::io::Result<std::process::Output> {
        let full_model = if model.contains('/') {
            model.to_string()
        } else {
            // Correct opencode model ID format for Bedrock
            format!("amazon-bedrock/global.anthropic.claude-{}-4-6", model)
        };

        // Use adver project dir so opencode loads CLAUDE.md (ENI persona)
        // NOT --agent build which overrides the system prompt with generic Claude
        let project_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent().unwrap().parent().unwrap().to_path_buf();

        eprintln!("[opencode] spawning model={full_model} project={}", project_dir.display());

        let result = tokio::time::timeout(
            timeout,
            tokio::process::Command::new("opencode")
                .arg("run")
                .arg("--dir").arg(&project_dir)
                .arg("--model").arg(&full_model)
                // No --agent flag — uses CLAUDE.md (ENI persona)
                .arg(prompt)
                .env("AWS_PROFILE", "ziya")
                // Discard stderr (opencode UI noise) so stdout is clean response text
                .stderr(std::process::Stdio::null())
                .output(),
        )
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "opencode timed out"))??;

        eprintln!("[opencode] done exit={} stdout={}b stderr={}b",
            result.status, result.stdout.len(), result.stderr.len());
        if !result.stdout.is_empty() {
            eprintln!("[opencode] stdout: {}", String::from_utf8_lossy(&result.stdout[..result.stdout.len().min(300)]));
        }
        if !result.stderr.is_empty() {
            eprintln!("[opencode] stderr: {}", String::from_utf8_lossy(&result.stderr[..result.stderr.len().min(200)]));
        }
        Ok(result)
    }
}
