//! Daemon Launcher Module
//!
//! Provides functionality to launch and manage specialized autonomous daemons.

use crate::{DaemonConfig, DaemonType};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::process::Command;
use tokio::sync::Mutex;
use tracing::{info, error, debug};
use uuid::Uuid;

pub struct DaemonLauncher {
    work_dir: PathBuf,
    launched_daemons: Mutex<HashMap<String, tokio::process::Child>>,
}

impl DaemonLauncher {
    pub fn new(work_dir: PathBuf) -> Self {
        Self {
            work_dir,
            launched_daemons: Mutex::new(HashMap::new()),
        }
    }

    /// Launch all four specialized daemons with optimal configurations
    pub async fn launch_all_optimal(&self) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        info!("Launching all specialized daemons with optimal configurations");
        
        let mut daemon_ids = Vec::new();
        
        // Launch Ghost Protocol Daemon (missing evasion modules)
        let ghost_config = DaemonConfig {
            id: format!("ghost-{}", Uuid::new_v4().to_string()[..8].to_string()),
            daemon_type: DaemonType::GhostProtocol,
            target_url: "http://127.0.0.1:8080".to_string(),
            work_dir: self.work_dir.join("ghost_protocol"),
            verbose: true,
            max_concurrent: 10,
            custom_params: serde_json::json!({
                "target_modules": ["header_transformer", "encoding_transformer", "timing_controller"],
                "success_threshold": 0.85,
                "daily_payload_target": 1000,
                "false_positive_limit": 0.05
            }),
        };
        
        match self.launch_daemon(ghost_config).await {
            Ok(daemon_id) => {
                daemon_ids.push(daemon_id);
                info!("Launched Ghost Protocol Daemon");
            }
            Err(e) => {
                error!("Failed to launch Ghost Protocol Daemon: {}", e);
            }
        }
        
        // Launch Cache Poisoning Daemon (ROI=78.4)
        let cache_config = DaemonConfig {
            id: format!("cache-{}", Uuid::new_v4().to_string()[..8].to_string()),
            daemon_type: DaemonType::CachePoisoning,
            target_url: "http://127.0.0.1:8080".to_string(),
            work_dir: self.work_dir.join("cache_poisoning"),
            verbose: true,
            max_concurrent: 5,
            custom_params: serde_json::json!({
                "target_success_rate": 0.90,
                "daily_vector_target": 500,
                "false_positive_limit": 0.02,
                "high_impact_targets": ["/api/cache", "/cdn/assets"]
            }),
        };
        
        match self.launch_daemon(cache_config).await {
            Ok(daemon_id) => {
                daemon_ids.push(daemon_id);
                info!("Launched Cache Poisoning Daemon");
            }
            Err(e) => {
                error!("Failed to launch Cache Poisoning Daemon: {}", e);
            }
        }
        
        // Launch Schema-Grammar Pipeline Daemon (ROI=37.3)
        let schema_config = DaemonConfig {
            id: format!("schema-{}", Uuid::new_v4().to_string()[..8].to_string()),
            daemon_type: DaemonType::SchemaGrammar,
            target_url: "http://127.0.0.1:8080".to_string(),
            work_dir: self.work_dir.join("schema_grammar"),
            verbose: true,
            max_concurrent: 20,
            custom_params: serde_json::json!({
                "daily_schema_target": 100,
                "fuzz_input_target": 1000,
                "accuracy_threshold": 0.80,
                "max_processing_time_ms": 100
            }),
        };
        
        match self.launch_daemon(schema_config).await {
            Ok(daemon_id) => {
                daemon_ids.push(daemon_id);
                info!("Launched Schema-Grammar Pipeline Daemon");
            }
            Err(e) => {
                error!("Failed to launch Schema-Grammar Pipeline Daemon: {}", e);
            }
        }
        
        // Launch HTTP/2 CONTINUATION Flood Daemon (ROI=52.5)
        let http2_config = DaemonConfig {
            id: format!("http2-{}", Uuid::new_v4().to_string()[..8].to_string()),
            daemon_type: DaemonType::H2Continuation,
            target_url: "http://127.0.0.1:8080".to_string(),
            work_dir: self.work_dir.join("http2_flood"),
            verbose: true,
            max_concurrent: 3,
            custom_params: serde_json::json!({
                "target_frame_rate": 10000,
                "success_rate_threshold": 0.95,
                "connection_drop_limit": 0.01,
                "high_impact_targets": ["/api/http2", "/stream/data"]
            }),
        };
        
        match self.launch_daemon(http2_config).await {
            Ok(daemon_id) => {
                daemon_ids.push(daemon_id);
                info!("Launched HTTP/2 CONTINUATION Flood Daemon");
            }
            Err(e) => {
                error!("Failed to launch HTTP/2 CONTINUATION Flood Daemon: {}", e);
            }
        }
        
        Ok(daemon_ids)
    }

    /// Launch a specific daemon with the given configuration
    pub async fn launch_daemon(&self, config: DaemonConfig) -> Result<String, Box<dyn std::error::Error>> {
        info!("Launching {} daemon [{}]", config.daemon_type, config.id);
        
        // Create work directory
        tokio::fs::create_dir_all(&config.work_dir).await?;
        
        // Determine the binary name based on daemon type
        let binary_name = match config.daemon_type {
            DaemonType::GhostProtocol => "aegis-ghost-protocol-daemon",
            DaemonType::CachePoisoning => "aegis-cache-poisoning-daemon",
            DaemonType::SchemaGrammar => "aegis-schema-grammar-daemon",
            DaemonType::H2Continuation => "aegis-h2-continuation-daemon",
        };
        
        // Launch the daemon process
        let mut cmd = Command::new(binary_name);
        cmd.arg("--id").arg(&config.id)
           .arg("--workspace").arg(&config.work_dir)
           .stdin(Stdio::null())
           .stdout(Stdio::piped())
           .stderr(Stdio::piped());
        
        let mut child = cmd.spawn()?;
        
        // Store the child process
        let daemon_id = config.id.clone();
        self.launched_daemons.lock().await.insert(daemon_id.clone(), child);
        
        info!("Successfully launched {} daemon [{}]", config.daemon_type, daemon_id);
        Ok(daemon_id)
    }

    /// Stop all launched daemons
    pub async fn stop_all(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Stopping all launched daemons");
        
        let mut daemons = self.launched_daemons.lock().await;
        for (daemon_id, child) in daemons.iter_mut() {
            info!("Stopping daemon [{}]", daemon_id);
            child.kill().await?;
        }
        
        daemons.clear();
        Ok(())
    }
}