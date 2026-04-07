//! AEGIS Daemon Launcher - Launches specialized autonomous daemons for high-ROI modules.
//!
//! This crate provides a unified interface for launching four specialized daemon types:
//! 1. Ghost Protocol Daemon (missing evasion modules)
//! 2. Cache Poisoning Daemon (ROI=78.4)
//! 3. Schema-Grammar Pipeline Daemon (ROI=37.3)
//! 4. HTTP/2 CONTINUATION Flood Daemon (ROI=52.5)

pub mod daemon_config;
pub mod daemon_launcher;
pub mod ghost_protocol_daemon;
pub mod cache_poisoning_daemon;
pub mod schema_grammar_daemon;
pub mod h2_continuation_daemon;

pub use daemon_config::*;
pub use daemon_launcher::*;
pub use ghost_protocol_daemon::*;
pub use cache_poisoning_daemon::*;
pub use schema_grammar_daemon::*;
pub use h2_continuation_daemon::*;