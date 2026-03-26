#[cfg(test)]
mod tests {
    use crate::state::{AppState, GraphState, ScanStatus};
    use crate::CliArgs;

    fn test_args() -> CliArgs {
        CliArgs {
            target: None,
            port: 7777,
            profile: "quick".to_string(),
            demo: false,
        }
    }

    #[test]
    fn app_state_initializes_with_defaults() {
        let state = AppState::new(test_args());
        let graph = state.graph.read();
        assert!(graph.nodes.is_empty());
        assert!(graph.edges.is_empty());
        assert!(graph.findings.is_empty());

        let status = state.scan_status.read();
        assert_eq!(status.phase, "idle");
        assert!(!status.is_running);
    }

    #[test]
    fn graph_state_default() {
        let gs = GraphState::default();
        assert!(gs.nodes.is_empty());
        assert!(gs.edges.is_empty());
        assert!(gs.findings.is_empty());
        assert!(gs.log_lines.is_empty());
        assert!(gs.events.is_empty());
    }

    #[test]
    fn scan_status_default() {
        let ss = ScanStatus::default();
        assert_eq!(ss.phase, "idle");
        assert_eq!(ss.progress_pct, 0.0);
        assert!(!ss.is_running);
        assert!(!ss.is_paused);
        assert_eq!(ss.total_findings, 0);
        assert_eq!(ss.risk_score, 0.0);
        assert_eq!(ss.duration_ms, 0);
        assert!(ss.target.is_empty());
    }

    #[test]
    fn broadcast_channel_works() {
        let state = AppState::new(test_args());
        let mut rx = state.event_tx.subscribe();
        let event = crate::graph_api::GraphEvent::LogMessage {
            level: "info".to_string(),
            message: "test".to_string(),
        };
        let _ = state.event_tx.send(event);
        let received = rx.try_recv();
        assert!(received.is_ok());
    }
}
