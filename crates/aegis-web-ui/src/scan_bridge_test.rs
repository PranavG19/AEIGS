#[cfg(test)]
mod tests {
    use crate::graph_api::GraphEvent;
    use crate::scan_bridge;
    use crate::state::AppState;
    use crate::CliArgs;
    use std::time::Duration;

    fn demo_args() -> CliArgs {
        CliArgs {
            target: None,
            port: 7777,
            profile: "quick".to_string(),
            demo: true,
        }
    }

    #[tokio::test]
    async fn demo_scan_populates_graph_state() {
        let state = AppState::new(demo_args());
        scan_bridge::start_demo_scan(state.clone());

        // Wait a bit for the first events to appear
        tokio::time::sleep(Duration::from_secs(5)).await;

        let graph = state.graph.read();
        assert!(!graph.events.is_empty(), "should have emitted events");
        assert!(!graph.nodes.is_empty(), "should have added nodes");

        let status = state.scan_status.read();
        assert!(status.is_running);
    }

    #[tokio::test]
    async fn demo_scan_sets_target() {
        let state = AppState::new(demo_args());
        scan_bridge::start_demo_scan(state.clone());

        tokio::time::sleep(Duration::from_millis(500)).await;

        let status = state.scan_status.read();
        assert_eq!(status.target, "https://demo.example.com");
    }

    #[tokio::test]
    async fn demo_scan_broadcasts_events() {
        let state = AppState::new(demo_args());
        let mut rx = state.event_tx.subscribe();
        scan_bridge::start_demo_scan(state.clone());

        tokio::time::sleep(Duration::from_secs(2)).await;

        let mut received = Vec::new();
        while let Ok(evt) = rx.try_recv() {
            received.push(evt);
        }
        assert!(!received.is_empty(), "broadcast should have events");

        // First event should be a log message about starting recon
        match &received[0] {
            GraphEvent::LogMessage { message, .. } => {
                assert!(message.contains("Starting recon"));
            }
            _ => panic!("first event should be LogMessage"),
        }
    }

    #[tokio::test]
    async fn demo_scan_can_be_stopped() {
        let state = AppState::new(demo_args());
        scan_bridge::start_demo_scan(state.clone());
        tokio::time::sleep(Duration::from_secs(1)).await;

        {
            let mut status = state.scan_status.write();
            status.is_running = false;
        }

        tokio::time::sleep(Duration::from_secs(2)).await;

        let events_count = state.graph.read().events.len();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let events_count_later = state.graph.read().events.len();

        // After stopping, no new events should appear
        assert_eq!(events_count, events_count_later);
    }
}
