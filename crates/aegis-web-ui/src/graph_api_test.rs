#[cfg(test)]
mod tests {
    use crate::graph_api::GraphEvent;

    #[test]
    fn graph_event_node_added_serializes() {
        let event = GraphEvent::NodeAdded {
            id: "ep-1".to_string(),
            node_type: "endpoint".to_string(),
            label: "GET /api/search".to_string(),
            severity: None,
            data: serde_json::json!({"method": "GET"}),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"NodeAdded\""));
        assert!(json.contains("ep-1"));
        assert!(json.contains("endpoint"));
    }

    #[test]
    fn graph_event_edge_added_serializes() {
        let event = GraphEvent::EdgeAdded {
            source: "ep-1".to_string(),
            target: "vuln-1".to_string(),
            label: "exploits".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"EdgeAdded\""));
        assert!(json.contains("exploits"));
    }

    #[test]
    fn graph_event_node_updated_serializes() {
        let event = GraphEvent::NodeUpdated {
            id: "vuln-1".to_string(),
            status: "vulnerable".to_string(),
            confidence: Some(0.95),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"NodeUpdated\""));
        assert!(json.contains("0.95"));
    }

    #[test]
    fn graph_event_finding_confirmed_serializes() {
        let event = GraphEvent::FindingConfirmed {
            node_id: "ep-1".to_string(),
            vuln_class: "SQL Injection".to_string(),
            severity: "Critical".to_string(),
            evidence_preview: "payload: ' OR 1=1".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("FindingConfirmed"));
        assert!(json.contains("SQL Injection"));
    }

    #[test]
    fn graph_event_phase_changed_serializes() {
        let event = GraphEvent::PhaseChanged {
            phase: "Fuzzing".to_string(),
            progress_pct: 45.0,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("PhaseChanged"));
        assert!(json.contains("45"));
    }

    #[test]
    fn graph_event_scan_complete_serializes() {
        let event = GraphEvent::ScanComplete {
            total_findings: 5,
            risk_score: 78.0,
            duration_ms: 40000,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("ScanComplete"));
        assert!(json.contains("78"));
    }

    #[test]
    fn graph_event_log_message_serializes() {
        let event = GraphEvent::LogMessage {
            level: "error".to_string(),
            message: "SQLi confirmed".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("LogMessage"));
        assert!(json.contains("SQLi confirmed"));
    }

    #[test]
    fn graph_event_roundtrip() {
        let event = GraphEvent::NodeAdded {
            id: "test-node".to_string(),
            node_type: "vulnerability".to_string(),
            label: "XSS".to_string(),
            severity: Some("high".to_string()),
            data: serde_json::json!(null),
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: GraphEvent = serde_json::from_str(&json).unwrap();
        match parsed {
            GraphEvent::NodeAdded {
                id,
                node_type,
                severity,
                ..
            } => {
                assert_eq!(id, "test-node");
                assert_eq!(node_type, "vulnerability");
                assert_eq!(severity.as_deref(), Some("high"));
            }
            _ => panic!("wrong variant"),
        }
    }
}
