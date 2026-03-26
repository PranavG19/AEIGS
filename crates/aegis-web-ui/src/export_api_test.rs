#[cfg(test)]
mod tests {
    use crate::state::{AppState, Finding, GraphEdge, GraphNode};
    use crate::CliArgs;
    use crate::export_api;

    fn test_args() -> CliArgs {
        CliArgs {
            target: None,
            port: 7777,
            profile: "quick".to_string(),
            demo: false,
        }
    }

    fn populate_state(state: &AppState) {
        let mut graph = state.graph.write();
        graph.nodes.insert("ep-1".to_string(), GraphNode {
            id: "ep-1".to_string(),
            node_type: "endpoint".to_string(),
            label: "GET /api/search".to_string(),
            severity: None,
            status: "discovered".to_string(),
            confidence: None,
            data: serde_json::Value::Null,
        });
        graph.nodes.insert("vuln-1".to_string(), GraphNode {
            id: "vuln-1".to_string(),
            node_type: "vulnerability".to_string(),
            label: "SQL Injection".to_string(),
            severity: Some("critical".to_string()),
            status: "vulnerable".to_string(),
            confidence: Some(0.95),
            data: serde_json::Value::Null,
        });
        graph.edges.push(GraphEdge {
            source: "ep-1".to_string(),
            target: "vuln-1".to_string(),
            label: "exploits".to_string(),
        });
        graph.findings.push(Finding {
            id: "f-1".to_string(),
            vuln_class: "SQL Injection".to_string(),
            severity: "Critical".to_string(),
            endpoint: "/api/search".to_string(),
            confidence: 0.95,
            evidence_preview: "' OR 1=1 --".to_string(),
            timestamp_ms: 1000,
        });

        let mut status = state.scan_status.write();
        status.target = "https://example.com".to_string();
        status.risk_score = 78.0;
    }

    #[test]
    fn base64_encoder_works() {
        let input = "Hello, World!";
        let mut buf = Vec::new();
        {
            use std::io::Write;
            let mut enc = super::super::Base64Encoder::new(&mut buf);
            enc.write_all(input.as_bytes()).unwrap();
            let _ = enc.finish();
        }
        let encoded = String::from_utf8(buf).unwrap();
        assert_eq!(encoded, "SGVsbG8sIFdvcmxkIQ==");
    }

    #[test]
    fn severity_to_sarif_level_mapping() {
        assert_eq!(super::super::severity_to_sarif_level("Critical"), "error");
        assert_eq!(super::super::severity_to_sarif_level("High"), "error");
        assert_eq!(super::super::severity_to_sarif_level("Medium"), "warning");
        assert_eq!(super::super::severity_to_sarif_level("Low"), "note");
        assert_eq!(super::super::severity_to_sarif_level("Unknown"), "none");
    }

    #[tokio::test]
    async fn export_dot_produces_valid_graphviz() {
        let state = AppState::new(test_args());
        populate_state(&state);

        let response = export_api::export_dot(
            axum::extract::State(state),
        ).await;

        use axum::response::IntoResponse;
        let resp = response.into_response();
        let body = axum::body::to_bytes(resp.into_body(), 1_000_000).await.unwrap();
        let dot_str = String::from_utf8(body.to_vec()).unwrap();

        assert!(dot_str.contains("digraph aegis"));
        assert!(dot_str.contains("ep-1"));
        assert!(dot_str.contains("vuln-1"));
        assert!(dot_str.contains("exploits"));
    }

    #[tokio::test]
    async fn export_json_contains_findings() {
        let state = AppState::new(test_args());
        populate_state(&state);

        let response = export_api::export_json(
            axum::extract::State(state),
        ).await;

        use axum::response::IntoResponse;
        let resp = response.into_response();
        let body = axum::body::to_bytes(resp.into_body(), 1_000_000).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(json["findings"].is_array());
        assert_eq!(json["findings"].as_array().unwrap().len(), 1);
        assert!(json["nodes"].is_array());
        assert!(json["edges"].is_array());
    }

    #[tokio::test]
    async fn export_sarif_valid_structure() {
        let state = AppState::new(test_args());
        populate_state(&state);

        let response = export_api::export_sarif(
            axum::extract::State(state),
        ).await;

        use axum::response::IntoResponse;
        let resp = response.into_response();
        let body = axum::body::to_bytes(resp.into_body(), 1_000_000).await.unwrap();
        let sarif: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(sarif["version"], "2.1.0");
        assert!(sarif["runs"].is_array());
        let runs = sarif["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0]["tool"]["driver"]["name"], "AEGIS");
        assert!(runs[0]["results"].is_array());
    }

    #[tokio::test]
    async fn export_html_contains_findings() {
        let state = AppState::new(test_args());
        populate_state(&state);

        let response = export_api::export_html(
            axum::extract::State(state),
        ).await;

        use axum::response::IntoResponse;
        let resp = response.into_response();
        let body = axum::body::to_bytes(resp.into_body(), 1_000_000).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        assert!(html.contains("AEGIS Scan Report"));
        assert!(html.contains("SQL Injection"));
        assert!(html.contains("/api/search"));
    }

    #[tokio::test]
    async fn export_svg_produces_valid_svg() {
        let state = AppState::new(test_args());
        populate_state(&state);

        let response = export_api::export_svg(
            axum::extract::State(state),
        ).await;

        use axum::response::IntoResponse;
        let resp = response.into_response();
        let body = axum::body::to_bytes(resp.into_body(), 1_000_000).await.unwrap();
        let svg = String::from_utf8(body.to_vec()).unwrap();

        assert!(svg.contains("<svg"));
        assert!(svg.contains("</svg>"));
        assert!(svg.contains("GET /api/search"));
    }

    #[tokio::test]
    async fn share_link_returns_url() {
        let state = AppState::new(test_args());
        populate_state(&state);

        let response = export_api::create_share_link(
            axum::extract::State(state),
        ).await;

        use axum::response::IntoResponse;
        let resp = response.into_response();
        let body = axum::body::to_bytes(resp.into_body(), 1_000_000).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["url"].as_str().unwrap().contains("localhost:7777"));
        assert!(json["url"].as_str().unwrap().contains("#share="));
    }
}
