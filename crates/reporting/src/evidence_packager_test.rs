#[cfg(test)]
mod tests {
    use crate::evidence_packager::{
        EvidenceBuilder, HttpRequestEvidence, HttpResponseEvidence, TimelineEvent,
        generate_attack_mapping, generate_curl_command, render_evidence_json,
        render_evidence_markdown,
    };

    fn sample_request() -> HttpRequestEvidence {
        HttpRequestEvidence {
            method: "POST".to_string(),
            url: "http://localhost:3000/api/login".to_string(),
            headers: vec![
                ("Content-Type".to_string(), "application/json".to_string()),
                ("X-Custom".to_string(), "test-value".to_string()),
            ],
            body: Some("{\"user\":\"admin' OR 1=1--\"}".to_string()),
        }
    }

    fn sample_response() -> HttpResponseEvidence {
        HttpResponseEvidence {
            status_code: 200,
            headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            body: Some("{\"token\":\"abc123\"}".to_string()),
            response_time_ms: Some(42),
        }
    }

    fn sample_get_request() -> HttpRequestEvidence {
        HttpRequestEvidence {
            method: "GET".to_string(),
            url: "http://localhost:3000/api/users?id=1".to_string(),
            headers: vec![("Accept".to_string(), "application/json".to_string())],
            body: None,
        }
    }

    #[test]
    fn builder_produces_complete_evidence_package() {
        let package = EvidenceBuilder::new("finding-001", "SqlInjection", "/api/login")
            .with_request(sample_request())
            .with_response(sample_response())
            .with_screenshot("/tmp/evidence/sqli_001.png")
            .with_timeline_event(TimelineEvent {
                timestamp: "2025-01-15T10:00:00Z".to_string(),
                event_type: "discovered".to_string(),
                description: "Initial detection via fuzzing".to_string(),
                confidence: Some(0.7),
            })
            .with_timeline_event(TimelineEvent {
                timestamp: "2025-01-15T10:05:00Z".to_string(),
                event_type: "verified".to_string(),
                description: "Counterfactual oracle confirmed".to_string(),
                confidence: Some(0.95),
            })
            .with_related_finding("finding-002")
            .with_related_finding("finding-003")
            .with_reproduction_step("Send POST to /api/login with SQLi payload")
            .with_reproduction_step("Observe 200 response with leaked token")
            .build();

        assert_eq!(package.finding_id, "finding-001");
        assert_eq!(package.vulnerability_class, "SqlInjection");
        assert_eq!(package.endpoint, "/api/login");
        assert!(package.request.is_some());
        assert!(package.response.is_some());
        assert_eq!(
            package.screenshot_path.as_deref(),
            Some("/tmp/evidence/sqli_001.png")
        );
        assert_eq!(package.timeline.len(), 2);
        assert_eq!(package.related_finding_ids.len(), 2);
        assert_eq!(package.reproduction_steps.len(), 2);
        assert!(!package.curl_command.is_empty());
        assert_eq!(package.attack_mapping.technique_id, "T1190");
        assert_eq!(package.attack_mapping.cwe_id, "CWE-89");
    }

    #[test]
    fn curl_command_with_headers_and_body() {
        let req = sample_request();
        let curl = generate_curl_command(&req);

        assert!(curl.starts_with("curl"));
        assert!(curl.contains("-X POST"));
        assert!(curl.contains("-H 'Content-Type: application/json'"));
        assert!(curl.contains("-H 'X-Custom: test-value'"));
        assert!(curl.contains("-d '{\"user\":\"admin' OR 1=1--\"}'"));
        assert!(curl.contains("'http://localhost:3000/api/login'"));
    }

    #[test]
    fn curl_command_get_omits_method_and_body() {
        let req = sample_get_request();
        let curl = generate_curl_command(&req);

        assert!(curl.starts_with("curl"));
        assert!(!curl.contains("-X"));
        assert!(!curl.contains("-d"));
        assert!(curl.contains("-H 'Accept: application/json'"));
        assert!(curl.contains("'http://localhost:3000/api/users?id=1'"));
    }

    #[test]
    fn attack_mapping_known_vuln_classes() {
        let sqli = generate_attack_mapping("SqlInjection");
        assert_eq!(sqli.technique_id, "T1190");
        assert_eq!(sqli.technique_name, "Exploit Public-Facing Application");
        assert_eq!(sqli.tactic, "Initial Access");
        assert_eq!(sqli.cwe_id, "CWE-89");

        let xss = generate_attack_mapping("CrossSiteScripting");
        assert_eq!(xss.technique_id, "T1189");
        assert_eq!(xss.technique_name, "Drive-by Compromise");
        assert_eq!(xss.tactic, "Initial Access");
        assert_eq!(xss.cwe_id, "CWE-79");

        let cmdi = generate_attack_mapping("CommandInjection");
        assert_eq!(cmdi.technique_id, "T1059");
        assert_eq!(cmdi.technique_name, "Command and Scripting Interpreter");
        assert_eq!(cmdi.tactic, "Execution");
        assert_eq!(cmdi.cwe_id, "CWE-78");

        let path = generate_attack_mapping("PathTraversal");
        assert_eq!(path.technique_id, "T1083");

        let ssrf = generate_attack_mapping("ServerSideRequestForgery");
        assert_eq!(ssrf.technique_id, "T1090");

        let ssti = generate_attack_mapping("ServerSideTemplateInjection");
        assert_eq!(ssti.technique_id, "T1221");
    }

    #[test]
    fn attack_mapping_unknown_class_falls_back() {
        let unknown = generate_attack_mapping("SomeNewVuln");
        assert_eq!(unknown.technique_id, "T1190");
        assert_eq!(unknown.technique_name, "Exploit Public-Facing Application");
        assert_eq!(unknown.tactic, "Initial Access");
        assert_eq!(unknown.cwe_id, "CWE-0");
    }

    #[test]
    fn json_rendering_roundtrips() {
        let package = EvidenceBuilder::new("finding-010", "CrossSiteScripting", "/search")
            .with_request(sample_get_request())
            .with_reproduction_step("Inject script tag in search parameter")
            .build();

        let json = render_evidence_json(&package);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["finding_id"], "finding-010");
        assert_eq!(parsed["vulnerability_class"], "CrossSiteScripting");
        assert_eq!(parsed["endpoint"], "/search");
        assert!(parsed["attack_mapping"]["technique_id"].as_str().is_some());
    }

    #[test]
    fn markdown_rendering_contains_key_sections() {
        let package = EvidenceBuilder::new("finding-020", "CommandInjection", "/api/exec")
            .with_request(sample_request())
            .with_response(sample_response())
            .with_screenshot("/evidence/cmd_020.png")
            .with_timeline_event(TimelineEvent {
                timestamp: "2025-02-01T12:00:00Z".to_string(),
                event_type: "discovered".to_string(),
                description: "Found via hypothesis-driven fuzzing".to_string(),
                confidence: Some(0.8),
            })
            .with_related_finding("finding-021")
            .with_reproduction_step("POST crafted payload to /api/exec")
            .build();

        let md = render_evidence_markdown(&package);

        assert!(md.contains("# Evidence: finding-020"));
        assert!(md.contains("**Vulnerability:** CommandInjection"));
        assert!(md.contains("**Endpoint:** /api/exec"));
        assert!(md.contains("## ATT&CK Mapping"));
        assert!(md.contains("T1059"));
        assert!(md.contains("## HTTP Request"));
        assert!(md.contains("## HTTP Response"));
        assert!(md.contains("## Reproduction"));
        assert!(md.contains("## Timeline"));
        assert!(md.contains("(confidence: 0.80)"));
        assert!(md.contains("## Related Findings"));
        assert!(md.contains("finding-021"));
        assert!(md.contains("## Screenshot"));
        assert!(md.contains("![Evidence screenshot]"));
    }

    #[test]
    fn timeline_events_preserve_insertion_order() {
        let package = EvidenceBuilder::new("finding-030", "SqlInjection", "/api/data")
            .with_timeline_event(TimelineEvent {
                timestamp: "2025-03-01T08:00:00Z".to_string(),
                event_type: "discovered".to_string(),
                description: "First detection".to_string(),
                confidence: Some(0.5),
            })
            .with_timeline_event(TimelineEvent {
                timestamp: "2025-03-01T08:10:00Z".to_string(),
                event_type: "confirmed".to_string(),
                description: "Counterfactual confirmation".to_string(),
                confidence: Some(0.85),
            })
            .with_timeline_event(TimelineEvent {
                timestamp: "2025-03-01T08:20:00Z".to_string(),
                event_type: "chained".to_string(),
                description: "Linked to auth bypass chain".to_string(),
                confidence: Some(0.92),
            })
            .build();

        assert_eq!(package.timeline.len(), 3);
        assert_eq!(package.timeline[0].event_type, "discovered");
        assert_eq!(package.timeline[1].event_type, "confirmed");
        assert_eq!(package.timeline[2].event_type, "chained");
        assert!(package.timeline[0].confidence.unwrap() < package.timeline[2].confidence.unwrap());
    }

    #[test]
    fn builder_without_request_produces_empty_curl() {
        let package = EvidenceBuilder::new("finding-040", "SqlInjection", "/api/data").build();
        assert!(package.curl_command.is_empty());
        assert!(package.request.is_none());
        assert!(package.response.is_none());
        assert!(package.screenshot_path.is_none());
        assert!(package.timeline.is_empty());
        assert!(package.related_finding_ids.is_empty());
        assert!(package.reproduction_steps.is_empty());
    }

    #[test]
    fn evidence_package_serde_roundtrip() {
        let package = EvidenceBuilder::new("finding-050", "BrokenAuthentication", "/login")
            .with_request(sample_request())
            .with_response(sample_response())
            .with_timeline_event(TimelineEvent {
                timestamp: "2025-04-01T00:00:00Z".to_string(),
                event_type: "discovered".to_string(),
                description: "Auth bypass detected".to_string(),
                confidence: None,
            })
            .build();

        let json = serde_json::to_string(&package).unwrap();
        let deserialized: crate::evidence_packager::EvidencePackage =
            serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.finding_id, package.finding_id);
        assert_eq!(
            deserialized.vulnerability_class,
            package.vulnerability_class
        );
        assert_eq!(deserialized.endpoint, package.endpoint);
        assert_eq!(deserialized.curl_command, package.curl_command);
        assert_eq!(deserialized.timeline.len(), package.timeline.len());
        assert_eq!(
            deserialized.attack_mapping.technique_id,
            package.attack_mapping.technique_id
        );
    }

    #[test]
    fn attack_mapping_human_readable_aliases() {
        let sqli = generate_attack_mapping("SQL Injection");
        assert_eq!(sqli.technique_id, "T1190");
        assert_eq!(sqli.cwe_id, "CWE-89");

        let xss = generate_attack_mapping("XSS");
        assert_eq!(xss.technique_id, "T1189");

        let ssrf = generate_attack_mapping("SSRF");
        assert_eq!(ssrf.technique_id, "T1090");
    }
}
