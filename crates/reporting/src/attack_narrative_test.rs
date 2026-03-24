use crate::attack_narrative::{
    AttackStep, AttackStepInput, ChainNarrativeInput, HttpExchange, generate_mermaid_diagram,
    generate_narrative, generate_summary, generate_technical_appendix,
};

fn single_step_input() -> ChainNarrativeInput {
    ChainNarrativeInput {
        chain_id: "CHAIN-001".to_string(),
        steps: vec![AttackStepInput {
            vulnerability_class: "SQL Injection".to_string(),
            endpoint: "/api/login".to_string(),
            parameter: Some("username".to_string()),
            technique: "Union-based injection".to_string(),
            request: Some(HttpExchange {
                method: "POST".to_string(),
                url: "http://target.local/api/login".to_string(),
                headers: vec![
                    ("Content-Type".to_string(), "application/json".to_string()),
                    ("Host".to_string(), "target.local".to_string()),
                ],
                body: Some("{\"username\": \"' UNION SELECT * FROM users--\"}".to_string()),
                status_code: None,
            }),
            response: Some(HttpExchange {
                method: String::new(),
                url: String::new(),
                headers: vec![("Content-Type".to_string(), "application/json".to_string())],
                body: Some("{\"users\": [{\"id\": 1, \"role\": \"admin\"}]}".to_string()),
                status_code: Some(200),
            }),
        }],
        target_asset: "user credentials database".to_string(),
        overall_difficulty: 1.5,
    }
}

fn multi_step_input() -> ChainNarrativeInput {
    ChainNarrativeInput {
        chain_id: "CHAIN-002".to_string(),
        steps: vec![
            AttackStepInput {
                vulnerability_class: "SQL Injection".to_string(),
                endpoint: "/api/login".to_string(),
                parameter: Some("username".to_string()),
                technique: "Union-based injection".to_string(),
                request: Some(HttpExchange {
                    method: "POST".to_string(),
                    url: "http://target.local/api/login".to_string(),
                    headers: vec![("Content-Type".to_string(), "application/json".to_string())],
                    body: Some("{\"username\": \"' OR 1=1--\"}".to_string()),
                    status_code: None,
                }),
                response: Some(HttpExchange {
                    method: String::new(),
                    url: String::new(),
                    headers: vec![],
                    body: Some("{\"token\": \"eyJ...\"}".to_string()),
                    status_code: Some(200),
                }),
            },
            AttackStepInput {
                vulnerability_class: "Broken Authorization".to_string(),
                endpoint: "/api/users/{id}".to_string(),
                parameter: Some("id".to_string()),
                technique: "IDOR via sequential ID".to_string(),
                request: Some(HttpExchange {
                    method: "GET".to_string(),
                    url: "http://target.local/api/users/1".to_string(),
                    headers: vec![("Authorization".to_string(), "Bearer eyJ...".to_string())],
                    body: None,
                    status_code: None,
                }),
                response: Some(HttpExchange {
                    method: String::new(),
                    url: String::new(),
                    headers: vec![],
                    body: Some("{\"user\": {\"email\": \"admin@corp.com\"}}".to_string()),
                    status_code: Some(200),
                }),
            },
            AttackStepInput {
                vulnerability_class: "Path Traversal".to_string(),
                endpoint: "/api/files".to_string(),
                parameter: Some("path".to_string()),
                technique: "Dot-dot-slash traversal".to_string(),
                request: None,
                response: None,
            },
        ],
        target_asset: "internal configuration files".to_string(),
        overall_difficulty: 4.0,
    }
}

#[test]
fn single_step_narrative_generation() {
    let input = single_step_input();
    let narrative = generate_narrative(&input);

    assert_eq!(narrative.title, "Attack Chain CHAIN-001");
    assert_eq!(narrative.severity, "Critical");
    assert_eq!(narrative.steps.len(), 1);

    let step = &narrative.steps[0];
    assert_eq!(step.step_number, 1);
    assert_eq!(step.vulnerability_class, "SQL Injection");
    assert_eq!(step.endpoint, "/api/login");
    assert!(step.description.contains("SQL Injection"));
    assert!(step.http_request.is_some());
    assert!(step.http_response.is_some());

    assert!(narrative.summary.contains("An attacker could"));
    assert!(narrative.summary.contains("SQL Injection"));
    assert!(narrative.summary.contains("user credentials database"));
    assert!(narrative.attack_vector.contains("SQL Injection"));
    assert!(narrative.remediation.contains("parameterized queries"));
}

#[test]
fn multi_step_chain_narrative() {
    let input = multi_step_input();
    let narrative = generate_narrative(&input);

    assert_eq!(narrative.title, "Attack Chain CHAIN-002");
    assert_eq!(narrative.severity, "High");
    assert_eq!(narrative.steps.len(), 3);

    assert_eq!(narrative.steps[0].step_number, 1);
    assert_eq!(narrative.steps[1].step_number, 2);
    assert_eq!(narrative.steps[2].step_number, 3);

    assert_eq!(narrative.steps[0].vulnerability_class, "SQL Injection");
    assert_eq!(
        narrative.steps[1].vulnerability_class,
        "Broken Authorization"
    );
    assert_eq!(narrative.steps[2].vulnerability_class, "Path Traversal");

    assert!(narrative.summary.contains("An attacker could exploit"));
    assert!(narrative.summary.contains("then leverage"));
    assert!(narrative.summary.contains("internal configuration files"));

    assert!(narrative.impact.contains("3 vulnerabilities"));
    assert!(narrative.impact.contains("internal configuration files"));

    assert!(narrative.remediation.contains("1. Fix SQL Injection"));
    assert!(
        narrative
            .remediation
            .contains("2. Fix Broken Authorization")
    );
    assert!(narrative.remediation.contains("3. Fix Path Traversal"));
}

#[test]
fn mermaid_diagram_contains_graph_td_and_nodes() {
    let steps = vec![
        AttackStep {
            step_number: 1,
            vulnerability_class: "SQL Injection".to_string(),
            endpoint: "/api/login".to_string(),
            technique: "Union-based injection".to_string(),
            description: String::new(),
            http_request: None,
            http_response: None,
        },
        AttackStep {
            step_number: 2,
            vulnerability_class: "Broken Authorization".to_string(),
            endpoint: "/api/users".to_string(),
            technique: "IDOR".to_string(),
            description: String::new(),
            http_request: None,
            http_response: None,
        },
    ];

    let diagram = generate_mermaid_diagram(&steps);

    assert!(diagram.starts_with("graph TD"));
    assert!(diagram.contains("S1[\"SQL Injection: /api/login\"]"));
    assert!(diagram.contains("S2[\"Broken Authorization: /api/users\"]"));
    assert!(diagram.contains("S1 -->|IDOR| S2"));
}

#[test]
fn technical_appendix_formats_http_exchanges() {
    let steps = vec![AttackStep {
        step_number: 1,
        vulnerability_class: "SQL Injection".to_string(),
        endpoint: "/api/login".to_string(),
        technique: "Union-based injection".to_string(),
        description: String::new(),
        http_request: Some(HttpExchange {
            method: "POST".to_string(),
            url: "http://target.local/api/login".to_string(),
            headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            body: Some("{\"username\": \"admin\"}".to_string()),
            status_code: None,
        }),
        http_response: Some(HttpExchange {
            method: String::new(),
            url: String::new(),
            headers: vec![("X-Request-Id".to_string(), "abc123".to_string())],
            body: Some("{\"result\": \"ok\"}".to_string()),
            status_code: Some(200),
        }),
    }];

    let appendix = generate_technical_appendix(&steps);

    assert!(appendix.contains("--- Step 1 (SQL Injection) ---"));
    assert!(appendix.contains("Request:"));
    assert!(appendix.contains("POST http://target.local/api/login"));
    assert!(appendix.contains("Content-Type: application/json"));
    assert!(appendix.contains("Body: {\"username\": \"admin\"}"));
    assert!(appendix.contains("Response (status 200):"));
    assert!(appendix.contains("X-Request-Id: abc123"));
    assert!(appendix.contains("Body: {\"result\": \"ok\"}"));
}

#[test]
fn summary_generation_various_chain_lengths() {
    let empty_summary = generate_summary(&[], "database");
    assert!(empty_summary.contains("No exploitation steps"));
    assert!(empty_summary.contains("database"));

    let single = vec![AttackStepInput {
        vulnerability_class: "Cross-Site Scripting".to_string(),
        endpoint: "/search".to_string(),
        parameter: Some("q".to_string()),
        technique: "Reflected XSS".to_string(),
        request: None,
        response: None,
    }];
    let single_summary = generate_summary(&single, "session cookies");
    assert!(single_summary.starts_with("An attacker could"));
    assert!(single_summary.contains("Cross-Site Scripting"));
    assert!(single_summary.contains("/search"));
    assert!(single_summary.contains("via the q parameter"));
    assert!(single_summary.contains("session cookies"));

    let two = vec![
        AttackStepInput {
            vulnerability_class: "SQL Injection".to_string(),
            endpoint: "/api/login".to_string(),
            parameter: None,
            technique: "Boolean-based blind".to_string(),
            request: None,
            response: None,
        },
        AttackStepInput {
            vulnerability_class: "Command Injection".to_string(),
            endpoint: "/api/exec".to_string(),
            parameter: Some("cmd".to_string()),
            technique: "OS command chaining".to_string(),
            request: None,
            response: None,
        },
    ];
    let two_summary = generate_summary(&two, "production server");
    assert!(two_summary.contains("An attacker could exploit the SQL Injection"));
    assert!(two_summary.contains("then leverage the Command Injection"));
    assert!(two_summary.contains("production server"));

    let four_steps: Vec<AttackStepInput> = (0..4)
        .map(|i| AttackStepInput {
            vulnerability_class: format!("Vuln-{i}"),
            endpoint: format!("/step{i}"),
            parameter: None,
            technique: format!("Tech-{i}"),
            request: None,
            response: None,
        })
        .collect();
    let four_summary = generate_summary(&four_steps, "crown jewels");
    assert!(four_summary.starts_with("An attacker could"));
    let leverage_count = four_summary.matches("then leverage").count();
    assert_eq!(leverage_count, 3);
    assert!(four_summary.contains("crown jewels"));
}

#[test]
fn mermaid_diagram_single_step_has_no_edges() {
    let steps = vec![AttackStep {
        step_number: 1,
        vulnerability_class: "SQL Injection".to_string(),
        endpoint: "/api/data".to_string(),
        technique: "Error-based".to_string(),
        description: String::new(),
        http_request: None,
        http_response: None,
    }];

    let diagram = generate_mermaid_diagram(&steps);
    assert!(diagram.contains("graph TD"));
    assert!(diagram.contains("S1"));
    assert!(!diagram.contains("-->"));
}

#[test]
fn technical_appendix_handles_missing_exchanges() {
    let steps = vec![AttackStep {
        step_number: 1,
        vulnerability_class: "Path Traversal".to_string(),
        endpoint: "/api/files".to_string(),
        technique: "Dot-dot-slash".to_string(),
        description: String::new(),
        http_request: None,
        http_response: None,
    }];

    let appendix = generate_technical_appendix(&steps);
    assert!(appendix.contains("--- Step 1 (Path Traversal) ---"));
    assert!(!appendix.contains("Request:"));
    assert!(!appendix.contains("Response"));
}

#[test]
fn severity_mapping_from_difficulty() {
    let critical = ChainNarrativeInput {
        chain_id: "C".to_string(),
        steps: vec![AttackStepInput {
            vulnerability_class: "SQL Injection".to_string(),
            endpoint: "/x".to_string(),
            parameter: None,
            technique: "t".to_string(),
            request: None,
            response: None,
        }],
        target_asset: "a".to_string(),
        overall_difficulty: 1.0,
    };
    assert_eq!(generate_narrative(&critical).severity, "Critical");

    let high = ChainNarrativeInput {
        overall_difficulty: 3.0,
        ..critical.clone()
    };
    assert_eq!(generate_narrative(&high).severity, "High");

    let medium = ChainNarrativeInput {
        overall_difficulty: 6.5,
        ..critical.clone()
    };
    assert_eq!(generate_narrative(&medium).severity, "Medium");

    let low = ChainNarrativeInput {
        overall_difficulty: 9.0,
        ..critical.clone()
    };
    assert_eq!(generate_narrative(&low).severity, "Low");
}

#[test]
fn narrative_impact_deduplicates_vuln_classes() {
    let input = ChainNarrativeInput {
        chain_id: "CHAIN-DUP".to_string(),
        steps: vec![
            AttackStepInput {
                vulnerability_class: "SQL Injection".to_string(),
                endpoint: "/a".to_string(),
                parameter: None,
                technique: "t1".to_string(),
                request: None,
                response: None,
            },
            AttackStepInput {
                vulnerability_class: "SQL Injection".to_string(),
                endpoint: "/b".to_string(),
                parameter: None,
                technique: "t2".to_string(),
                request: None,
                response: None,
            },
        ],
        target_asset: "db".to_string(),
        overall_difficulty: 3.0,
    };
    let narrative = generate_narrative(&input);
    assert!(narrative.impact.contains("1 vulnerability"));
}

#[test]
fn narrative_serializes_to_json() {
    let input = single_step_input();
    let narrative = generate_narrative(&input);
    let json = serde_json::to_string(&narrative);
    assert!(json.is_ok());
    let json_str = json.unwrap();
    assert!(json_str.contains("Attack Chain CHAIN-001"));
    assert!(json_str.contains("SQL Injection"));
}
