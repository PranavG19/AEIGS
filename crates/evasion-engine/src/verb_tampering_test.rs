use super::verb_tampering::*;

#[test]
fn technique_all_returns_ten_variants() {
    let all = VerbTamperingTechnique::all();
    assert_eq!(all.len(), 10);
}

#[test]
fn technique_display_no_empty_strings() {
    for t in VerbTamperingTechnique::all() {
        let display = format!("{t}");
        assert!(!display.is_empty(), "Display for {t:?} was empty");
    }
}

#[test]
fn technique_risk_scores_within_bounds() {
    for t in VerbTamperingTechnique::all() {
        let score = t.risk_score();
        assert!(
            (0.0..=1.0).contains(&score),
            "Risk score {score} out of bounds for {t:?}"
        );
    }
}

#[test]
fn technique_serialization_roundtrip() {
    for t in VerbTamperingTechnique::all() {
        let json = serde_json::to_string(t).unwrap();
        let back: VerbTamperingTechnique = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, back);
    }
}

#[test]
fn http_method_as_str_uppercase() {
    for m in HttpMethod::standard_rest() {
        let s = m.as_str();
        assert_eq!(s, s.to_uppercase(), "Method {s} not uppercase");
    }
    for m in HttpMethod::dangerous() {
        let s = m.as_str();
        assert_eq!(s, s.to_uppercase(), "Dangerous method {s} not uppercase");
    }
}

#[test]
fn http_method_standard_rest_count() {
    assert_eq!(HttpMethod::standard_rest().len(), 7);
}

#[test]
fn http_method_dangerous_count() {
    assert_eq!(HttpMethod::dangerous().len(), 3);
}

#[test]
fn http_method_display_matches_as_str() {
    for m in HttpMethod::standard_rest() {
        assert_eq!(format!("{m}"), m.as_str());
    }
}

#[test]
fn override_header_all_returns_four() {
    assert_eq!(MethodOverrideHeader::all().len(), 4);
}

#[test]
fn override_header_names_contain_override_or_method() {
    for h in MethodOverrideHeader::all() {
        let name = h.header_name().to_lowercase();
        assert!(
            name.contains("method") || name.contains("override"),
            "Header name '{}' missing expected keyword",
            h.header_name()
        );
    }
}

#[test]
fn override_header_display_matches_header_name() {
    for h in MethodOverrideHeader::all() {
        assert_eq!(format!("{h}"), h.header_name());
    }
}

#[test]
fn override_param_all_returns_three() {
    assert_eq!(MethodOverrideParam::all().len(), 3);
}

#[test]
fn override_param_names_nonempty() {
    for p in MethodOverrideParam::all() {
        assert!(!p.param_name().is_empty());
    }
}

#[test]
fn webdav_methods_all_seven() {
    assert_eq!(WebDavMethod::all().len(), 7);
}

#[test]
fn webdav_method_as_str_uppercase() {
    for m in WebDavMethod::all() {
        let s = m.as_str();
        assert_eq!(s, s.to_uppercase(), "WebDAV method {s} not uppercase");
    }
}

#[test]
fn engine_generate_probes_not_empty() {
    let engine = VerbTamperingEngine::new();
    let probes = engine.generate_probes("/api/users", "GET");
    assert!(!probes.is_empty(), "Engine produced zero probes");
}

#[test]
fn engine_standard_switch_excludes_original_method() {
    let engine = VerbTamperingEngine::new();
    let probes = engine.standard_method_switch_probes("/api/data", "GET");
    for p in &probes {
        assert_ne!(p.method, "GET", "Should not re-test the original method");
    }
    assert_eq!(
        probes.len(),
        6,
        "7 standard REST methods minus 1 original = 6"
    );
}

#[test]
fn engine_standard_switch_case_insensitive_original() {
    let engine = VerbTamperingEngine::new();
    let probes_lower = engine.standard_method_switch_probes("/api/data", "get");
    for p in &probes_lower {
        assert_ne!(p.method, "GET", "Should normalize original to uppercase");
    }
}

#[test]
fn engine_method_override_header_probes_structure() {
    let engine = VerbTamperingEngine::new();
    let probes = engine.method_override_header_probes("/admin", "POST");
    assert!(!probes.is_empty());
    for p in &probes {
        assert_eq!(p.method, "POST", "Override probes use POST as wire method");
        assert_eq!(p.override_headers.len(), 1);
        assert!(p.override_params.is_empty());
    }
}

#[test]
fn engine_method_override_param_probes_structure() {
    let engine = VerbTamperingEngine::new();
    let probes = engine.method_override_param_probes("/admin", "POST");
    assert!(!probes.is_empty());
    for p in &probes {
        assert_eq!(p.method, "POST");
        assert!(p.override_headers.is_empty());
        assert_eq!(p.override_params.len(), 1);
    }
}

#[test]
fn engine_cross_site_tracing_two_probes() {
    let engine = VerbTamperingEngine::new();
    let probes = engine.cross_site_tracing_probes("/test");
    assert_eq!(probes.len(), 2);
    let methods: Vec<&str> = probes.iter().map(|p| p.method.as_str()).collect();
    assert!(methods.contains(&"TRACE"));
    assert!(methods.contains(&"TRACK"));
}

#[test]
fn engine_connect_abuse_single_probe() {
    let engine = VerbTamperingEngine::new();
    let probes = engine.connect_abuse_probes("/test");
    assert_eq!(probes.len(), 1);
    assert_eq!(probes[0].method, "CONNECT");
}

#[test]
fn engine_webdav_probes_count() {
    let engine = VerbTamperingEngine::new();
    let probes = engine.webdav_probes("/test");
    assert_eq!(probes.len(), 7, "One probe per WebDAV method");
}

#[test]
fn engine_head_leakage_single_probe() {
    let engine = VerbTamperingEngine::new();
    let probes = engine.head_leakage_probes("/test");
    assert_eq!(probes.len(), 1);
    assert_eq!(probes[0].method, "HEAD");
}

#[test]
fn engine_case_sensitivity_probes_nonempty() {
    let engine = VerbTamperingEngine::new();
    let probes = engine.case_sensitivity_probes("/test");
    assert!(
        probes.len() >= 10,
        "Should have many case variants, got {}",
        probes.len()
    );
    for p in &probes {
        assert_ne!(
            p.method,
            p.method.to_uppercase(),
            "Case variant should not be canonical uppercase"
        );
    }
}

#[test]
fn engine_arbitrary_method_probes_nonempty() {
    let engine = VerbTamperingEngine::new();
    let probes = engine.arbitrary_method_probes("/test");
    assert!(probes.len() >= 3);
    let standard: Vec<&str> = HttpMethod::standard_rest()
        .iter()
        .map(|m| m.as_str())
        .collect();
    for p in &probes {
        assert!(
            !standard.contains(&p.method.as_str()),
            "Arbitrary method {} should not be a standard method",
            p.method
        );
    }
}

#[test]
fn engine_auth_bypass_probes_exclude_original() {
    let engine = VerbTamperingEngine::new();
    let probes = engine.auth_bypass_probes("/admin/delete", "POST");
    for p in &probes {
        assert_ne!(p.method, "POST");
    }
    assert_eq!(probes.len(), 4, "5 bypass methods minus POST = 4");
}

#[test]
fn classify_response_trace_echoed() {
    let probe = VerbTamperingProbe {
        technique: VerbTamperingTechnique::CrossSiteTracing,
        method: "TRACE".to_string(),
        override_headers: Vec::new(),
        override_params: Vec::new(),
        description: "test".to_string(),
    };
    let outcome = classify_response(&probe, 200, "TRACE /test HTTP/1.1", &[]);
    assert!(matches!(
        outcome,
        TamperingOutcome::TraceEchoed {
            echoed_headers: true
        }
    ));
}

#[test]
fn classify_response_trace_rejected() {
    let probe = VerbTamperingProbe {
        technique: VerbTamperingTechnique::CrossSiteTracing,
        method: "TRACE".to_string(),
        override_headers: Vec::new(),
        override_params: Vec::new(),
        description: "test".to_string(),
    };
    let outcome = classify_response(&probe, 405, "Method Not Allowed", &[]);
    assert!(matches!(
        outcome,
        TamperingOutcome::Rejected { status_code: 405 }
    ));
}

#[test]
fn classify_response_head_body_leakage() {
    let probe = VerbTamperingProbe {
        technique: VerbTamperingTechnique::HeadResponseLeakage,
        method: "HEAD".to_string(),
        override_headers: Vec::new(),
        override_params: Vec::new(),
        description: "test".to_string(),
    };
    let outcome = classify_response(&probe, 200, "some leaked body content", &[]);
    assert!(matches!(
        outcome,
        TamperingOutcome::HeadBodyLeakage { body_length: 24 }
    ));
    assert!(outcome.is_vulnerable());
}

#[test]
fn classify_response_head_no_body() {
    let probe = VerbTamperingProbe {
        technique: VerbTamperingTechnique::HeadResponseLeakage,
        method: "HEAD".to_string(),
        override_headers: Vec::new(),
        override_params: Vec::new(),
        description: "test".to_string(),
    };
    let outcome = classify_response(&probe, 200, "", &[]);
    assert!(matches!(
        outcome,
        TamperingOutcome::Accepted { status_code: 200 }
    ));
    assert!(!outcome.is_vulnerable());
}

#[test]
fn classify_response_override_honored() {
    let probe = VerbTamperingProbe {
        technique: VerbTamperingTechnique::MethodOverrideHeader,
        method: "POST".to_string(),
        override_headers: vec![("X-HTTP-Method-Override".to_string(), "DELETE".to_string())],
        override_params: Vec::new(),
        description: "test".to_string(),
    };
    let outcome = classify_response(&probe, 200, "", &[]);
    assert!(matches!(
        outcome,
        TamperingOutcome::OverrideHonored { ref effective_method, status_code: 200 }
        if effective_method == "DELETE"
    ));
    assert!(outcome.is_vulnerable());
}

#[test]
fn classify_response_override_rejected() {
    let probe = VerbTamperingProbe {
        technique: VerbTamperingTechnique::MethodOverrideHeader,
        method: "POST".to_string(),
        override_headers: vec![("X-HTTP-Method-Override".to_string(), "DELETE".to_string())],
        override_params: Vec::new(),
        description: "test".to_string(),
    };
    let outcome = classify_response(&probe, 403, "Forbidden", &[]);
    assert!(matches!(
        outcome,
        TamperingOutcome::Rejected { status_code: 403 }
    ));
}

#[test]
fn classify_response_auth_bypass_success() {
    let probe = VerbTamperingProbe {
        technique: VerbTamperingTechnique::MethodAuthBypass,
        method: "GET".to_string(),
        override_headers: Vec::new(),
        override_params: Vec::new(),
        description: "Auth bypass: switch from POST to GET on restricted endpoint".to_string(),
    };
    let outcome = classify_response(&probe, 200, "admin data", &[]);
    assert!(matches!(outcome, TamperingOutcome::AuthBypassed { .. }));
    assert!(outcome.is_vulnerable());
}

#[test]
fn classify_response_server_error() {
    let probe = VerbTamperingProbe {
        technique: VerbTamperingTechnique::ArbitraryMethodProbe,
        method: "FOO".to_string(),
        override_headers: Vec::new(),
        override_params: Vec::new(),
        description: "test".to_string(),
    };
    let outcome = classify_response(&probe, 500, "Internal Server Error", &[]);
    assert!(matches!(
        outcome,
        TamperingOutcome::ServerError { status_code: 500 }
    ));
    assert!(outcome.is_interesting());
}

#[test]
fn classify_response_standard_accepted() {
    let probe = VerbTamperingProbe {
        technique: VerbTamperingTechnique::StandardMethodSwitch,
        method: "PUT".to_string(),
        override_headers: Vec::new(),
        override_params: Vec::new(),
        description: "test".to_string(),
    };
    let outcome = classify_response(&probe, 200, "", &[]);
    assert!(matches!(
        outcome,
        TamperingOutcome::Accepted { status_code: 200 }
    ));
    assert!(outcome.is_interesting());
}

#[test]
fn classify_response_standard_rejected() {
    let probe = VerbTamperingProbe {
        technique: VerbTamperingTechnique::StandardMethodSwitch,
        method: "PUT".to_string(),
        override_headers: Vec::new(),
        override_params: Vec::new(),
        description: "test".to_string(),
    };
    let outcome = classify_response(&probe, 405, "", &[]);
    assert!(matches!(
        outcome,
        TamperingOutcome::Rejected { status_code: 405 }
    ));
    assert!(!outcome.is_interesting());
}

#[test]
fn tampering_outcome_display_formats() {
    let cases: Vec<TamperingOutcome> = vec![
        TamperingOutcome::Accepted { status_code: 200 },
        TamperingOutcome::Rejected { status_code: 405 },
        TamperingOutcome::OverrideHonored {
            effective_method: "DELETE".into(),
            status_code: 200,
        },
        TamperingOutcome::HeadBodyLeakage { body_length: 42 },
        TamperingOutcome::TraceEchoed {
            echoed_headers: true,
        },
        TamperingOutcome::TraceEchoed {
            echoed_headers: false,
        },
        TamperingOutcome::AuthBypassed {
            original_method: "POST".into(),
            bypass_method: "GET".into(),
            status_code: 200,
        },
        TamperingOutcome::ServerError { status_code: 500 },
    ];
    for outcome in &cases {
        let s = format!("{outcome}");
        assert!(!s.is_empty(), "Display was empty for {outcome:?}");
    }
}

#[test]
fn build_result_aggregates_findings() {
    let probe1 = VerbTamperingProbe {
        technique: VerbTamperingTechnique::StandardMethodSwitch,
        method: "PUT".to_string(),
        override_headers: Vec::new(),
        override_params: Vec::new(),
        description: "switch to PUT".to_string(),
    };
    let probe2 = VerbTamperingProbe {
        technique: VerbTamperingTechnique::CrossSiteTracing,
        method: "TRACE".to_string(),
        override_headers: Vec::new(),
        override_params: Vec::new(),
        description: "TRACE test".to_string(),
    };
    let result = build_result(
        "/api/test",
        "GET",
        vec![
            (probe1, TamperingOutcome::Accepted { status_code: 200 }),
            (
                probe2,
                TamperingOutcome::TraceEchoed {
                    echoed_headers: true,
                },
            ),
        ],
    );
    assert_eq!(result.endpoint, "/api/test");
    assert_eq!(result.original_method, "GET");
    assert_eq!(result.findings.len(), 2);
}

#[test]
fn result_vulnerabilities_filters_correctly() {
    let probe_safe = VerbTamperingProbe {
        technique: VerbTamperingTechnique::StandardMethodSwitch,
        method: "PUT".to_string(),
        override_headers: Vec::new(),
        override_params: Vec::new(),
        description: "safe".to_string(),
    };
    let probe_vuln = VerbTamperingProbe {
        technique: VerbTamperingTechnique::CrossSiteTracing,
        method: "TRACE".to_string(),
        override_headers: Vec::new(),
        override_params: Vec::new(),
        description: "vuln".to_string(),
    };
    let result = build_result(
        "/test",
        "GET",
        vec![
            (probe_safe, TamperingOutcome::Rejected { status_code: 405 }),
            (
                probe_vuln,
                TamperingOutcome::TraceEchoed {
                    echoed_headers: true,
                },
            ),
        ],
    );
    let vulns = result.vulnerabilities();
    assert_eq!(vulns.len(), 1);
    assert_eq!(vulns[0].technique, VerbTamperingTechnique::CrossSiteTracing);
}

#[test]
fn result_max_risk_returns_highest() {
    let probe1 = VerbTamperingProbe {
        technique: VerbTamperingTechnique::CaseSensitivityProbe,
        method: "get".to_string(),
        override_headers: Vec::new(),
        override_params: Vec::new(),
        description: "low risk".to_string(),
    };
    let probe2 = VerbTamperingProbe {
        technique: VerbTamperingTechnique::MethodAuthBypass,
        method: "GET".to_string(),
        override_headers: Vec::new(),
        override_params: Vec::new(),
        description: "high risk".to_string(),
    };
    let result = build_result(
        "/test",
        "POST",
        vec![
            (probe1, TamperingOutcome::Accepted { status_code: 200 }),
            (
                probe2,
                TamperingOutcome::AuthBypassed {
                    original_method: "POST".into(),
                    bypass_method: "GET".into(),
                    status_code: 200,
                },
            ),
        ],
    );
    assert!((result.max_risk() - 0.9).abs() < f64::EPSILON);
}

#[test]
fn result_max_risk_empty_findings() {
    let result = build_result("/test", "GET", vec![]);
    assert!((result.max_risk() - 0.0).abs() < f64::EPSILON);
}

#[test]
fn engine_default_works() {
    let engine = VerbTamperingEngine::default();
    let probes = engine.generate_probes("/test", "GET");
    assert!(!probes.is_empty());
}

#[test]
fn engine_generate_probes_covers_all_techniques() {
    let engine = VerbTamperingEngine::new();
    let probes = engine.generate_probes("/api/resource", "POST");
    let mut seen = std::collections::HashSet::new();
    for p in &probes {
        seen.insert(p.technique);
    }
    for t in VerbTamperingTechnique::all() {
        assert!(
            seen.contains(t),
            "Technique {t:?} not covered by generate_probes"
        );
    }
}

#[test]
fn classify_response_param_override_honored() {
    let probe = VerbTamperingProbe {
        technique: VerbTamperingTechnique::MethodOverrideParam,
        method: "POST".to_string(),
        override_headers: Vec::new(),
        override_params: vec![("_method".to_string(), "PUT".to_string())],
        description: "test".to_string(),
    };
    let outcome = classify_response(&probe, 200, "", &[]);
    assert!(matches!(
        outcome,
        TamperingOutcome::OverrideHonored { ref effective_method, status_code: 200 }
        if effective_method == "PUT"
    ));
}

#[test]
fn probe_serialization_roundtrip() {
    let probe = VerbTamperingProbe {
        technique: VerbTamperingTechnique::MethodOverrideHeader,
        method: "POST".to_string(),
        override_headers: vec![("X-HTTP-Method-Override".to_string(), "DELETE".to_string())],
        override_params: Vec::new(),
        description: "roundtrip test".to_string(),
    };
    let json = serde_json::to_string(&probe).unwrap();
    let back: VerbTamperingProbe = serde_json::from_str(&json).unwrap();
    assert_eq!(probe, back);
}

#[test]
fn finding_serialization_roundtrip() {
    let finding = VerbTamperingFinding {
        technique: VerbTamperingTechnique::CrossSiteTracing,
        probe: VerbTamperingProbe {
            technique: VerbTamperingTechnique::CrossSiteTracing,
            method: "TRACE".to_string(),
            override_headers: Vec::new(),
            override_params: Vec::new(),
            description: "xst".to_string(),
        },
        outcome: TamperingOutcome::TraceEchoed {
            echoed_headers: true,
        },
    };
    let json = serde_json::to_string(&finding).unwrap();
    let back: VerbTamperingFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(finding, back);
}

#[test]
fn outcome_is_vulnerable_negative_cases() {
    let not_vuln = vec![
        TamperingOutcome::Accepted { status_code: 200 },
        TamperingOutcome::Rejected { status_code: 405 },
        TamperingOutcome::TraceEchoed {
            echoed_headers: false,
        },
        TamperingOutcome::ServerError { status_code: 500 },
    ];
    for outcome in &not_vuln {
        assert!(
            !outcome.is_vulnerable(),
            "{outcome:?} should not be vulnerable"
        );
    }
}

#[test]
fn outcome_is_interesting_negative_cases() {
    let not_interesting = vec![
        TamperingOutcome::Rejected { status_code: 405 },
        TamperingOutcome::Rejected { status_code: 403 },
    ];
    for outcome in &not_interesting {
        assert!(
            !outcome.is_interesting(),
            "{outcome:?} should not be interesting"
        );
    }
}
