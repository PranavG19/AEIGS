use super::*;

#[test]
fn cl_te_probes_generated() {
    let probes = generate_cl_te_probes("/", "example.com");
    assert_eq!(probes.len(), 2);
    assert_eq!(probes[0].technique, SmugglingTechnique::ClTe);
    assert_eq!(probes[0].name, "CL.TE basic");
    assert!(probes[0]
        .treatment_headers
        .iter()
        .any(|(k, _)| k == "Transfer-Encoding"));
    assert!(probes[0]
        .treatment_headers
        .iter()
        .any(|(k, _)| k == "Content-Length"));
    assert!(!probes[0].treatment_body.is_empty());
    assert!(probes[0].control_body.is_empty());
}

#[test]
fn cl_te_timing_probe_short_timeout() {
    let probes = generate_cl_te_probes("/api", "target.local");
    let timing_probe = &probes[1];
    assert_eq!(timing_probe.name, "CL.TE timing");
    assert_eq!(timing_probe.timeout, Duration::from_secs(5));
    assert_eq!(timing_probe.treatment_body, b"1\r\nZ");
}

#[test]
fn te_cl_probe_generated() {
    let probes = generate_te_cl_probes("/", "example.com");
    assert_eq!(probes.len(), 1);
    assert_eq!(probes[0].technique, SmugglingTechnique::TeCl);
    assert_eq!(probes[0].name, "TE.CL basic");

    let cl_header = probes[0]
        .treatment_headers
        .iter()
        .find(|(k, _)| k == "Content-Length");
    assert_eq!(cl_header.unwrap().1, "0");

    let body_str = String::from_utf8_lossy(&probes[0].treatment_body);
    assert!(body_str.contains("POST / HTTP/1.1"));
    assert!(body_str.contains("Host: example.com"));
    assert!(body_str.ends_with("0\r\n\r\n"));
}

#[test]
fn te_te_probes_cover_obfuscations() {
    let probes = generate_te_te_probes("/", "example.com");
    assert!(
        probes.len() >= 6,
        "should generate at least 6 TE.TE variants, got {}",
        probes.len()
    );

    for probe in &probes {
        assert_eq!(probe.technique, SmugglingTechnique::TeTe);
        assert!(probe.obfuscation.is_some());
    }

    let obfusc_names: Vec<String> = probes
        .iter()
        .map(|p| p.obfuscation.as_ref().unwrap().to_string())
        .collect();
    assert!(obfusc_names.contains(&"prefix_junk".to_string()));
    assert!(obfusc_names.contains(&"space_before_colon".to_string()));
    assert!(obfusc_names.contains(&"mixed_case".to_string()));
}

#[test]
fn generate_all_probes_combines_techniques() {
    let probes = generate_all_probes("/", "example.com");
    assert!(
        probes.len() >= 9,
        "should have CL.TE + TE.CL + TE.TE probes, got {}",
        probes.len()
    );

    let techniques: Vec<SmugglingTechnique> = probes.iter().map(|p| p.technique).collect();
    assert!(techniques.contains(&SmugglingTechnique::ClTe));
    assert!(techniques.contains(&SmugglingTechnique::TeCl));
    assert!(techniques.contains(&SmugglingTechnique::TeTe));
}

#[test]
fn evaluate_differential_status_code_mismatch() {
    let evidence = evaluate_differential(200, 1000, 100, 400, 50, 100);
    match evidence {
        SmugglingEvidence::ResponseDifferential {
            treatment_status,
            control_status,
            ..
        } => {
            assert_eq!(treatment_status, 200);
            assert_eq!(control_status, 400);
        }
        other => panic!("expected ResponseDifferential, got {:?}", other),
    }
}

#[test]
fn evaluate_differential_body_length_mismatch() {
    let evidence = evaluate_differential(200, 5000, 100, 200, 100, 100);
    match evidence {
        SmugglingEvidence::ResponseDifferential {
            treatment_body_len,
            control_body_len,
            ..
        } => {
            assert_eq!(treatment_body_len, 5000);
            assert_eq!(control_body_len, 100);
        }
        other => panic!("expected ResponseDifferential, got {:?}", other),
    }
}

#[test]
fn evaluate_differential_timing_mismatch() {
    let evidence = evaluate_differential(200, 100, 8000, 200, 100, 500);
    match evidence {
        SmugglingEvidence::TimingDifferential {
            treatment_ms,
            control_ms,
        } => {
            assert_eq!(treatment_ms, 8000);
            assert_eq!(control_ms, 500);
        }
        other => panic!("expected TimingDifferential, got {:?}", other),
    }
}

#[test]
fn evaluate_differential_no_desync() {
    let evidence = evaluate_differential(200, 1000, 100, 200, 1000, 100);
    assert!(matches!(evidence, SmugglingEvidence::NoDesync));
}

#[test]
fn evaluate_differential_small_body_diff_ignored() {
    let evidence = evaluate_differential(200, 100, 100, 200, 90, 100);
    assert!(
        matches!(evidence, SmugglingEvidence::NoDesync),
        "10-byte difference should not trigger: {:?}",
        evidence
    );
}

#[test]
fn evaluate_differential_timing_needs_significant_gap() {
    let evidence = evaluate_differential(200, 100, 300, 200, 100, 200);
    assert!(
        matches!(evidence, SmugglingEvidence::NoDesync),
        "100ms gap should not trigger timing differential: {:?}",
        evidence
    );
}

#[test]
fn technique_severity_values() {
    assert!(technique_severity(SmugglingTechnique::ClTe) > 9.0);
    assert!(technique_severity(SmugglingTechnique::TeCl) > 9.0);
    assert!(technique_severity(SmugglingTechnique::TeTe) >= 8.0);
    assert!(technique_severity(SmugglingTechnique::H2Cl) > 9.0);
    assert!(technique_severity(SmugglingTechnique::H2Te) > 9.0);
    assert!(technique_severity(SmugglingTechnique::H2cSmuggle) >= 7.0);
}

#[test]
fn build_result_confirmed() {
    let probe = &generate_cl_te_probes("/", "example.com")[0];
    let evidence = SmugglingEvidence::ResponseDifferential {
        treatment_status: 200,
        control_status: 408,
        treatment_body_len: 1000,
        control_body_len: 0,
    };

    let result = build_result(probe, evidence);
    assert!(result.confirmed);
    assert!(result.severity > 9.0);
    assert_eq!(result.technique, SmugglingTechnique::ClTe);
}

#[test]
fn build_result_not_confirmed() {
    let probe = &generate_cl_te_probes("/", "example.com")[0];
    let evidence = SmugglingEvidence::NoDesync;

    let result = build_result(probe, evidence);
    assert!(!result.confirmed);
    assert_eq!(result.severity, 0.0);
}

#[test]
fn technique_display() {
    assert_eq!(format!("{}", SmugglingTechnique::ClTe), "CL.TE");
    assert_eq!(format!("{}", SmugglingTechnique::TeCl), "TE.CL");
    assert_eq!(format!("{}", SmugglingTechnique::TeTe), "TE.TE");
    assert_eq!(format!("{}", SmugglingTechnique::H2Cl), "H2.CL");
    assert_eq!(format!("{}", SmugglingTechnique::H2Te), "H2.TE");
    assert_eq!(format!("{}", SmugglingTechnique::H2cSmuggle), "H2C Smuggle");
}

#[test]
fn obfuscation_display() {
    assert_eq!(format!("{}", TeObfuscation::PrefixJunk), "prefix_junk");
    assert_eq!(
        format!("{}", TeObfuscation::SpaceBeforeColon),
        "space_before_colon"
    );
    assert_eq!(format!("{}", TeObfuscation::TabSeparator), "tab_separator");
    assert_eq!(
        format!("{}", TeObfuscation::DuplicateHeader),
        "duplicate_header"
    );
    assert_eq!(format!("{}", TeObfuscation::VerticalTab), "vertical_tab");
    assert_eq!(format!("{}", TeObfuscation::LineFolding), "line_folding");
    assert_eq!(format!("{}", TeObfuscation::MixedCase), "mixed_case");
    assert_eq!(format!("{}", TeObfuscation::LeadingComma), "leading_comma");
    assert_eq!(
        format!("{}", TeObfuscation::NewlineInValue),
        "newline_in_value"
    );
    assert_eq!(
        format!("{}", TeObfuscation::IdentityPrefix),
        "identity_prefix"
    );
}

#[test]
fn cl_te_smuggled_prefix_contains_host() {
    let probes = generate_cl_te_probes("/target", "vuln.site");
    let body = String::from_utf8_lossy(&probes[0].treatment_body);
    assert!(
        body.contains("vuln.site"),
        "smuggled request should target the correct host"
    );
    assert!(
        body.contains("/target"),
        "smuggled request should target the correct path"
    );
}

#[test]
fn te_cl_chunked_encoding_valid() {
    let probes = generate_te_cl_probes("/", "example.com");
    let body = String::from_utf8_lossy(&probes[0].treatment_body);

    let lines: Vec<&str> = body.split("\r\n").collect();
    let chunk_size_hex = lines[0];
    let chunk_size = usize::from_str_radix(chunk_size_hex, 16).unwrap();

    assert!(
        chunk_size > 0,
        "chunk size should be positive, parsed '{}' = {}",
        chunk_size_hex,
        chunk_size
    );
}

#[test]
fn evaluate_zero_control_body_with_treatment_body() {
    let evidence = evaluate_differential(200, 500, 100, 200, 0, 100);
    match evidence {
        SmugglingEvidence::ResponseDifferential { .. } => {}
        other => panic!(
            "expected ResponseDifferential when control has 0 body, got {:?}",
            other
        ),
    }
}

#[test]
fn evaluate_both_zero_body_no_desync() {
    let evidence = evaluate_differential(200, 0, 100, 200, 0, 100);
    assert!(matches!(evidence, SmugglingEvidence::NoDesync));
}

#[test]
fn te_te_mixed_case_header_name() {
    let probes = generate_te_te_probes("/", "example.com");
    let mixed_case_probe = probes
        .iter()
        .find(|p| p.obfuscation.as_ref() == Some(&TeObfuscation::MixedCase))
        .expect("should have mixed case probe");

    let te_header = mixed_case_probe
        .treatment_headers
        .iter()
        .find(|(k, _)| k.to_lowercase().contains("transfer"))
        .expect("should have transfer-encoding header");

    assert_eq!(te_header.0, "TrAnSfEr-EnCoDiNg");
}

#[test]
fn all_probes_have_host_header() {
    let probes = generate_all_probes("/", "test.local");
    for probe in &probes {
        let has_host = probe
            .treatment_headers
            .iter()
            .any(|(k, v)| k == "Host" && v == "test.local");
        assert!(has_host, "probe '{}' missing Host header", probe.name);
    }
}

#[test]
fn control_requests_are_benign() {
    let probes = generate_all_probes("/", "example.com");
    for probe in &probes {
        let has_te = probe
            .control_headers
            .iter()
            .any(|(k, _)| k.to_lowercase().contains("transfer-encoding"));
        assert!(
            !has_te,
            "control for '{}' should not have Transfer-Encoding",
            probe.name,
        );
    }
}
