use super::header_smuggling::*;

#[test]
fn generate_all_payloads_covers_eight_techniques() {
    let payloads = HeaderSmugglingEngine::generate_all_payloads("example.com");
    let coverage = HeaderSmugglingEngine::technique_coverage(&payloads);
    assert!(
        coverage >= 8,
        "expected ≥8 technique categories, got {coverage}"
    );
}

#[test]
fn generate_all_payloads_non_empty() {
    let payloads = HeaderSmugglingEngine::generate_all_payloads("example.com");
    assert!(
        !payloads.is_empty(),
        "generate_all_payloads must produce at least one payload"
    );
}

#[test]
fn header_name_normalization_produces_at_least_three() {
    let payloads = HeaderSmugglingEngine::header_name_normalization_payloads();
    assert!(
        payloads.len() >= 3,
        "expected ≥3 normalization payloads, got {}",
        payloads.len()
    );
}

#[test]
fn header_name_normalization_technique_tag() {
    for p in HeaderSmugglingEngine::header_name_normalization_payloads() {
        assert_eq!(p.technique, SmuggleTechnique::HeaderNameNormalization);
    }
}

#[test]
fn header_name_normalization_has_dual_headers() {
    for p in HeaderSmugglingEngine::header_name_normalization_payloads() {
        assert!(
            p.headers.len() >= 2,
            "normalization payload must carry both canonical and variant header"
        );
    }
}

#[test]
fn line_folding_payloads_exist() {
    let payloads = HeaderSmugglingEngine::line_folding_payloads();
    assert!(payloads.len() >= 2, "expected ≥2 line-folding payloads");
    for p in &payloads {
        assert_eq!(p.technique, SmuggleTechnique::LineFolding);
        assert!(
            p.raw_suffix.is_some(),
            "line-folding payloads use raw_suffix for CRLF sequences"
        );
    }
}

#[test]
fn line_folding_contains_crlf() {
    for p in HeaderSmugglingEngine::line_folding_payloads() {
        let raw = p.raw_suffix.unwrap();
        assert!(
            raw.contains("\r\n"),
            "line-folding raw payload must contain CRLF"
        );
    }
}

#[test]
fn space_before_colon_payloads_exist() {
    let payloads = HeaderSmugglingEngine::space_before_colon_payloads();
    assert!(payloads.len() >= 2);
    for p in &payloads {
        assert_eq!(p.technique, SmuggleTechnique::SpaceBeforeColon);
    }
}

#[test]
fn space_before_colon_has_trailing_space() {
    for p in HeaderSmugglingEngine::space_before_colon_payloads() {
        let any_trailing_space = p.headers.iter().any(|(name, _)| name.ends_with(' '));
        assert!(
            any_trailing_space,
            "at least one header name should have trailing space"
        );
    }
}

#[test]
fn duplicate_header_payloads_exist() {
    let payloads = HeaderSmugglingEngine::duplicate_header_payloads();
    assert!(payloads.len() >= 4, "expected ≥4 duplicate header payloads");
}

#[test]
fn duplicate_header_payloads_have_matching_names() {
    for p in HeaderSmugglingEngine::duplicate_header_payloads() {
        assert!(p.headers.len() >= 2);
        assert_eq!(
            p.headers[0].0, p.headers[1].0,
            "both headers must share the same name for duplicate testing"
        );
    }
}

#[test]
fn oversized_header_payloads_increasing_size() {
    let payloads = HeaderSmugglingEngine::oversized_header_payloads();
    assert!(payloads.len() >= 3);
    let sizes: Vec<usize> = payloads.iter().map(|p| p.headers[0].1.len()).collect();
    for window in sizes.windows(2) {
        assert!(
            window[1] > window[0],
            "oversized payloads should increase in size"
        );
    }
}

#[test]
fn oversized_header_minimum_8kb() {
    let payloads = HeaderSmugglingEngine::oversized_header_payloads();
    let smallest = payloads.iter().map(|p| p.headers[0].1.len()).min().unwrap();
    assert!(
        smallest >= 8 * 1024,
        "smallest oversized payload must be ≥8 KB, got {smallest}"
    );
}

#[test]
fn transfer_encoding_obfuscation_payloads_exist() {
    let payloads = HeaderSmugglingEngine::transfer_encoding_obfuscation_payloads();
    assert!(payloads.len() >= 6, "expected ≥6 TE obfuscation variants");
    for p in &payloads {
        assert_eq!(p.technique, SmuggleTechnique::TransferEncodingObfuscation);
    }
}

#[test]
fn te_payloads_use_raw_suffix() {
    for p in HeaderSmugglingEngine::transfer_encoding_obfuscation_payloads() {
        assert!(
            p.raw_suffix.is_some(),
            "TE obfuscation payloads rely on raw_suffix for precise byte control"
        );
    }
}

#[test]
fn host_header_at_least_five_variants() {
    let attacks = HeaderSmugglingEngine::generate_host_attacks("target.com");
    assert!(
        attacks.len() >= 5,
        "expected ≥5 host attack variants, got {}",
        attacks.len()
    );
}

#[test]
fn host_header_all_five_variant_types_covered() {
    let attacks = HeaderSmugglingEngine::generate_host_attacks("target.com");
    let variants: std::collections::HashSet<_> = attacks.iter().map(|a| a.variant).collect();
    assert!(variants.contains(&HostAttackVariant::DuplicateHost));
    assert!(variants.contains(&HostAttackVariant::AbsoluteUri));
    assert!(variants.contains(&HostAttackVariant::HostLineInjection));
    assert!(variants.contains(&HostAttackVariant::XForwardedHostOverride));
    assert!(variants.contains(&HostAttackVariant::HostPortInjection));
}

#[test]
fn host_duplicate_has_two_host_headers() {
    let attacks = HeaderSmugglingEngine::generate_host_attacks("target.com");
    let dup = attacks
        .iter()
        .find(|a| a.variant == HostAttackVariant::DuplicateHost)
        .expect("DuplicateHost variant must exist");
    let host_count = dup
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("host"))
        .count();
    assert_eq!(host_count, 2);
}

#[test]
fn host_absolute_uri_present() {
    let attacks = HeaderSmugglingEngine::generate_host_attacks("target.com");
    let abs = attacks
        .iter()
        .find(|a| a.variant == HostAttackVariant::AbsoluteUri)
        .unwrap();
    assert!(
        abs.absolute_uri.is_some(),
        "AbsoluteUri variant must set absolute_uri"
    );
    assert!(abs.absolute_uri.as_ref().unwrap().contains("HTTP/1.1"));
}

#[test]
fn host_line_injection_contains_crlf() {
    let attacks = HeaderSmugglingEngine::generate_host_attacks("target.com");
    let inj = attacks
        .iter()
        .find(|a| a.variant == HostAttackVariant::HostLineInjection)
        .unwrap();
    let host_val = &inj.headers[0].1;
    assert!(
        host_val.contains("\r\n"),
        "HostLineInjection must embed CRLF"
    );
}

#[test]
fn host_port_injection_uses_at_sign() {
    let attacks = HeaderSmugglingEngine::generate_host_attacks("target.com");
    let port = attacks
        .iter()
        .find(|a| a.variant == HostAttackVariant::HostPortInjection)
        .unwrap();
    let host_val = &port.headers[0].1;
    assert!(
        host_val.contains('@'),
        "HostPortInjection must use @ for URL-parser confusion"
    );
}

#[test]
fn cache_key_manipulation_payloads_non_empty() {
    let payloads = HeaderSmugglingEngine::cache_key_manipulation_payloads("target.com");
    assert!(payloads.len() >= 3);
    for p in &payloads {
        assert_eq!(p.technique, SmuggleTechnique::CacheKeyManipulation);
    }
}

#[test]
fn all_payloads_have_detection_method() {
    for p in HeaderSmugglingEngine::generate_all_payloads("example.com") {
        assert!(
            !p.detection_method.is_empty(),
            "payload '{}' missing detection method",
            p.description
        );
    }
}

#[test]
fn all_payloads_have_description() {
    for p in HeaderSmugglingEngine::generate_all_payloads("example.com") {
        assert!(!p.description.is_empty(), "payload has empty description");
    }
}

#[test]
fn fingerprint_first_wins() {
    let fp = HeaderSmugglingEngine::fingerprint_duplicate_handling(
        "X-Forwarded-For",
        "User IP: value-first is active",
    );
    assert_eq!(fp.resolution, DuplicateResolution::FirstWins);
    assert_eq!(fp.header_name, "X-Forwarded-For");
}

#[test]
fn fingerprint_last_wins() {
    let fp =
        HeaderSmugglingEngine::fingerprint_duplicate_handling("Cookie", "session=value-second");
    assert_eq!(fp.resolution, DuplicateResolution::LastWins);
}

#[test]
fn fingerprint_concatenated() {
    let fp = HeaderSmugglingEngine::fingerprint_duplicate_handling(
        "X-Custom",
        "got value-first, value-second together",
    );
    assert_eq!(fp.resolution, DuplicateResolution::Concatenated);
}

#[test]
fn fingerprint_rejected() {
    let fp =
        HeaderSmugglingEngine::fingerprint_duplicate_handling("Authorization", "400 Bad Request");
    assert_eq!(fp.resolution, DuplicateResolution::Rejected);
}

#[test]
fn payloads_at_risk_filters_correctly() {
    let payloads = HeaderSmugglingEngine::generate_all_payloads("example.com");
    let critical = HeaderSmugglingEngine::payloads_at_risk(&payloads, SmuggleRisk::Critical);
    for p in &critical {
        assert_eq!(p.risk, SmuggleRisk::Critical);
    }
    assert!(
        !critical.is_empty(),
        "must have at least one critical payload"
    );
}

#[test]
fn payloads_at_risk_high_includes_critical() {
    let payloads = HeaderSmugglingEngine::generate_all_payloads("example.com");
    let high_plus = HeaderSmugglingEngine::payloads_at_risk(&payloads, SmuggleRisk::High);
    let critical = HeaderSmugglingEngine::payloads_at_risk(&payloads, SmuggleRisk::Critical);
    assert!(high_plus.len() >= critical.len());
}

#[test]
fn display_impls_non_empty() {
    let techniques = [
        SmuggleTechnique::HeaderNameNormalization,
        SmuggleTechnique::LineFolding,
        SmuggleTechnique::SpaceBeforeColon,
        SmuggleTechnique::DuplicateHeader,
        SmuggleTechnique::OversizedHeader,
        SmuggleTechnique::TransferEncodingObfuscation,
        SmuggleTechnique::HostHeaderAttack,
        SmuggleTechnique::CacheKeyManipulation,
    ];
    for t in &techniques {
        let s = format!("{t}");
        assert!(!s.is_empty());
    }

    let risks = [
        SmuggleRisk::Low,
        SmuggleRisk::Medium,
        SmuggleRisk::High,
        SmuggleRisk::Critical,
    ];
    for r in &risks {
        assert!(!format!("{r}").is_empty());
    }

    let resolutions = [
        DuplicateResolution::FirstWins,
        DuplicateResolution::LastWins,
        DuplicateResolution::Concatenated,
        DuplicateResolution::Rejected,
    ];
    for d in &resolutions {
        assert!(!format!("{d}").is_empty());
    }

    let variants = [
        HostAttackVariant::DuplicateHost,
        HostAttackVariant::AbsoluteUri,
        HostAttackVariant::HostLineInjection,
        HostAttackVariant::XForwardedHostOverride,
        HostAttackVariant::HostPortInjection,
    ];
    for v in &variants {
        assert!(!format!("{v}").is_empty());
    }
}

#[test]
fn host_payloads_wrapped_as_smuggle_payloads() {
    let payloads = HeaderSmugglingEngine::host_header_payloads("target.com");
    assert!(payloads.len() >= 5);
    for p in &payloads {
        assert_eq!(p.technique, SmuggleTechnique::HostHeaderAttack);
    }
}
