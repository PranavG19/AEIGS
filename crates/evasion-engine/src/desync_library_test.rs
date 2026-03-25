use super::desync_library::*;

#[test]
fn cl_te_payloads_generated() {
    let lib = DesyncLibrary::new();
    let payloads = lib.cl_te_payloads();

    assert_eq!(payloads.len(), 5);
    assert!(payloads
        .iter()
        .all(|p| p.technique == DesyncTechnique::ClTe));
    assert!(payloads.iter().any(|p| p.impact == DesyncImpact::Detection));
    assert!(payloads
        .iter()
        .any(|p| p.impact == DesyncImpact::SecurityBypass));
    assert!(payloads
        .iter()
        .any(|p| p.impact == DesyncImpact::RequestCapture));
    assert!(payloads
        .iter()
        .any(|p| p.impact == DesyncImpact::CachePoisoning));
}

#[test]
fn cl_te_detection_payload_structure() {
    let lib = DesyncLibrary::new();
    let payloads = lib.cl_te_payloads();
    let detection = &payloads[0];

    assert!(detection.raw_request.contains("Content-Length: 6"));
    assert!(detection.raw_request.contains("Transfer-Encoding: chunked"));
    assert!(detection.raw_request.contains("0\r\n\r\nG"));
    assert!(detection.description.contains("CL.TE"));
}

#[test]
fn cl_te_admin_bypass_contains_smuggled_request() {
    let lib = DesyncLibrary::new();
    let payloads = lib.cl_te_payloads();
    let admin_bypass = payloads
        .iter()
        .find(|p| p.impact == DesyncImpact::SecurityBypass)
        .unwrap();

    assert!(admin_bypass.raw_request.contains("GET /admin HTTP/1.1"));
}

#[test]
fn te_cl_payloads_generated() {
    let lib = DesyncLibrary::new();
    let payloads = lib.te_cl_payloads();

    assert_eq!(payloads.len(), 4);
    assert!(payloads
        .iter()
        .all(|p| p.technique == DesyncTechnique::TeCl));
}

#[test]
fn te_cl_request_capture() {
    let lib = DesyncLibrary::new();
    let payloads = lib.te_cl_payloads();
    let capture = payloads
        .iter()
        .find(|p| p.impact == DesyncImpact::RequestCapture)
        .unwrap();

    assert!(capture.raw_request.contains("Content-Length: 200000"));
    assert!(capture.raw_request.contains("stolen="));
}

#[test]
fn te_te_payloads_cover_all_obfuscation_variants() {
    let lib = DesyncLibrary::new();
    let payloads = lib.te_te_payloads();

    assert_eq!(payloads.len(), 15, "should have 15 TE obfuscation variants");
    assert!(payloads
        .iter()
        .all(|p| p.technique == DesyncTechnique::TeTe));
    assert!(payloads
        .iter()
        .all(|p| p.transfer_encoding_variant.is_some()));

    let variants: Vec<_> = payloads
        .iter()
        .map(|p| p.transfer_encoding_variant.as_ref().unwrap().as_str())
        .collect();
    assert!(variants.contains(&"standard"));
    assert!(variants.contains(&"capitalized"));
    assert!(variants.contains(&"trailing_space"));
    assert!(variants.contains(&"tab_before_value"));
    assert!(variants.contains(&"double_te"));
    assert!(variants.contains(&"null_byte"));
    assert!(variants.contains(&"mixed_case"));
}

#[test]
fn h2_downgrade_payloads() {
    let lib = DesyncLibrary::new();
    let payloads = lib.h2_downgrade_payloads();

    assert_eq!(payloads.len(), 4);
    let h2cl: Vec<_> = payloads
        .iter()
        .filter(|p| p.technique == DesyncTechnique::H2Cl)
        .collect();
    let h2te: Vec<_> = payloads
        .iter()
        .filter(|p| p.technique == DesyncTechnique::H2Te)
        .collect();
    assert_eq!(h2cl.len(), 2);
    assert_eq!(h2te.len(), 2);
}

#[test]
fn h2_cl_payload_contains_pseudo_headers() {
    let lib = DesyncLibrary::new();
    let payloads = lib.h2_downgrade_payloads();
    let h2cl = &payloads[0];

    assert!(h2cl.raw_request.contains(":method POST"));
    assert!(h2cl.raw_request.contains(":path /"));
    assert!(h2cl.raw_request.contains(":authority"));
    assert!(h2cl.raw_request.contains("content-length: 0"));
}

#[test]
fn request_tunneling_payloads() {
    let lib = DesyncLibrary::new();
    let payloads = lib.request_tunneling_payloads();

    assert_eq!(payloads.len(), 3);
    assert!(payloads
        .iter()
        .all(|p| p.technique == DesyncTechnique::RequestTunneling));
    assert!(payloads
        .iter()
        .any(|p| p.raw_request.contains("/internal-api/users")));
    assert!(payloads
        .iter()
        .any(|p| p.raw_request.contains("password-reset")));
    assert!(payloads.iter().any(|p| p.raw_request.contains("DELETE")));
}

#[test]
fn websocket_smuggling_payloads() {
    let lib = DesyncLibrary::new();
    let payloads = lib.websocket_smuggling_payloads();

    assert_eq!(payloads.len(), 3);
    assert!(payloads
        .iter()
        .all(|p| p.technique == DesyncTechnique::WebSocketSmuggling));
    assert!(payloads
        .iter()
        .all(|p| p.raw_request.contains("Upgrade: websocket")));
    assert!(payloads.iter().any(|p| p.raw_request.contains("socket.io")));
}

#[test]
fn hop_by_hop_payloads() {
    let lib = DesyncLibrary::new();
    let payloads = lib.hop_by_hop_payloads();

    assert_eq!(payloads.len(), 8);
    assert!(payloads
        .iter()
        .all(|p| p.technique == DesyncTechnique::HopByHop));
    assert!(payloads
        .iter()
        .all(|p| p.raw_request.contains("Connection: close,")));
    assert!(payloads
        .iter()
        .any(|p| p.raw_request.contains("Authorization")));
    assert!(payloads.iter().any(|p| p.raw_request.contains("Cookie")));
    assert!(payloads
        .iter()
        .any(|p| p.raw_request.contains("X-Csrf-Token")));
}

#[test]
fn h2_crlf_injection_payloads() {
    let lib = DesyncLibrary::new();
    let payloads = lib.h2_crlf_injection_payloads();

    assert_eq!(payloads.len(), 2);
    assert!(payloads
        .iter()
        .all(|p| p.technique == DesyncTechnique::H2CrlfInjection));
    assert!(payloads.iter().any(|p| p.raw_request.contains("\\r\\n")));
}

#[test]
fn header_duplication_payloads() {
    let lib = DesyncLibrary::new();
    let payloads = lib.header_duplication_payloads();

    assert_eq!(payloads.len(), 3);
    assert!(payloads
        .iter()
        .all(|p| p.technique == DesyncTechnique::HeaderDuplication));
}

#[test]
fn full_library_has_50_plus_payloads() {
    let lib = DesyncLibrary::new();
    let all = lib.generate_full_library();

    assert!(
        all.len() >= 50,
        "full library should have 50+ payloads, got {}",
        all.len()
    );
}

#[test]
fn full_library_covers_all_techniques() {
    let lib = DesyncLibrary::new();
    let all = lib.generate_full_library();

    let techniques: Vec<_> = all.iter().map(|p| p.technique).collect();
    assert!(techniques.contains(&DesyncTechnique::ClTe));
    assert!(techniques.contains(&DesyncTechnique::TeCl));
    assert!(techniques.contains(&DesyncTechnique::TeTe));
    assert!(techniques.contains(&DesyncTechnique::H2Cl));
    assert!(techniques.contains(&DesyncTechnique::H2Te));
    assert!(techniques.contains(&DesyncTechnique::RequestTunneling));
    assert!(techniques.contains(&DesyncTechnique::WebSocketSmuggling));
    assert!(techniques.contains(&DesyncTechnique::HopByHop));
    assert!(techniques.contains(&DesyncTechnique::H2CrlfInjection));
    assert!(techniques.contains(&DesyncTechnique::HeaderDuplication));
}

#[test]
fn unique_payload_ids() {
    let lib = DesyncLibrary::new();
    let all = lib.generate_full_library();
    let ids: Vec<_> = all.iter().map(|p| p.id).collect();
    let unique: std::collections::HashSet<_> = ids.iter().collect();
    assert_eq!(ids.len(), unique.len(), "all payload IDs should be unique");
}

#[test]
fn filter_by_technique() {
    let lib = DesyncLibrary::new();
    let cl_te = lib.payloads_by_technique(DesyncTechnique::ClTe);
    assert_eq!(cl_te.len(), 5);
    assert!(cl_te.iter().all(|p| p.technique == DesyncTechnique::ClTe));
}

#[test]
fn filter_by_min_impact() {
    let lib = DesyncLibrary::new();
    let high_impact = lib.payloads_by_min_impact(DesyncImpact::RequestCapture);

    assert!(!high_impact.is_empty());
    assert!(high_impact
        .iter()
        .all(|p| p.impact >= DesyncImpact::RequestCapture));
}

#[test]
fn custom_target_host() {
    let lib = DesyncLibrary::new().with_target_host("my-app.com".into());
    let payloads = lib.cl_te_payloads();
    assert!(payloads
        .iter()
        .all(|p| p.raw_request.contains("my-app.com")));
}

#[test]
fn custom_smuggled_host() {
    let lib = DesyncLibrary::new().with_smuggled_host("my-evil.com".into());
    let payloads = lib.cl_te_payloads();
    let capture = payloads
        .iter()
        .find(|p| p.impact == DesyncImpact::RequestCapture)
        .unwrap();
    assert!(capture.raw_request.contains("my-evil.com"));
}

#[test]
fn desync_technique_display() {
    assert_eq!(DesyncTechnique::ClTe.to_string(), "CL.TE");
    assert_eq!(DesyncTechnique::TeCl.to_string(), "TE.CL");
    assert_eq!(DesyncTechnique::TeTe.to_string(), "TE.TE");
    assert_eq!(DesyncTechnique::H2Cl.to_string(), "H2.CL");
    assert_eq!(DesyncTechnique::H2Te.to_string(), "H2.TE");
    assert_eq!(
        DesyncTechnique::WebSocketSmuggling.to_string(),
        "WebSocket Smuggling"
    );
    assert_eq!(DesyncTechnique::HopByHop.to_string(), "Hop-by-Hop Abuse");
}

#[test]
fn desync_impact_display() {
    assert_eq!(DesyncImpact::Detection.to_string(), "Detection");
    assert_eq!(
        DesyncImpact::RequestHijacking.to_string(),
        "Request Hijacking"
    );
}

#[test]
fn desync_impact_ordering() {
    assert!(DesyncImpact::Detection < DesyncImpact::CachePoisoning);
    assert!(DesyncImpact::CachePoisoning < DesyncImpact::RequestCapture);
    assert!(DesyncImpact::SecurityBypass < DesyncImpact::ResponseSplitting);
    assert!(DesyncImpact::ResponseSplitting < DesyncImpact::RequestHijacking);
}

#[test]
fn default_library() {
    let lib = DesyncLibrary::default();
    let payloads = lib.cl_te_payloads();
    assert!(payloads[0].raw_request.contains("vulnerable-app.com"));
}

#[test]
fn all_payloads_have_descriptions() {
    let lib = DesyncLibrary::new();
    let all = lib.generate_full_library();
    for p in &all {
        assert!(
            !p.description.is_empty(),
            "payload {} has empty description",
            p.id
        );
        assert!(
            !p.expected_behavior.is_empty(),
            "payload {} has empty expected_behavior",
            p.id
        );
    }
}

#[test]
fn all_payloads_have_raw_requests() {
    let lib = DesyncLibrary::new();
    let all = lib.generate_full_library();
    for p in &all {
        assert!(
            !p.raw_request.is_empty(),
            "payload {} has empty raw_request",
            p.id
        );
    }
}
