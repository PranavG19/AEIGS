use std::collections::HashSet;
use std::path::{Path, PathBuf};

use aegis_exploiter::{
    AmassWrapper, ExploitContext, ExploitResult, GauWrapper, ToolWrapper, TrufflehogWrapper,
    spawn_with_timeout,
};
use aegis_passive_recon::dependency_parser::{ParsedDependency, parse_lock_file};
use aegis_passive_recon::filesystem_walker::{FileClassification, walk_directory};
use aegis_passive_recon::vuln_database::VulnDatabase;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::phase_error::PhaseError;
use crate::pipeline::{PhaseResult, ScanContext};
use crate::recon_client;
use crate::util::{extract_path_from_url, timestamp_ms};

struct SharedResponse {
    headers: reqwest::header::HeaderMap,
    body: String,
    is_https: bool,
    target_domain: Option<String>,
}

fn fetch_shared_response(target: &str) -> Option<SharedResponse> {
    let target_domain = recon_client::validated_domain(target);
    target_domain.as_ref()?;
    let client = recon_client::default_client()?;
    let resp = client.get(target).send().ok()?;
    let is_https = target.starts_with("https://");
    let headers = resp.headers().clone();
    let body = resp.text().ok()?;
    Some(SharedResponse {
        headers,
        body,
        is_https,
        target_domain,
    })
}

fn hdr(resp: &SharedResponse, name: &str) -> Option<String> {
    resp.headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn hdr_all(resp: &SharedResponse, name: &str) -> Vec<String> {
    resp.headers
        .get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok().map(|s| s.to_string()))
        .collect()
}

macro_rules! collect_ops {
    ($seq:expr, $fc:expr, $entries:expr, $issues:expr, $to_ops:expr) => {{
        let ops = $to_ops(&$issues, $seq);
        *$fc += ops.len() as u64;
        $entries.extend(ops);
    }};
}

fn run_header_analyzers(
    resp: &SharedResponse,
    seq: &mut u64,
    entries: &mut Vec<OperationLogEntry>,
    fc: &mut u64,
) {
    let domain = resp.target_domain.as_deref();

    // Missing security headers
    let hdr_findings = crate::header_audit::check_missing_headers(&resp.headers);
    collect_ops!(
        seq,
        fc,
        entries,
        hdr_findings,
        crate::header_audit::header_findings_to_operations
    );

    // CSP
    let csp_val = hdr(resp, "content-security-policy");
    let csp_issues = crate::csp_analyzer::analyze_csp_header(csp_val.as_deref());
    collect_ops!(
        seq,
        fc,
        entries,
        csp_issues,
        crate::csp_analyzer::csp_findings_to_operations
    );

    // CSP nonce/hash quality
    let csp_nonce_issues =
        crate::csp_nonce_audit::analyze_csp_nonces(csp_val.as_deref().unwrap_or(""));
    collect_ops!(
        seq,
        fc,
        entries,
        csp_nonce_issues,
        crate::csp_nonce_audit::csp_nonce_to_operations
    );

    // HSTS
    let hsts_val = hdr(resp, "strict-transport-security");
    let hsts_issues = crate::hsts_preload::analyze_hsts_header(hsts_val.as_deref());
    collect_ops!(
        seq,
        fc,
        entries,
        hsts_issues,
        crate::hsts_preload::hsts_findings_to_operations
    );

    // Permissions-Policy
    if let Some(pp_val) = hdr(resp, "permissions-policy") {
        let pp_issues = crate::permissions_policy::analyze_policy(&pp_val);
        collect_ops!(
            seq,
            fc,
            entries,
            pp_issues,
            crate::permissions_policy::policy_findings_to_operations
        );
    }

    // Cache headers
    let cc_val = hdr(resp, "cache-control");
    let pragma_val = hdr(resp, "pragma");
    let cache_issues =
        crate::cache_audit::analyze_cache_headers(cc_val.as_deref(), pragma_val.as_deref());
    collect_ops!(
        seq,
        fc,
        entries,
        cache_issues,
        crate::cache_audit::cache_findings_to_operations
    );

    // X-Frame-Options
    let xfo_values = hdr_all(resp, "x-frame-options");
    let xfo_issues = crate::xfo_audit::analyze_xfo(&xfo_values);
    collect_ops!(
        seq,
        fc,
        entries,
        xfo_issues,
        crate::xfo_audit::xfo_to_operations
    );

    // COOP/COEP
    let coop_val = hdr(resp, "cross-origin-opener-policy");
    let coep_val = hdr(resp, "cross-origin-embedder-policy");
    let coop_issues =
        crate::coop_coep_audit::analyze_coop_coep(coop_val.as_deref(), coep_val.as_deref());
    collect_ops!(
        seq,
        fc,
        entries,
        coop_issues,
        crate::coop_coep_audit::coop_coep_to_operations
    );

    // CORP
    let corp_val = hdr(resp, "cross-origin-resource-policy");
    let corp_issues = crate::corp_audit::analyze_corp(corp_val.as_deref());
    collect_ops!(
        seq,
        fc,
        entries,
        corp_issues,
        crate::corp_audit::corp_to_operations
    );

    // Content-Type + X-Content-Type-Options
    let nosniff = hdr(resp, "x-content-type-options");
    let ct = hdr(resp, "content-type");
    let ctype_issues =
        crate::content_type_audit::analyze_content_type(nosniff.as_deref(), ct.as_deref());
    collect_ops!(
        seq,
        fc,
        entries,
        ctype_issues,
        crate::content_type_audit::content_type_to_operations
    );

    // Content-Disposition
    let cd_val = hdr(resp, "content-disposition").unwrap_or_default();
    let cd_issues = crate::content_disposition_audit::analyze_content_disposition(
        ct.as_deref().unwrap_or(""),
        &cd_val,
    );
    collect_ops!(
        seq,
        fc,
        entries,
        cd_issues,
        crate::content_disposition_audit::content_disposition_to_operations
    );

    // Server-Timing
    let st_values = hdr_all(resp, "server-timing");
    let stiming_leaks = crate::server_timing_audit::analyze_server_timing(&st_values);
    collect_ops!(
        seq,
        fc,
        entries,
        stiming_leaks,
        crate::server_timing_audit::server_timing_to_operations
    );

    // Deprecated headers
    let dephdr_issues = crate::deprecated_header_audit::analyze_deprecated_headers(|name| {
        resp.headers.get(name).is_some()
    });
    collect_ops!(
        seq,
        fc,
        entries,
        dephdr_issues,
        crate::deprecated_header_audit::deprecated_header_to_operations
    );

    // Expose-Headers
    let expose_val = hdr(resp, "access-control-expose-headers");
    let exphdr_issues = crate::expose_headers_audit::analyze_expose_headers(expose_val.as_deref());
    collect_ops!(
        seq,
        fc,
        entries,
        exphdr_issues,
        crate::expose_headers_audit::expose_headers_to_operations
    );

    // Referrer-Policy
    if let Some(ref_val) = hdr(resp, "referrer-policy") {
        let referrer_issues = crate::referrer_audit::analyze_referrer_policy(&ref_val);
        collect_ops!(
            seq,
            fc,
            entries,
            referrer_issues,
            crate::referrer_audit::referrer_to_operations
        );
    }

    // NEL + Report-To
    let nel_val = hdr(resp, "nel");
    let report_to_values = hdr_all(resp, "report-to");
    let nel_issues = crate::nel_audit::analyze_nel(nel_val.as_deref(), &report_to_values, domain);
    collect_ops!(
        seq,
        fc,
        entries,
        nel_issues,
        crate::nel_audit::nel_to_operations
    );

    // Link headers
    let link_values = hdr_all(resp, "link");
    let linkhdr_issues = crate::link_header_audit::analyze_link_headers(&link_values, domain);
    collect_ops!(
        seq,
        fc,
        entries,
        linkhdr_issues,
        crate::link_header_audit::link_header_to_operations
    );

    // Reporting-Endpoints
    let repep_val = hdr(resp, "reporting-endpoints");
    let repep_issues =
        crate::reporting_endpoints_audit::analyze_reporting_endpoints(repep_val.as_deref(), domain);
    collect_ops!(
        seq,
        fc,
        entries,
        repep_issues,
        crate::reporting_endpoints_audit::reporting_endpoints_to_operations
    );

    // Timing-Allow-Origin
    let tao_values = hdr_all(resp, "timing-allow-origin");
    let tao_issues = crate::timing_allow_origin_audit::analyze_timing_allow_origin(&tao_values);
    collect_ops!(
        seq,
        fc,
        entries,
        tao_issues,
        crate::timing_allow_origin_audit::timing_allow_origin_to_operations
    );

    // Clear-Site-Data
    let csd_val = hdr(resp, "clear-site-data");
    let csd_issues =
        crate::clear_site_data_audit::analyze_clear_site_data(csd_val.as_deref(), resp.is_https);
    collect_ops!(
        seq,
        fc,
        entries,
        csd_issues,
        crate::clear_site_data_audit::clear_site_data_to_operations
    );

    // SourceMap header
    let sm_val = hdr(resp, "sourcemap").or_else(|| hdr(resp, "x-sourcemap"));
    let smhdr_issues = crate::sourcemap_header_audit::analyze_sourcemap_header(sm_val.as_deref());
    collect_ops!(
        seq,
        fc,
        entries,
        smhdr_issues,
        crate::sourcemap_header_audit::sourcemap_header_to_operations
    );

    // ETag
    let etag_val = hdr(resp, "etag");
    let etag_issues = crate::etag_audit::analyze_etag(etag_val.as_deref());
    collect_ops!(
        seq,
        fc,
        entries,
        etag_issues,
        crate::etag_audit::etag_to_operations
    );

    // WWW-Authenticate
    let wwwauth_values = hdr_all(resp, "www-authenticate");
    let wwwauth_issues =
        crate::www_authenticate_audit::analyze_www_authenticate(&wwwauth_values, resp.is_https);
    collect_ops!(
        seq,
        fc,
        entries,
        wwwauth_issues,
        crate::www_authenticate_audit::www_authenticate_to_operations
    );

    // Proxy headers
    let via_values = hdr_all(resp, "via");
    let has_age = resp.headers.get("age").is_some();
    let extra_proxy: Vec<(String, String)> = ["x-cache", "x-forwarded-for"]
        .iter()
        .filter_map(|name| {
            resp.headers
                .get(*name)
                .and_then(|v| v.to_str().ok())
                .map(|v| (name.to_string(), v.to_string()))
        })
        .collect();
    let proxyhdr_issues =
        crate::proxy_header_audit::analyze_proxy_headers(&via_values, has_age, &extra_proxy);
    collect_ops!(
        seq,
        fc,
        entries,
        proxyhdr_issues,
        crate::proxy_header_audit::proxy_header_to_operations
    );

    // X-DNS-Prefetch-Control
    let dnspf_val = hdr(resp, "x-dns-prefetch-control");
    let dnspf_issues =
        crate::dns_prefetch_control_audit::analyze_dns_prefetch_control(dnspf_val.as_deref());
    collect_ops!(
        seq,
        fc,
        entries,
        dnspf_issues,
        crate::dns_prefetch_control_audit::dns_prefetch_control_to_operations
    );

    // Set-Cookie
    let set_cookies = hdr_all(resp, "set-cookie");
    let cookie_findings = crate::cookie_audit::analyze_set_cookies(&set_cookies);
    collect_ops!(
        seq,
        fc,
        entries,
        cookie_findings,
        crate::cookie_audit::cookie_findings_to_operations
    );

    // Session fixation / session security
    let session_issues =
        crate::session_fixation_audit::analyze_session_security("", &set_cookies);
    collect_ops!(
        seq,
        fc,
        entries,
        session_issues,
        crate::session_fixation_audit::session_fixation_to_operations
    );
}

fn run_body_analyzers(
    resp: &SharedResponse,
    seq: &mut u64,
    entries: &mut Vec<OperationLogEntry>,
    fc: &mut u64,
) {
    let domain = resp.target_domain.as_deref().unwrap_or("");
    let body = &resp.body;

    // JS library detection
    let jslib_findings = crate::js_library_scanner::detect_libraries(body);
    collect_ops!(
        seq,
        fc,
        entries,
        jslib_findings,
        crate::js_library_scanner::js_library_findings_to_operations
    );

    // SRI
    let sri_issues = crate::sri_checker::find_missing_sri(body);
    collect_ops!(
        seq,
        fc,
        entries,
        sri_issues,
        crate::sri_checker::sri_findings_to_operations
    );

    // Mixed content
    let mc_issues = crate::mixed_content::find_mixed_content(body);
    collect_ops!(
        seq,
        fc,
        entries,
        mc_issues,
        crate::mixed_content::mixed_content_to_operations
    );

    // Forms
    let form_findings = crate::form_audit::analyze_forms(body);
    collect_ops!(
        seq,
        fc,
        entries,
        form_findings,
        crate::form_audit::form_findings_to_operations
    );

    // Comment leaks
    let comment_leaks = crate::comment_leak::find_comment_leaks(body);
    collect_ops!(
        seq,
        fc,
        entries,
        comment_leaks,
        crate::comment_leak::comment_leak_to_operations
    );

    // Sourcemap references in HTML
    let smap_leaks = crate::sourcemap_detector::find_sourcemap_references(body, domain);
    collect_ops!(
        seq,
        fc,
        entries,
        smap_leaks,
        crate::sourcemap_detector::sourcemap_to_operations
    );

    // Meta tags
    let meta_issues = crate::meta_tag_audit::analyze_meta_tags(body);
    collect_ops!(
        seq,
        fc,
        entries,
        meta_issues,
        crate::meta_tag_audit::meta_findings_to_operations
    );

    // Iframes
    let iframe_findings = crate::iframe_audit::analyze_iframes(body);
    collect_ops!(
        seq,
        fc,
        entries,
        iframe_findings,
        crate::iframe_audit::iframe_findings_to_operations
    );

    // Base tags
    let base_findings = crate::base_tag_audit::analyze_base_tags(body, domain);
    collect_ops!(
        seq,
        fc,
        entries,
        base_findings,
        crate::base_tag_audit::base_tag_to_operations
    );

    // Opener issues
    let opener_issues = crate::opener_audit::find_opener_issues(body);
    collect_ops!(
        seq,
        fc,
        entries,
        opener_issues,
        crate::opener_audit::opener_to_operations
    );

    // Inline event handlers
    let handler_issues = crate::inline_handler_audit::find_inline_handlers(body);
    collect_ops!(
        seq,
        fc,
        entries,
        handler_issues,
        crate::inline_handler_audit::inline_handler_to_operations
    );

    // Dangerous JS patterns
    let djs_issues = crate::dangerous_js_audit::find_dangerous_js(body);
    collect_ops!(
        seq,
        fc,
        entries,
        djs_issues,
        crate::dangerous_js_audit::dangerous_js_to_operations
    );

    // Preconnect audit
    let precon_issues = crate::preconnect_audit::analyze_preconnects(body);
    collect_ops!(
        seq,
        fc,
        entries,
        precon_issues,
        crate::preconnect_audit::preconnect_to_operations
    );

    // document.domain
    let docdomain_issues = crate::document_domain_audit::find_document_domain(body);
    collect_ops!(
        seq,
        fc,
        entries,
        docdomain_issues,
        crate::document_domain_audit::document_domain_to_operations
    );

    // JSONP endpoints
    let jsonp_issues = crate::jsonp_audit::find_jsonp_endpoints(body);
    collect_ops!(
        seq,
        fc,
        entries,
        jsonp_issues,
        crate::jsonp_audit::jsonp_to_operations
    );

    // Hidden input audit
    let hidinput_issues = crate::hidden_input_audit::find_hidden_input_issues(body);
    collect_ops!(
        seq,
        fc,
        entries,
        hidinput_issues,
        crate::hidden_input_audit::hidden_input_to_operations
    );

    // Fetch/XHR credential audit
    let fetchcred_issues = crate::fetch_credential_audit::analyze_fetch_credentials(body);
    collect_ops!(
        seq,
        fc,
        entries,
        fetchcred_issues,
        crate::fetch_credential_audit::fetch_credential_to_operations
    );

    // Service worker security
    let sw_issues = crate::service_worker_audit::analyze_service_worker_usage(
        body,
        !resp.is_https,
    );
    collect_ops!(
        seq,
        fc,
        entries,
        sw_issues,
        crate::service_worker_audit::service_worker_to_operations
    );

    // postMessage security
    let pm_issues = crate::postmessage_audit::analyze_postmessage_usage(body);
    collect_ops!(
        seq,
        fc,
        entries,
        pm_issues,
        crate::postmessage_audit::postmessage_to_operations
    );

    // Client-side storage audit
    let storage_issues = crate::storage_audit::analyze_storage_usage(body);
    collect_ops!(
        seq,
        fc,
        entries,
        storage_issues,
        crate::storage_audit::storage_to_operations
    );

    // WebSocket references in HTML
    let ws_issues = crate::websocket_audit::analyze_html_for_websockets(body);
    collect_ops!(
        seq,
        fc,
        entries,
        ws_issues,
        crate::websocket_audit::websocket_to_operations
    );

    // DOM clobbering
    let domclob_issues = crate::dom_clobbering_audit::analyze_dom_clobbering(body);
    collect_ops!(
        seq,
        fc,
        entries,
        domclob_issues,
        crate::dom_clobbering_audit::dom_clobber_to_operations
    );

    // Deserialization indicators in response body
    let ct = hdr(resp, "content-type").unwrap_or_default();
    let deser_issues =
        crate::deserialization_audit::analyze_deserialization_response(&ct, body);
    collect_ops!(
        seq,
        fc,
        entries,
        deser_issues,
        crate::deserialization_audit::deserialization_to_operations
    );

    // WebAssembly security audit
    let wasm_csp = hdr(resp, "content-security-policy").unwrap_or_default();
    let wasm_issues = crate::wasm_audit::analyze_wasm_usage(body, &wasm_csp);
    collect_ops!(
        seq,
        fc,
        entries,
        wasm_issues,
        crate::wasm_audit::wasm_to_operations
    );

    // Server-Sent Events audit
    let sse_issues = crate::sse_audit::analyze_sse_usage(body);
    collect_ops!(
        seq,
        fc,
        entries,
        sse_issues,
        crate::sse_audit::sse_to_operations
    );

    // Client-side template injection
    let csti_issues = crate::template_injection_audit::analyze_template_injection(body);
    collect_ops!(
        seq,
        fc,
        entries,
        csti_issues,
        crate::template_injection_audit::template_injection_to_operations
    );

    // Dependency confusion indicators
    let depconf_issues = crate::dependency_confusion_audit::analyze_dependency_confusion(body);
    collect_ops!(
        seq,
        fc,
        entries,
        depconf_issues,
        crate::dependency_confusion_audit::dep_confusion_to_operations
    );

    // Third-party script risk audit
    let tps_issues =
        crate::third_party_script_audit::analyze_third_party_scripts(body, domain);
    collect_ops!(
        seq,
        fc,
        entries,
        tps_issues,
        crate::third_party_script_audit::third_party_script_to_operations
    );

    // API endpoint leak detection
    let apileak_issues = crate::api_endpoint_leak_audit::analyze_api_endpoint_leaks(body);
    collect_ops!(
        seq,
        fc,
        entries,
        apileak_issues,
        crate::api_endpoint_leak_audit::api_endpoint_leak_to_operations
    );

    // Trusted Types policy audit (needs CSP header + body)
    let tt_csp = hdr(resp, "content-security-policy").unwrap_or_default();
    let tt_issues = crate::trusted_types_audit::analyze_trusted_types(&tt_csp, body);
    collect_ops!(
        seq,
        fc,
        entries,
        tt_issues,
        crate::trusted_types_audit::trusted_types_to_operations
    );

    // Web NFC/Bluetooth wireless API audit
    let wl_issues = crate::wireless_api_audit::analyze_wireless_api(body);
    collect_ops!(
        seq,
        fc,
        entries,
        wl_issues,
        crate::wireless_api_audit::wireless_api_to_operations
    );

    // File System Access API audit
    let fa_issues = crate::file_access_audit::analyze_file_access(body);
    collect_ops!(
        seq,
        fc,
        entries,
        fa_issues,
        crate::file_access_audit::file_access_to_operations
    );

    // Web Speech API audit
    let speech_issues = crate::speech_api_audit::analyze_speech_api(body);
    collect_ops!(
        seq,
        fc,
        entries,
        speech_issues,
        crate::speech_api_audit::speech_api_to_operations
    );

    // USB/HID/Serial hardware API audit
    let hw_issues = crate::hardware_api_audit::analyze_hardware_api(body);
    collect_ops!(
        seq,
        fc,
        entries,
        hw_issues,
        crate::hardware_api_audit::hardware_api_to_operations
    );

    // Idle detection API audit
    let idle_issues = crate::idle_detection_audit::analyze_idle_detection(body);
    collect_ops!(
        seq,
        fc,
        entries,
        idle_issues,
        crate::idle_detection_audit::idle_detection_to_operations
    );

    // Screen capture API audit
    let sc_issues = crate::screen_capture_audit::analyze_screen_capture(body);
    collect_ops!(
        seq,
        fc,
        entries,
        sc_issues,
        crate::screen_capture_audit::screen_capture_to_operations
    );

    // DeviceOrientation/Motion fingerprinting
    let dm_issues = crate::device_motion_audit::analyze_device_motion(body);
    collect_ops!(
        seq,
        fc,
        entries,
        dm_issues,
        crate::device_motion_audit::device_motion_to_operations
    );

    // Viewport meta audit
    let vp_issues = crate::viewport_audit::analyze_viewport(body);
    collect_ops!(
        seq,
        fc,
        entries,
        vp_issues,
        crate::viewport_audit::viewport_to_operations
    );

    // SharedArrayBuffer / COEP audit
    let coep_val = hdr(resp, "cross-origin-embedder-policy").unwrap_or_default();
    let coop_val = hdr(resp, "cross-origin-opener-policy").unwrap_or_default();
    let sb_issues =
        crate::shared_buffer_audit::analyze_shared_buffer(body, &coep_val, &coop_val);
    collect_ops!(
        seq,
        fc,
        entries,
        sb_issues,
        crate::shared_buffer_audit::shared_buffer_to_operations
    );

    // Drag-drop data leak audit
    let dd_issues = crate::drag_drop_audit::analyze_drag_drop(body);
    collect_ops!(
        seq,
        fc,
        entries,
        dd_issues,
        crate::drag_drop_audit::drag_drop_to_operations
    );

    // Contact Picker API audit
    let cp_issues = crate::contact_picker_audit::analyze_contact_picker(body);
    collect_ops!(
        seq,
        fc,
        entries,
        cp_issues,
        crate::contact_picker_audit::contact_picker_to_operations
    );

    // EyeDropper API audit
    let ed_issues = crate::eyedropper_audit::analyze_eyedropper(body);
    collect_ops!(
        seq,
        fc,
        entries,
        ed_issues,
        crate::eyedropper_audit::eyedropper_to_operations
    );

    // WebHID API audit
    let hid_issues = crate::webhid_audit::analyze_webhid(body);
    collect_ops!(
        seq,
        fc,
        entries,
        hid_issues,
        crate::webhid_audit::webhid_to_operations
    );

    // Web Serial API audit
    let serial_issues = crate::web_serial_audit::analyze_web_serial(body);
    collect_ops!(
        seq,
        fc,
        entries,
        serial_issues,
        crate::web_serial_audit::web_serial_to_operations
    );

    // Web Bluetooth API audit
    let bt_issues = crate::web_bluetooth_audit::analyze_web_bluetooth(body);
    collect_ops!(
        seq,
        fc,
        entries,
        bt_issues,
        crate::web_bluetooth_audit::web_bluetooth_to_operations
    );

    // Local Font Access API audit
    let lf_issues = crate::local_font_audit::analyze_local_font(body);
    collect_ops!(
        seq,
        fc,
        entries,
        lf_issues,
        crate::local_font_audit::local_font_to_operations
    );

    // Compute Pressure API audit
    let cp2_issues = crate::compute_pressure_audit::analyze_compute_pressure(body);
    collect_ops!(
        seq,
        fc,
        entries,
        cp2_issues,
        crate::compute_pressure_audit::compute_pressure_to_operations
    );

    // Window Management API audit
    let wm_issues = crate::window_management_audit::analyze_window_management(body);
    collect_ops!(
        seq,
        fc,
        entries,
        wm_issues,
        crate::window_management_audit::window_management_to_operations
    );

    // Ambient Light Sensor audit
    let als_issues = crate::ambient_light_audit::analyze_ambient_light(body);
    collect_ops!(
        seq,
        fc,
        entries,
        als_issues,
        crate::ambient_light_audit::ambient_light_to_operations
    );

    // Presentation API audit
    let pres_issues = crate::presentation_audit::analyze_presentation(body);
    collect_ops!(
        seq,
        fc,
        entries,
        pres_issues,
        crate::presentation_audit::presentation_to_operations
    );

    // WebNFC API audit
    let nfc_issues = crate::web_nfc_audit::analyze_web_nfc(body);
    collect_ops!(
        seq,
        fc,
        entries,
        nfc_issues,
        crate::web_nfc_audit::web_nfc_to_operations
    );

    // WebTransport API audit
    let wt_issues = crate::web_transport_audit::analyze_web_transport(body);
    collect_ops!(
        seq,
        fc,
        entries,
        wt_issues,
        crate::web_transport_audit::web_transport_to_operations
    );

    // File System Access API audit
    let fsa_issues = crate::file_system_access_audit::analyze_file_system_access(body);
    collect_ops!(
        seq,
        fc,
        entries,
        fsa_issues,
        crate::file_system_access_audit::file_system_access_to_operations
    );

    // Fullscreen API abuse audit
    let fs_issues = crate::fullscreen_audit::analyze_fullscreen(body);
    collect_ops!(
        seq,
        fc,
        entries,
        fs_issues,
        crate::fullscreen_audit::fullscreen_to_operations
    );

    // Selection API data leak audit
    let sel_issues = crate::selection_audit::analyze_selection(body);
    collect_ops!(
        seq,
        fc,
        entries,
        sel_issues,
        crate::selection_audit::selection_to_operations
    );

    // Permissions API abuse
    let perm_issues = crate::permissions_api_audit::analyze_permissions_api(body);
    collect_ops!(
        seq,
        fc,
        entries,
        perm_issues,
        crate::permissions_api_audit::permissions_api_to_operations
    );

    // Meta redirect / JS redirect audit
    let mr_issues = crate::meta_redirect_audit::analyze_meta_redirect(body);
    collect_ops!(
        seq,
        fc,
        entries,
        mr_issues,
        crate::meta_redirect_audit::meta_redirect_to_operations
    );

    // Canvas/audio/font fingerprinting
    let fp_issues = crate::canvas_fingerprint_audit::analyze_canvas_fingerprint(body);
    collect_ops!(
        seq,
        fc,
        entries,
        fp_issues,
        crate::canvas_fingerprint_audit::canvas_fingerprint_to_operations
    );

    // Battery API fingerprinting
    let batt_issues = crate::battery_audit::analyze_battery(body);
    collect_ops!(
        seq,
        fc,
        entries,
        batt_issues,
        crate::battery_audit::battery_to_operations
    );

    // Notification API audit
    let notif_issues =
        crate::notification_audit::analyze_notifications(body, resp.is_https);
    collect_ops!(
        seq,
        fc,
        entries,
        notif_issues,
        crate::notification_audit::notification_to_operations
    );

    // WebRTC leak detection
    let rtc_issues = crate::webrtc_audit::analyze_webrtc(body);
    collect_ops!(
        seq,
        fc,
        entries,
        rtc_issues,
        crate::webrtc_audit::webrtc_to_operations
    );

    // Geolocation API audit
    let geo_issues =
        crate::geolocation_audit::analyze_geolocation(body, resp.is_https);
    collect_ops!(
        seq,
        fc,
        entries,
        geo_issues,
        crate::geolocation_audit::geolocation_to_operations
    );

    // Clipboard API audit
    let clip_issues = crate::clipboard_audit::analyze_clipboard(body);
    collect_ops!(
        seq,
        fc,
        entries,
        clip_issues,
        crate::clipboard_audit::clipboard_to_operations
    );

    // Web Crypto API misuse detection
    let wc_issues = crate::webcrypto_audit::analyze_webcrypto(body);
    collect_ops!(
        seq,
        fc,
        entries,
        wc_issues,
        crate::webcrypto_audit::webcrypto_to_operations
    );

    // Web Locks API audit
    let wl_issues = crate::web_locks_audit::analyze_web_locks(body);
    collect_ops!(
        seq,
        fc,
        entries,
        wl_issues,
        crate::web_locks_audit::web_locks_to_operations
    );

    // window.name leak detection
    let wn_issues = crate::window_name_audit::analyze_window_name(body);
    collect_ops!(
        seq,
        fc,
        entries,
        wn_issues,
        crate::window_name_audit::window_name_to_operations
    );

    // Payment form security audit
    let payment_issues =
        crate::payment_form_audit::analyze_payment_forms(body, resp.is_https);
    collect_ops!(
        seq,
        fc,
        entries,
        payment_issues,
        crate::payment_form_audit::payment_form_to_operations
    );

    // Credential harvesting form detection
    let cred_issues =
        crate::credential_harvest_audit::analyze_credential_harvest(body, domain);
    collect_ops!(
        seq,
        fc,
        entries,
        cred_issues,
        crate::credential_harvest_audit::credential_harvest_to_operations
    );

    // Resource timing leak detection
    let rt_issues = crate::resource_timing_audit::analyze_resource_timing(
        body,
        &hdr(resp, "timing-allow-origin").unwrap_or_default(),
    );
    collect_ops!(
        seq,
        fc,
        entries,
        rt_issues,
        crate::resource_timing_audit::resource_timing_to_operations
    );

    // Object URL / blob: / data: audit
    let objurl_issues = crate::object_url_audit::analyze_object_urls(body);
    collect_ops!(
        seq,
        fc,
        entries,
        objurl_issues,
        crate::object_url_audit::object_url_to_operations
    );

    // Mutation Observer surveillance audit
    let mo_issues = crate::mutation_observer_audit::analyze_mutation_observer(body);
    collect_ops!(
        seq,
        fc,
        entries,
        mo_issues,
        crate::mutation_observer_audit::mutation_observer_to_operations
    );

    // Resize Observer fingerprinting audit
    let ro_issues = crate::resize_observer_audit::analyze_resize_observer(body);
    collect_ops!(
        seq,
        fc,
        entries,
        ro_issues,
        crate::resize_observer_audit::resize_observer_to_operations
    );

    // Wake Lock API audit
    let wkl_issues = crate::wake_lock_audit::analyze_wake_lock(body);
    collect_ops!(
        seq,
        fc,
        entries,
        wkl_issues,
        crate::wake_lock_audit::wake_lock_to_operations
    );

    // Picture-in-Picture API audit
    let pip_issues = crate::pip_audit::analyze_pip(body);
    collect_ops!(
        seq,
        fc,
        entries,
        pip_issues,
        crate::pip_audit::pip_to_operations
    );

    // Storage Access API audit
    let sa_issues = crate::storage_access_audit::analyze_storage_access(body);
    collect_ops!(
        seq,
        fc,
        entries,
        sa_issues,
        crate::storage_access_audit::storage_access_to_operations
    );

    // Intersection Observer timing audit
    let io_issues = crate::intersection_observer_audit::analyze_intersection_observer(body);
    collect_ops!(
        seq,
        fc,
        entries,
        io_issues,
        crate::intersection_observer_audit::intersection_observer_to_operations
    );

    // Navigation API audit
    let nav_issues = crate::navigation_api_audit::analyze_navigation_api(body);
    collect_ops!(
        seq,
        fc,
        entries,
        nav_issues,
        crate::navigation_api_audit::navigation_api_to_operations
    );

    // Gamepad API fingerprinting audit
    let gp_issues = crate::gamepad_audit::analyze_gamepad(body);
    collect_ops!(
        seq,
        fc,
        entries,
        gp_issues,
        crate::gamepad_audit::gamepad_to_operations
    );

    // Broadcast Channel API audit
    let bc_issues = crate::broadcast_channel_audit::analyze_broadcast_channel(body);
    collect_ops!(
        seq,
        fc,
        entries,
        bc_issues,
        crate::broadcast_channel_audit::broadcast_channel_to_operations
    );

    // Performance Observer leak audit
    let po_issues = crate::perf_observer_audit::analyze_perf_observer(body);
    collect_ops!(
        seq,
        fc,
        entries,
        po_issues,
        crate::perf_observer_audit::perf_observer_to_operations
    );

    // Background Sync API audit
    let bgsync_issues = crate::background_sync_audit::analyze_background_sync(body);
    collect_ops!(
        seq,
        fc,
        entries,
        bgsync_issues,
        crate::background_sync_audit::background_sync_to_operations
    );

    // Credential Management API audit
    let cma_issues = crate::credential_api_audit::analyze_credential_api(body);
    collect_ops!(
        seq,
        fc,
        entries,
        cma_issues,
        crate::credential_api_audit::credential_api_to_operations
    );

    // Payment Request API audit
    let pr_issues = crate::payment_request_audit::analyze_payment_request(body, resp.is_https);
    collect_ops!(
        seq,
        fc,
        entries,
        pr_issues,
        crate::payment_request_audit::payment_request_to_operations
    );

    // Reporting API audit (headers + body)
    let ra_report_to = hdr(resp, "report-to").unwrap_or_default();
    let ra_rep_ep = hdr(resp, "reporting-endpoints").unwrap_or_default();
    let ra_issues = crate::reporting_api_audit::analyze_reporting_api(
        domain,
        &ra_report_to,
        &ra_rep_ep,
        body,
    );
    collect_ops!(
        seq,
        fc,
        entries,
        ra_issues,
        crate::reporting_api_audit::reporting_api_to_operations
    );

    // Technology detection (needs both headers + body)
    let header_pairs: Vec<(String, String)> = resp
        .headers
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let tech_detections = crate::tech_detector::detect_from_parts(&header_pairs, body);
    entries.extend(crate::tech_detector::tech_to_operations(
        &tech_detections,
        seq,
    ));
}

pub fn run_recon(ctx: &mut ScanContext) -> Result<PhaseResult, PhaseError> {
    let mut entries = Vec::new();
    let mut sequence = 0u64;
    let mut findings_count = 0u64;

    // --- Shared fetch: one GET request for all header + body analyzers ---
    let shared_target = ctx.config.target.clone();
    let shared_handle = std::thread::spawn(move || fetch_shared_response(&shared_target));

    // --- Separate threads for scanners that need custom HTTP requests ---
    let target = ctx.config.target.clone();
    let gau_target = target.clone();
    let amass_target = target.clone();
    let crtsh_target = target.clone();
    let s3_target = target.clone();
    let st_target = target;
    let gau_handle = std::thread::spawn(move || harvest_urls(&gau_target));
    let amass_handle = std::thread::spawn(move || enumerate_subdomains(&amass_target));
    let crtsh_handle = std::thread::spawn(move || query_crtsh(&crtsh_target));
    let st_handle = std::thread::spawn(move || query_securitytrails(&st_target));
    let s3_handle = std::thread::spawn(move || crate::s3_scanner::scan_s3_buckets(&s3_target));
    let shodan_target = ctx.config.target.clone();
    let shodan_handle =
        std::thread::spawn(move || crate::shodan_lookup::shodan_lookup(&shodan_target));
    let tls_target = ctx.config.target.clone();
    let tls_handle = std::thread::spawn(move || crate::tls_scanner::scan_tls(&tls_target));
    let robots_target = ctx.config.target.clone();
    let robots_handle =
        std::thread::spawn(move || crate::robots_parser::fetch_robots_txt(&robots_target));
    let sitemap_target = ctx.config.target.clone();
    let sitemap_handle =
        std::thread::spawn(move || crate::robots_parser::fetch_sitemap(&sitemap_target));
    let dns_target = ctx.config.target.clone();
    let dns_handle = std::thread::spawn(move || crate::dns_enumerator::enumerate_dns(&dns_target));
    let cors_target = ctx.config.target.clone();
    let cors_handle = std::thread::spawn(move || crate::cors_scanner::scan_cors(&cors_target));
    let method_target = ctx.config.target.clone();
    let method_handle =
        std::thread::spawn(move || crate::method_scanner::scan_methods(&method_target));
    let redirect_target = ctx.config.target.clone();
    let redirect_handle =
        std::thread::spawn(move || crate::redirect_scanner::scan_redirects(&redirect_target));
    let info_target = ctx.config.target.clone();
    let info_handle =
        std::thread::spawn(move || crate::info_disclosure::scan_info_disclosure(&info_target));
    let email_target = ctx.config.target.clone();
    let email_handle =
        std::thread::spawn(move || crate::email_security::check_email_security(&email_target));
    let version_target = ctx.config.target.clone();
    let version_handle =
        std::thread::spawn(move || crate::http_version::detect_http_version(&version_target));
    let waf_target = ctx.config.target.clone();
    let waf_handle = std::thread::spawn(move || crate::waf_detector::detect_waf(&waf_target));
    let rl_target = ctx.config.target.clone();
    let rl_handle =
        std::thread::spawn(move || crate::rate_limit_detector::detect_rate_limits(&rl_target));
    let sectxt_target = ctx.config.target.clone();
    let sectxt_handle =
        std::thread::spawn(move || crate::security_txt::fetch_security_txt(&sectxt_target));
    let errpage_target = ctx.config.target.clone();
    let errpage_handle =
        std::thread::spawn(move || crate::error_page_audit::audit_error_pages(&errpage_target));
    let hosthdr_target = ctx.config.target.clone();
    let hosthdr_handle =
        std::thread::spawn(move || crate::host_header_audit::audit_host_header(&hosthdr_target));
    let crlf_target = ctx.config.target.clone();
    let crlf_handle =
        std::thread::spawn(move || crate::crlf_injection_audit::audit_crlf(&crlf_target));
    let sensfile_target = ctx.config.target.clone();
    let sensfile_handle = std::thread::spawn(move || {
        crate::sensitive_file_audit::audit_sensitive_files(&sensfile_target)
    });
    let protopoll_target = ctx.config.target.clone();
    let protopoll_handle = std::thread::spawn(move || {
        crate::prototype_pollution_audit::audit_prototype_pollution(&protopoll_target)
    });
    let cors_pf_target = ctx.config.target.clone();
    let cors_pf_handle = std::thread::spawn(move || {
        crate::cors_preflight_audit::audit_cors_preflight(&cors_pf_target)
    });
    let verbtamp_target = ctx.config.target.clone();
    let verbtamp_handle = std::thread::spawn(move || {
        crate::verb_tamper_audit::audit_verb_tampering(&verbtamp_target)
    });
    let cookiepfx_target = ctx.config.target.clone();
    let cookiepfx_handle = std::thread::spawn(move || {
        crate::cookie_prefix_audit::audit_cookie_prefixes(&cookiepfx_target)
    });
    let cachepoison_target = ctx.config.target.clone();
    let cachepoison_handle = std::thread::spawn(move || {
        crate::cache_poison_audit::audit_cache_poison(&cachepoison_target)
    });
    let ssrf_target = ctx.config.target.clone();
    let ssrf_handle = std::thread::spawn(move || {
        crate::ssrf_redirect_audit::audit_ssrf_redirect(&ssrf_target)
    });
    let clickjack_target = ctx.config.target.clone();
    let clickjack_handle = std::thread::spawn(move || {
        crate::clickjack_audit::audit_clickjacking(&clickjack_target)
    });
    let jwt_target = ctx.config.target.clone();
    let jwt_handle = std::thread::spawn(move || {
        crate::jwt_header_audit::audit_jwt_headers(&jwt_target)
    });
    let apiver_target = ctx.config.target.clone();
    let apiver_handle = std::thread::spawn(move || {
        crate::api_version_audit::audit_api_versioning(&apiver_target)
    });
    let cspreport_target = ctx.config.target.clone();
    let cspreport_handle = std::thread::spawn(move || {
        crate::csp_report_leak_audit::audit_csp_report_leak(&cspreport_target)
    });
    let gqlintro_target = ctx.config.target.clone();
    let gqlintro_handle = std::thread::spawn(move || {
        crate::graphql_introspection_audit::audit_graphql_introspection(&gqlintro_target)
    });
    let openredir_target = ctx.config.target.clone();
    let openredir_handle = std::thread::spawn(move || {
        crate::open_redirect_param_audit::audit_open_redirect_params(&openredir_target)
    });
    let pathtraversal_target = ctx.config.target.clone();
    let pathtraversal_handle = std::thread::spawn(move || {
        crate::path_traversal_audit::audit_path_traversal(&pathtraversal_target)
    });
    let smuggling_target = ctx.config.target.clone();
    let smuggling_handle = std::thread::spawn(move || {
        crate::request_smuggling_audit::audit_request_smuggling(&smuggling_target)
    });
    let methoverride_target = ctx.config.target.clone();
    let methoverride_handle = std::thread::spawn(move || {
        crate::method_override_audit::audit_method_override(&methoverride_target)
    });
    let trufflehog_handle = ctx.config.source_dir.as_ref().map(|dir| {
        let dir = dir.clone();
        std::thread::spawn(move || scan_secrets(&dir))
    });
    let github_org_handle = ctx.config.github_org.as_ref().map(|org| {
        let org = org.clone();
        std::thread::spawn(move || scan_github_org(&org))
    });

    // --- Source directory analysis ---
    if let Some(source_dir) = &ctx.config.source_dir {
        let walk =
            walk_directory(source_dir).map_err(|e| PhaseError::FilesystemWalk(e.to_string()))?;
        let lock_files: Vec<_> = walk
            .files
            .iter()
            .filter(|f| f.classification == FileClassification::LockFile)
            .collect();

        let mut all_deps: Vec<ParsedDependency> = Vec::new();
        for lock_file in &lock_files {
            if let Ok(deps) = parse_lock_file(&lock_file.path) {
                all_deps.extend(deps);
            }
        }

        entries.extend(deps_to_operations(&all_deps, &mut sequence));
        entries.extend(vuln_lookup(
            &all_deps,
            &mut sequence,
            ctx.config.scope.vuln_db.as_deref(),
        ));
        entries.extend(walk_to_operations(&walk.files, &mut sequence));
    }

    // --- Collect shared fetch results → run all header + body analyzers ---
    if let Some(resp) = shared_handle.join().unwrap_or(None) {
        run_header_analyzers(&resp, &mut sequence, &mut entries, &mut findings_count);
        run_body_analyzers(&resp, &mut sequence, &mut entries, &mut findings_count);
    }

    // --- Collect results from separate-thread scanners ---
    if let Some(handle) = trufflehog_handle {
        let secrets = handle.join().unwrap_or_default();
        let secret_ops = secret_findings_to_operations(&secrets, &mut sequence);
        findings_count += secret_ops.len() as u64;
        entries.extend(secret_ops);
    }

    if let Some(handle) = github_org_handle {
        let secrets = handle.join().unwrap_or_default();
        let org_ops = secret_findings_to_operations(&secrets, &mut sequence);
        findings_count += org_ops.len() as u64;
        entries.extend(org_ops);
    }

    let gau_urls = gau_handle.join().unwrap_or_default();
    entries.extend(harvested_urls_to_operations(&gau_urls, &mut sequence));

    let subdomains = amass_handle.join().unwrap_or_default();
    entries.extend(subdomains_to_operations(&subdomains, &mut sequence));

    let ct_subdomains = crtsh_handle.join().unwrap_or_default();
    entries.extend(crtsh_to_operations(&ct_subdomains, &mut sequence));

    let st_subdomains = st_handle.join().unwrap_or_default();
    entries.extend(securitytrails_to_operations(&st_subdomains, &mut sequence));

    let mut all_subdomains = Vec::new();
    all_subdomains.extend(subdomains.iter().cloned());
    all_subdomains.extend(ct_subdomains.iter().cloned());
    all_subdomains.extend(st_subdomains.iter().cloned());
    all_subdomains.sort();
    all_subdomains.dedup();
    if !all_subdomains.is_empty() {
        let takeover_candidates =
            crate::subdomain_takeover::check_subdomain_takeover(&all_subdomains);
        let takeover_ops = crate::subdomain_takeover::takeover_findings_to_operations(
            &takeover_candidates,
            &mut sequence,
        );
        findings_count += takeover_ops.len() as u64;
        entries.extend(takeover_ops);
    }

    let s3_findings = s3_handle.join().unwrap_or_default();
    let s3_ops = crate::s3_scanner::s3_findings_to_operations(&s3_findings, &mut sequence);
    findings_count += s3_ops
        .iter()
        .filter(|op| matches!(op.operation, GraphOperation::AddFinding { .. }))
        .count() as u64;
    entries.extend(s3_ops);

    if let Some(shodan_result) = shodan_handle.join().ok().flatten() {
        let shodan_ops = crate::shodan_lookup::shodan_to_operations(&shodan_result, &mut sequence);
        findings_count += shodan_ops
            .iter()
            .filter(|op| matches!(op.operation, GraphOperation::AddFinding { .. }))
            .count() as u64;
        entries.extend(shodan_ops);
    }

    let tls_findings = tls_handle.join().unwrap_or_default();
    let tls_ops = crate::tls_scanner::tls_findings_to_operations(&tls_findings, &mut sequence);
    findings_count += tls_ops.len() as u64;
    entries.extend(tls_ops);

    let robots_paths = robots_handle.join().unwrap_or_default();
    entries.extend(crate::robots_parser::discovered_paths_to_operations(
        &robots_paths,
        "robots.txt",
        &mut sequence,
    ));

    let sitemap_urls = sitemap_handle.join().unwrap_or_default();
    entries.extend(crate::robots_parser::discovered_paths_to_operations(
        &sitemap_urls,
        "sitemap.xml",
        &mut sequence,
    ));

    let dns_records = dns_handle.join().unwrap_or_default();
    entries.extend(crate::dns_enumerator::dns_to_operations(
        &dns_records,
        &mut sequence,
    ));

    let cors_findings = cors_handle.join().unwrap_or_default();
    let cors_ops = crate::cors_scanner::cors_findings_to_operations(&cors_findings, &mut sequence);
    findings_count += cors_ops.len() as u64;
    entries.extend(cors_ops);

    if let Some(method_result) = method_handle.join().ok().flatten() {
        let method_ops =
            crate::method_scanner::method_findings_to_operations(&method_result, &mut sequence);
        findings_count += method_ops.len() as u64;
        entries.extend(method_ops);
    }

    let redirect_findings = redirect_handle.join().unwrap_or_default();
    let redirect_ops =
        crate::redirect_scanner::redirect_findings_to_operations(&redirect_findings, &mut sequence);
    findings_count += redirect_ops.len() as u64;
    entries.extend(redirect_ops);

    let info_findings = info_handle.join().unwrap_or_default();
    let info_ops =
        crate::info_disclosure::disclosure_findings_to_operations(&info_findings, &mut sequence);
    findings_count += info_ops.len() as u64;
    entries.extend(info_ops);

    let email_issues = email_handle.join().unwrap_or_default();
    let email_ops =
        crate::email_security::email_findings_to_operations(&email_issues, &mut sequence);
    findings_count += email_ops.len() as u64;
    entries.extend(email_ops);

    if let Some(version_info) = version_handle.join().ok().flatten() {
        entries.extend(crate::http_version::version_to_operations(
            &version_info,
            &mut sequence,
        ));
    }

    let waf_detections = waf_handle.join().unwrap_or_default();
    entries.extend(crate::waf_detector::waf_to_operations(
        &waf_detections,
        &mut sequence,
    ));

    if let Some(rl_info) = rl_handle.join().ok().flatten() {
        entries.extend(crate::rate_limit_detector::rate_limit_to_operations(
            &rl_info,
            &mut sequence,
        ));
    }

    if let Some(sectxt_info) = sectxt_handle.join().ok().flatten() {
        entries.extend(crate::security_txt::security_txt_to_operations(
            &sectxt_info,
            &mut sequence,
        ));
    }

    let errpage_leaks = errpage_handle.join().unwrap_or_default();
    let errpage_ops =
        crate::error_page_audit::error_page_to_operations(&errpage_leaks, &mut sequence);
    findings_count += errpage_ops.len() as u64;
    entries.extend(errpage_ops);

    let hosthdr_issues = hosthdr_handle.join().unwrap_or_default();
    let hosthdr_ops =
        crate::host_header_audit::host_header_to_operations(&hosthdr_issues, &mut sequence);
    findings_count += hosthdr_ops.len() as u64;
    entries.extend(hosthdr_ops);

    let crlf_issues = crlf_handle.join().unwrap_or_default();
    let crlf_ops = crate::crlf_injection_audit::crlf_to_operations(&crlf_issues, &mut sequence);
    findings_count += crlf_ops.len() as u64;
    entries.extend(crlf_ops);

    let sensfile_issues = sensfile_handle.join().unwrap_or_default();
    let sensfile_ops =
        crate::sensitive_file_audit::sensitive_file_to_operations(&sensfile_issues, &mut sequence);
    findings_count += sensfile_ops.len() as u64;
    entries.extend(sensfile_ops);

    let protopoll_issues = protopoll_handle.join().unwrap_or_default();
    let protopoll_ops =
        crate::prototype_pollution_audit::pollution_to_operations(&protopoll_issues, &mut sequence);
    findings_count += protopoll_ops.len() as u64;
    entries.extend(protopoll_ops);

    let cors_pf_issues = cors_pf_handle.join().unwrap_or_default();
    let cors_pf_ops =
        crate::cors_preflight_audit::preflight_to_operations(&cors_pf_issues, &mut sequence);
    findings_count += cors_pf_ops.len() as u64;
    entries.extend(cors_pf_ops);

    let verbtamp_issues = verbtamp_handle.join().unwrap_or_default();
    let verbtamp_ops =
        crate::verb_tamper_audit::verb_tamper_to_operations(&verbtamp_issues, &mut sequence);
    findings_count += verbtamp_ops.len() as u64;
    entries.extend(verbtamp_ops);

    let cookiepfx_issues = cookiepfx_handle.join().unwrap_or_default();
    let cookiepfx_ops =
        crate::cookie_prefix_audit::cookie_prefix_to_operations(&cookiepfx_issues, &mut sequence);
    findings_count += cookiepfx_ops.len() as u64;
    entries.extend(cookiepfx_ops);

    let cachepoison_issues = cachepoison_handle.join().unwrap_or_default();
    let cachepoison_ops =
        crate::cache_poison_audit::cache_poison_to_operations(&cachepoison_issues, &mut sequence);
    findings_count += cachepoison_ops.len() as u64;
    entries.extend(cachepoison_ops);

    let ssrf_issues = ssrf_handle.join().unwrap_or_default();
    let ssrf_ops =
        crate::ssrf_redirect_audit::ssrf_redirect_to_operations(&ssrf_issues, &mut sequence);
    findings_count += ssrf_ops.len() as u64;
    entries.extend(ssrf_ops);

    let clickjack_issues = clickjack_handle.join().unwrap_or_default();
    let clickjack_ops =
        crate::clickjack_audit::clickjack_to_operations(&clickjack_issues, &mut sequence);
    findings_count += clickjack_ops.len() as u64;
    entries.extend(clickjack_ops);

    let jwt_issues = jwt_handle.join().unwrap_or_default();
    let jwt_ops =
        crate::jwt_header_audit::jwt_header_to_operations(&jwt_issues, &mut sequence);
    findings_count += jwt_ops.len() as u64;
    entries.extend(jwt_ops);

    let apiver_issues = apiver_handle.join().unwrap_or_default();
    let apiver_ops =
        crate::api_version_audit::api_version_to_operations(&apiver_issues, &mut sequence);
    findings_count += apiver_ops.len() as u64;
    entries.extend(apiver_ops);

    let cspreport_issues = cspreport_handle.join().unwrap_or_default();
    let cspreport_ops = crate::csp_report_leak_audit::csp_report_leak_to_operations(
        &cspreport_issues,
        &mut sequence,
    );
    findings_count += cspreport_ops.len() as u64;
    entries.extend(cspreport_ops);

    let gqlintro_issues = gqlintro_handle.join().unwrap_or_default();
    let gqlintro_ops = crate::graphql_introspection_audit::graphql_intro_to_operations(
        &gqlintro_issues,
        &mut sequence,
    );
    findings_count += gqlintro_ops.len() as u64;
    entries.extend(gqlintro_ops);

    let openredir_issues = openredir_handle.join().unwrap_or_default();
    let openredir_ops = crate::open_redirect_param_audit::open_redirect_to_operations(
        &openredir_issues,
        &mut sequence,
    );
    findings_count += openredir_ops.len() as u64;
    entries.extend(openredir_ops);

    let pathtraversal_issues = pathtraversal_handle.join().unwrap_or_default();
    let pathtraversal_ops = crate::path_traversal_audit::path_traversal_to_operations(
        &pathtraversal_issues,
        &mut sequence,
    );
    findings_count += pathtraversal_ops.len() as u64;
    entries.extend(pathtraversal_ops);

    let smuggling_issues = smuggling_handle.join().unwrap_or_default();
    let smuggling_ops = crate::request_smuggling_audit::smuggling_to_operations(
        &smuggling_issues,
        &mut sequence,
    );
    findings_count += smuggling_ops.len() as u64;
    entries.extend(smuggling_ops);

    let methoverride_issues = methoverride_handle.join().unwrap_or_default();
    let methoverride_ops = crate::method_override_audit::method_override_to_operations(
        &methoverride_issues,
        &mut sequence,
    );
    findings_count += methoverride_ops.len() as u64;
    entries.extend(methoverride_ops);

    let ops_count = entries.len() as u64;
    if !entries.is_empty() {
        ctx.graph.apply_operations(&entries)?;
    }

    Ok(PhaseResult {
        operations_applied: ops_count,
        findings_count,
    })
}

pub(crate) fn deps_to_operations(
    deps: &[ParsedDependency],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    deps.iter()
        .map(|dep| {
            *seq += 1;
            OperationLogEntry {
                sequence_number: *seq,
                module: ModuleIdentifier::PassiveRecon,
                operation: GraphOperation::AddNode {
                    node_type: NodeType::Dependency,
                    properties: vec![
                        ("name".to_string(), dep.name.clone()),
                        ("version".to_string(), dep.version.clone()),
                        ("ecosystem".to_string(), format!("{:?}", dep.ecosystem)),
                    ],
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}

pub(crate) fn vuln_lookup(
    deps: &[ParsedDependency],
    seq: &mut u64,
    vuln_db_path: Option<&Path>,
) -> Vec<OperationLogEntry> {
    let db = match vuln_db_path {
        Some(path) if path.exists() => VulnDatabase::open(path).ok(),
        _ => {
            let default = crate::update_db::default_db_path();
            if default.exists() {
                VulnDatabase::open(&default).ok()
            } else {
                None
            }
        }
    };
    let Some(db) = db else {
        return Vec::new();
    };
    let Ok(matches) = db.check_all_dependencies(deps) else {
        return Vec::new();
    };
    matches
        .iter()
        .map(|m| {
            *seq += 1;
            OperationLogEntry {
                sequence_number: *seq,
                module: ModuleIdentifier::PassiveRecon,
                operation: GraphOperation::AddFinding {
                    linked_node_ids: vec![],
                    vulnerability_class:
                        aegis_protocol::finding::VulnerabilityClass::KnownVulnerableDependency,
                    severity: m.severity,
                    confidence: aegis_protocol::finding::Confidence::new(0.9).unwrap(),
                    certificate: Vec::new(),
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}

pub(crate) fn walk_to_operations(
    files: &[aegis_passive_recon::filesystem_walker::ClassifiedFile],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    files
        .iter()
        .filter(|f| f.classification == FileClassification::ConfigFile)
        .map(|f| {
            *seq += 1;
            OperationLogEntry {
                sequence_number: *seq,
                module: ModuleIdentifier::PassiveRecon,
                operation: GraphOperation::AddNode {
                    node_type: NodeType::Config,
                    properties: vec![("path".to_string(), f.path.to_string_lossy().to_string())],
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}

pub fn run_recon_standalone(
    source_dir: &Option<PathBuf>,
    vuln_db_path: Option<&Path>,
) -> Result<Vec<OperationLogEntry>, PhaseError> {
    let Some(source_dir) = source_dir else {
        return Ok(Vec::new());
    };

    let walk = walk_directory(source_dir).map_err(|e| PhaseError::FilesystemWalk(e.to_string()))?;
    let lock_files: Vec<_> = walk
        .files
        .iter()
        .filter(|f| f.classification == FileClassification::LockFile)
        .collect();

    let mut all_deps = Vec::new();
    for lock_file in &lock_files {
        if let Ok(deps) = parse_lock_file(&lock_file.path) {
            all_deps.extend(deps);
        }
    }

    let mut sequence = 0u64;
    let mut entries = Vec::new();
    entries.extend(deps_to_operations(&all_deps, &mut sequence));
    entries.extend(vuln_lookup(&all_deps, &mut sequence, vuln_db_path));
    entries.extend(walk_to_operations(&walk.files, &mut sequence));
    Ok(entries)
}

/// Runs gau to harvest historical URLs from web archives.
pub fn harvest_urls(target: &str) -> Vec<String> {
    let wrapper = GauWrapper;
    if !wrapper.is_available() {
        tracing::debug!("gau not installed, skipping URL harvest");
        return Vec::new();
    }
    let context = ExploitContext::new(
        target.to_string(),
        String::new(),
        VulnerabilityClass::InformationDisclosure,
    );
    let command = wrapper.build_command(&context);
    let (stdout, stderr) = match spawn_with_timeout(command, wrapper.timeout(), "gau") {
        Ok(output) => output,
        Err(e) => {
            tracing::warn!(error = %e, "gau URL harvest failed");
            return Vec::new();
        }
    };
    let results = wrapper.parse_output(&stdout, &stderr);
    let mut urls: Vec<String> = results
        .iter()
        .filter_map(|r| r.extracted_data.clone())
        .collect();
    urls.sort();
    urls.dedup();
    if !urls.is_empty() {
        tracing::info!(count = urls.len(), "gau harvested historical URLs");
    }
    urls
}

/// Converts harvested URLs into Endpoint node operations, deduplicating by path.
pub(crate) fn harvested_urls_to_operations(
    urls: &[String],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    let mut seen_paths = HashSet::new();
    urls.iter()
        .filter_map(|url| extract_path_from_url(url))
        .filter(|path| seen_paths.insert(path.clone()))
        .map(|path| {
            *seq += 1;
            OperationLogEntry {
                sequence_number: *seq,
                module: ModuleIdentifier::PassiveRecon,
                operation: GraphOperation::AddNode {
                    node_type: NodeType::Endpoint,
                    properties: vec![
                        ("path".to_string(), path),
                        ("method".to_string(), "GET".to_string()),
                        ("source".to_string(), "gau".to_string()),
                    ],
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}

/// Runs amass for passive subdomain enumeration.
pub fn enumerate_subdomains(target: &str) -> Vec<String> {
    let wrapper = AmassWrapper;
    if !wrapper.is_available() {
        tracing::debug!("amass not installed, skipping subdomain enumeration");
        return Vec::new();
    }
    let context = ExploitContext::new(
        target.to_string(),
        String::new(),
        VulnerabilityClass::InformationDisclosure,
    );
    let command = wrapper.build_command(&context);
    let (stdout, stderr) = match spawn_with_timeout(command, wrapper.timeout(), "amass") {
        Ok(output) => output,
        Err(e) => {
            tracing::warn!(error = %e, "amass subdomain enumeration failed");
            return Vec::new();
        }
    };
    let results = wrapper.parse_output(&stdout, &stderr);
    let mut subdomains: Vec<String> = results
        .iter()
        .filter_map(|r| r.extracted_data.clone())
        .collect();
    subdomains.sort();
    subdomains.dedup();
    if !subdomains.is_empty() {
        tracing::info!(count = subdomains.len(), "amass found subdomains");
    }
    subdomains
}

/// Converts discovered subdomains into Service node operations.
pub(crate) fn subdomains_to_operations(
    subdomains: &[String],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    subdomains_to_operations_with_source(subdomains, "amass", seq)
}

pub(crate) fn subdomains_to_operations_with_source(
    subdomains: &[String],
    source: &str,
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    subdomains
        .iter()
        .map(|subdomain| {
            *seq += 1;
            OperationLogEntry {
                sequence_number: *seq,
                module: ModuleIdentifier::PassiveRecon,
                operation: GraphOperation::AddNode {
                    node_type: NodeType::Service,
                    properties: vec![
                        ("hostname".to_string(), subdomain.clone()),
                        ("source".to_string(), source.to_string()),
                    ],
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}

/// Runs trufflehog to scan source directory for leaked secrets.
pub fn scan_secrets(source_dir: &Path) -> Vec<ExploitResult> {
    let wrapper = TrufflehogWrapper;
    if !wrapper.is_available() {
        tracing::debug!("trufflehog not installed, skipping secret scan");
        return Vec::new();
    }
    let context = ExploitContext::new(
        String::new(),
        source_dir.to_string_lossy().to_string(),
        VulnerabilityClass::SensitiveDataExposure,
    );
    let command = wrapper.build_command(&context);
    let (stdout, stderr) = match spawn_with_timeout(command, wrapper.timeout(), "trufflehog") {
        Ok(output) => output,
        Err(e) => {
            tracing::warn!(error = %e, "trufflehog secret scan failed");
            return Vec::new();
        }
    };
    let results = wrapper.parse_output(&stdout, &stderr);
    if !results.is_empty() {
        tracing::info!(count = results.len(), "trufflehog found potential secrets");
    }
    results
}

/// Runs trufflehog in GitHub org mode to scan an organization's repositories.
///
/// Requires trufflehog installed and GITHUB_TOKEN env var for API access.
/// Uses the same output parser as filesystem mode since the JSON format
/// is identical.
pub fn scan_github_org(org: &str) -> Vec<ExploitResult> {
    let wrapper = TrufflehogWrapper;
    if !wrapper.is_available() {
        tracing::debug!("trufflehog not installed, skipping GitHub org scan");
        return Vec::new();
    }
    if std::env::var("GITHUB_TOKEN").is_err() {
        tracing::debug!("GITHUB_TOKEN not set, skipping GitHub org scan");
        return Vec::new();
    }
    let mut command = std::process::Command::new("trufflehog");
    command.args([
        "github",
        "--org",
        org,
        "--json",
        "--results=verified,unknown",
        "--no-update",
    ]);
    // GitHub org scanning is slower than filesystem — double the wrapper's base timeout
    let timeout = wrapper.timeout().saturating_mul(2);
    let (stdout, stderr) = match spawn_with_timeout(command, timeout, "trufflehog-github") {
        Ok(output) => output,
        Err(e) => {
            tracing::warn!(org = %org, error = %e, "trufflehog GitHub org scan failed");
            return Vec::new();
        }
    };
    let results = wrapper.parse_output(&stdout, &stderr);
    if !results.is_empty() {
        tracing::info!(
            org = %org,
            count = results.len(),
            "trufflehog found secrets in GitHub org"
        );
    }
    results
}

/// Queries crt.sh Certificate Transparency logs for subdomains of the target.
///
/// Uses the free crt.sh HTTPS API (no API key needed). Returns deduplicated
/// subdomain names. Returns an empty vec on any network/parse error.
pub fn query_crtsh(target: &str) -> Vec<String> {
    let Some(domain) = crate::recon_client::validated_domain(target) else {
        tracing::debug!("could not extract domain from target for crt.sh query");
        return Vec::new();
    };
    let url = format!("https://crt.sh/?q=%.{domain}&output=json");
    let client = match crate::recon_client::build_client(std::time::Duration::from_secs(30)) {
        Some(c) => c,
        None => {
            tracing::warn!("failed to build HTTP client for crt.sh");
            return Vec::new();
        }
    };
    let response = match client.get(&url).send() {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "crt.sh query failed");
            return Vec::new();
        }
    };
    let body = match response.text() {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "failed to read crt.sh response body");
            return Vec::new();
        }
    };
    let subdomains = parse_crtsh_response(&body);
    if !subdomains.is_empty() {
        tracing::info!(
            count = subdomains.len(),
            "crt.sh found subdomains via CT logs"
        );
    }
    subdomains
}

/// Parses crt.sh JSON response into a deduplicated list of subdomain names.
pub(crate) fn parse_crtsh_response(body: &str) -> Vec<String> {
    let entries: Vec<CrtshEntry> = match serde_json::from_str(body) {
        Ok(e) => e,
        Err(_) => {
            tracing::debug!("failed to parse crt.sh JSON response");
            return Vec::new();
        }
    };
    let mut seen = HashSet::new();
    let mut subdomains = Vec::new();
    for entry in &entries {
        for name in entry.name_value.split('\n') {
            let name = name.trim().trim_start_matches("*.");
            if !name.is_empty() && seen.insert(name) {
                subdomains.push(name.to_string());
            }
        }
    }
    subdomains
}

#[derive(serde::Deserialize)]
struct CrtshEntry {
    #[serde(default)]
    name_value: String,
}

pub(crate) fn crtsh_to_operations(subdomains: &[String], seq: &mut u64) -> Vec<OperationLogEntry> {
    subdomains_to_operations_with_source(subdomains, "crtsh", seq)
}

/// Queries SecurityTrails API for subdomains of the target domain.
///
/// Requires `SECURITYTRAILS_API_KEY` environment variable. Returns empty vec
/// if the key is not set or the query fails. Free tier: 50 queries/month.
pub fn query_securitytrails(target: &str) -> Vec<String> {
    let api_key = match std::env::var("SECURITYTRAILS_API_KEY") {
        Ok(key) if !key.is_empty() => key,
        _ => {
            tracing::debug!("SECURITYTRAILS_API_KEY not set, skipping SecurityTrails query");
            return Vec::new();
        }
    };
    let Some(domain) = crate::recon_client::validated_domain(target) else {
        return Vec::new();
    };
    let url = format!("https://api.securitytrails.com/v1/domain/{domain}/subdomains");
    let client = match crate::recon_client::build_client(std::time::Duration::from_secs(30)) {
        Some(c) => c,
        None => {
            tracing::warn!("failed to build HTTP client for SecurityTrails");
            return Vec::new();
        }
    };
    let response = match client.get(&url).header("APIKEY", &api_key).send() {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "SecurityTrails query failed");
            return Vec::new();
        }
    };
    if !response.status().is_success() {
        tracing::warn!(
            status = %response.status(),
            "SecurityTrails returned non-success status"
        );
        return Vec::new();
    }
    let body = match response.text() {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "failed to read SecurityTrails response body");
            return Vec::new();
        }
    };
    let subdomains = parse_securitytrails_response(&body, &domain);
    if !subdomains.is_empty() {
        tracing::info!(count = subdomains.len(), "SecurityTrails found subdomains");
    }
    subdomains
}

/// Parses SecurityTrails JSON response into fully-qualified subdomain names.
///
/// SecurityTrails returns subdomain prefixes only (e.g. "www", "api").
/// This function appends the base domain to create FQDNs.
pub(crate) fn parse_securitytrails_response(body: &str, domain: &str) -> Vec<String> {
    let response: SecurityTrailsResponse = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(_) => {
            tracing::debug!("failed to parse SecurityTrails JSON response");
            return Vec::new();
        }
    };
    response
        .subdomains
        .into_iter()
        .filter(|s| !s.is_empty())
        .map(|prefix| format!("{prefix}.{domain}"))
        .collect()
}

#[derive(serde::Deserialize)]
struct SecurityTrailsResponse {
    #[serde(default)]
    subdomains: Vec<String>,
}

pub(crate) fn securitytrails_to_operations(
    subdomains: &[String],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    subdomains_to_operations_with_source(subdomains, "securitytrails", seq)
}

/// Converts trufflehog results into AddFinding operations.
pub(crate) fn secret_findings_to_operations(
    results: &[ExploitResult],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    results
        .iter()
        .map(|r| {
            *seq += 1;
            let severity = r.severity_upgrade.unwrap_or(5.0);
            OperationLogEntry {
                sequence_number: *seq,
                module: ModuleIdentifier::PassiveRecon,
                operation: GraphOperation::AddFinding {
                    linked_node_ids: vec![],
                    vulnerability_class: VulnerabilityClass::SensitiveDataExposure,
                    severity,
                    confidence: aegis_protocol::finding::Confidence::new(0.85).unwrap(),
                    certificate: Vec::new(),
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}
