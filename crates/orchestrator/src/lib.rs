pub mod actor;
pub mod ambient_light_audit;
pub mod api_endpoint_leak_audit;
pub mod api_version_audit;
pub mod attest;
pub mod auth_session;
pub mod background_sync_audit;
pub mod base_tag_audit;
pub mod battery_audit;
pub mod benchmark;
pub mod broadcast_channel_audit;
pub mod cache_audit;
pub mod cache_poison_audit;
pub mod calibration;
pub mod canvas_fingerprint_audit;
pub mod checkpoint;
pub mod clear_site_data_audit;
pub mod clipboard_audit;
pub mod clickjack_audit;
pub mod comment_leak;
pub mod compute_pressure_audit;
pub mod content_disposition_audit;
pub mod content_index_audit;
pub mod content_type_audit;
pub mod content_type_confusion_audit;
pub mod contact_picker_audit;
pub mod convergence;
pub mod cookie_audit;
pub mod cookie_prefix_audit;
pub mod coop_coep_audit;
pub mod corp_audit;
pub mod cors_preflight_audit;
pub mod credential_api_audit;
pub mod credential_harvest_audit;
pub mod cors_scanner;
pub mod crlf_injection_audit;
pub mod csp_analyzer;
pub mod csp_nonce_audit;
pub mod csp_report_leak_audit;
pub mod cve_correlator;
pub mod dangerous_js_audit;
pub mod dependency_confusion_audit;
pub mod deprecated_header_audit;
pub mod deserialization_audit;
pub mod device_motion_audit;
pub mod digital_goods_audit;
pub mod distributed;
pub mod distributed_transport;
pub mod dns_enumerator;
pub mod dom_clobbering_audit;
pub mod dns_prefetch_control_audit;
pub mod doctor;
pub mod document_domain_audit;
pub mod drag_drop_audit;
pub mod email_security;
pub mod endpoint_similarity;
pub mod error_page_audit;
pub mod etag_audit;
pub mod expose_headers_audit;
pub mod eyedropper_audit;
pub mod fetch_credential_audit;
pub mod file_access_audit;
pub mod file_system_access_audit;
pub mod form_audit;
pub mod fullscreen_audit;
pub mod gamepad_audit;
pub mod geolocation_audit;
pub mod graphql_introspection_audit;
mod graph_persistence;
pub mod hardware_api_audit;
pub mod header_audit;
pub mod hidden_input_audit;
pub mod host_header_audit;
pub mod hsts_preload;
pub(crate) mod html_parser;
pub mod http_version;
pub mod hypothesis_bridge;
pub mod idle_detection_audit;
pub mod idor_analyzer;
pub mod iframe_audit;
pub mod info_disclosure;
pub mod inline_handler_audit;
pub mod intersection_observer_audit;
pub mod interactive;
pub mod js_library_scanner;
pub mod jwt_header_audit;
pub mod jsonp_audit;
pub mod link_header_audit;
pub mod local_font_audit;
pub mod mass_assign_audit;
pub mod meta_redirect_audit;
pub mod meta_tag_audit;
pub mod method_override_audit;
pub mod method_scanner;
pub mod mixed_content;
pub mod mutation_observer_audit;
pub mod navigation_api_audit;
pub mod nel_audit;
pub mod notification_audit;
pub mod object_url_audit;
pub mod open_redirect_param_audit;
pub mod opener_audit;
pub mod path_traversal_audit;
pub mod payment_form_audit;
pub mod payment_request_audit;
pub mod perf_observer_audit;
pub mod permissions_api_audit;
pub mod permissions_policy;
pub mod pip_audit;
mod phase_analyze;
mod phase_crawl;
mod phase_dom_verify;
pub mod phase_error;
mod phase_fingerprint;
mod phase_fuzz;
mod phase_recon;
mod phase_report;
pub mod pipeline;
pub mod pipeline_composer;
pub mod postmessage_audit;
pub mod preconnect_audit;
pub mod presentation_audit;
pub mod prototype_pollution_audit;
pub mod proxy_header_audit;
pub mod rate_limit_detector;
pub mod recon_client;
pub mod redirect_scanner;
pub mod resize_observer_audit;
pub mod resource_timing_audit;
pub mod request_smuggling_audit;
pub mod referrer_audit;
pub mod reporting_api_audit;
pub mod reporting_endpoints_audit;
pub mod robots_parser;
pub mod s3_scanner;
pub mod scan_config;
pub mod scan_history;
pub mod scan_strategy;
pub mod screen_capture_audit;
pub mod security_txt;
pub mod selection_audit;
pub mod sensitive_file_audit;
pub mod service_worker_audit;
pub mod session_fixation_audit;
pub mod sse_audit;
pub mod ssrf_redirect_audit;
pub mod storage_access_audit;
pub mod storage_audit;
pub mod server_timing_audit;
pub mod shared_buffer_audit;
pub mod shodan_lookup;
pub mod sourcemap_detector;
pub mod sourcemap_header_audit;
pub mod speech_api_audit;
pub mod sri_checker;
pub mod subdomain_takeover;
pub mod tech_detector;
pub mod telemetry;
pub mod template_injection_audit;
pub mod third_party_script_audit;
pub mod timing_allow_origin_audit;
pub mod trusted_types_audit;
pub mod verb_tamper_audit;
pub mod tls_scanner;
pub mod topics_api_audit;
pub mod update_db;
mod util;
pub mod viewport_audit;
pub mod waf_detector;
pub mod wake_lock_audit;
pub mod wasm_audit;
pub mod web_bluetooth_audit;
pub mod web_locks_audit;
pub mod web_nfc_audit;
pub mod web_serial_audit;
pub mod web_share_audit;
pub mod web_transport_audit;
pub mod webcrypto_audit;
pub mod webhid_audit;
pub mod webrtc_audit;
pub mod websocket_audit;
pub mod webusb_audit;
pub mod window_management_audit;
pub mod window_name_audit;
pub mod wireless_api_audit;
pub mod www_authenticate_audit;
pub mod xfo_audit;

pub use actor::*;
pub use ambient_light_audit::*;
pub use api_endpoint_leak_audit::*;
pub use api_version_audit::*;
pub use auth_session::*;
pub use background_sync_audit::*;
pub use battery_audit::*;
pub use base_tag_audit::*;
pub use broadcast_channel_audit::*;
pub use cache_audit::*;
pub use cache_poison_audit::*;
pub use canvas_fingerprint_audit::*;
pub use checkpoint::*;
pub use clear_site_data_audit::*;
pub use clickjack_audit::*;
pub use clipboard_audit::*;
pub use comment_leak::*;
pub use compute_pressure_audit::*;
pub use content_disposition_audit::*;
pub use content_index_audit::*;
pub use content_type_audit::*;
pub use content_type_confusion_audit::*;
pub use contact_picker_audit::*;
pub use convergence::*;
pub use cookie_audit::*;
pub use cookie_prefix_audit::*;
pub use coop_coep_audit::*;
pub use corp_audit::*;
pub use cors_preflight_audit::*;
pub use cors_scanner::*;
pub use credential_api_audit::*;
pub use credential_harvest_audit::*;
pub use csp_analyzer::*;
pub use csp_nonce_audit::*;
pub use csp_report_leak_audit::*;
pub use cve_correlator::*;
pub use dangerous_js_audit::*;
pub use dependency_confusion_audit::*;
pub use deprecated_header_audit::*;
pub use deserialization_audit::*;
pub use device_motion_audit::*;
pub use digital_goods_audit::*;
pub use distributed::*;
pub use distributed_transport::*;
pub use dns_enumerator::*;
pub use dom_clobbering_audit::*;
pub use dns_prefetch_control_audit::*;
pub use document_domain_audit::*;
pub use drag_drop_audit::*;
pub use email_security::*;
pub use endpoint_similarity::*;
pub use error_page_audit::*;
pub use etag_audit::*;
pub use expose_headers_audit::*;
pub use eyedropper_audit::*;
pub use fetch_credential_audit::*;
pub use file_access_audit::*;
pub use file_system_access_audit::*;
pub use form_audit::*;
pub use fullscreen_audit::*;
pub use gamepad_audit::*;
pub use geolocation_audit::*;
pub use graphql_introspection_audit::*;
pub use graph_persistence::*;
pub use hardware_api_audit::*;
pub use header_audit::*;
pub use hidden_input_audit::*;
pub use hsts_preload::*;
pub use http_version::*;
pub use hypothesis_bridge::*;
pub use idle_detection_audit::*;
pub use idor_analyzer::*;
pub use iframe_audit::*;
pub use info_disclosure::*;
pub use inline_handler_audit::*;
pub use intersection_observer_audit::*;
pub use interactive::*;
pub use js_library_scanner::*;
pub use jwt_header_audit::*;
pub use jsonp_audit::*;
pub use link_header_audit::*;
pub use local_font_audit::*;
pub use mass_assign_audit::*;
pub use meta_redirect_audit::*;
pub use meta_tag_audit::*;
pub use method_override_audit::*;
pub use method_scanner::*;
pub use mixed_content::*;
pub use mutation_observer_audit::*;
pub use navigation_api_audit::*;
pub use nel_audit::*;
pub use notification_audit::*;
pub use object_url_audit::*;
pub use open_redirect_param_audit::*;
pub use opener_audit::*;
pub use path_traversal_audit::*;
pub use payment_form_audit::*;
pub use payment_request_audit::*;
pub use perf_observer_audit::*;
pub use permissions_api_audit::*;
pub use permissions_policy::*;
pub use pip_audit::*;
pub use phase_analyze::*;
pub use phase_crawl::*;
pub use phase_dom_verify::*;
pub use phase_error::*;
pub use phase_fingerprint::*;
pub use phase_fuzz::*;
pub use phase_recon::*;
pub use phase_report::*;
pub use pipeline::*;
pub use pipeline_composer::*;
pub use postmessage_audit::*;
pub use preconnect_audit::*;
pub use presentation_audit::*;
pub use prototype_pollution_audit::*;
pub use proxy_header_audit::*;
pub use rate_limit_detector::*;
pub use recon_client::*;
pub use redirect_scanner::*;
pub use resize_observer_audit::*;
pub use resource_timing_audit::*;
pub use request_smuggling_audit::*;
pub use referrer_audit::*;
pub use reporting_api_audit::*;
pub use reporting_endpoints_audit::*;
pub use robots_parser::*;
pub use s3_scanner::*;
pub use scan_config::*;
pub use scan_history::*;
pub use scan_strategy::*;
pub use screen_capture_audit::*;
pub use security_txt::*;
pub use selection_audit::*;
pub use sensitive_file_audit::*;
pub use service_worker_audit::*;
pub use session_fixation_audit::*;
pub use sse_audit::*;
pub use ssrf_redirect_audit::*;
pub use storage_access_audit::*;
pub use storage_audit::*;
pub use server_timing_audit::*;
pub use shared_buffer_audit::*;
pub use shodan_lookup::*;
pub use sourcemap_detector::*;
pub use sourcemap_header_audit::*;
pub use speech_api_audit::*;
pub use sri_checker::*;
pub use subdomain_takeover::*;
pub use tech_detector::*;
pub use telemetry::*;
pub use template_injection_audit::*;
pub use third_party_script_audit::*;
pub use timing_allow_origin_audit::*;
pub use trusted_types_audit::*;
pub use verb_tamper_audit::*;
pub use tls_scanner::*;
pub use topics_api_audit::*;
pub use update_db::*;
pub use viewport_audit::*;
pub use waf_detector::*;
pub use wake_lock_audit::*;
pub use wasm_audit::*;
pub use web_bluetooth_audit::*;
pub use web_locks_audit::*;
pub use web_nfc_audit::*;
pub use web_serial_audit::*;
pub use web_share_audit::*;
pub use web_transport_audit::*;
pub use webcrypto_audit::*;
pub use webhid_audit::*;
pub use webrtc_audit::*;
pub use websocket_audit::*;
pub use webusb_audit::*;
pub use window_management_audit::*;
pub use window_name_audit::*;
pub use wireless_api_audit::*;
pub use www_authenticate_audit::*;
pub use xfo_audit::*;

#[cfg(test)]
#[path = "scan_history_test.rs"]
mod scan_history_test;

#[cfg(test)]
#[path = "scan_config_test.rs"]
mod scan_config_test;

#[cfg(test)]
#[path = "pipeline_test.rs"]
mod pipeline_test;

#[cfg(test)]
#[path = "phase_recon_test.rs"]
mod phase_recon_test;

#[cfg(test)]
#[path = "phase_crawl_test.rs"]
mod phase_crawl_test;

#[cfg(test)]
#[path = "phase_dom_verify_test.rs"]
mod phase_dom_verify_test;

#[cfg(test)]
#[path = "phase_fingerprint_test.rs"]
mod phase_fingerprint_test;

#[cfg(test)]
#[path = "phase_fuzz_test.rs"]
mod phase_fuzz_test;

#[cfg(test)]
#[path = "phase_analyze_test.rs"]
mod phase_analyze_test;

#[cfg(test)]
#[path = "phase_report_test.rs"]
mod phase_report_test;

#[cfg(test)]
#[path = "graph_persistence_test.rs"]
mod graph_persistence_test;

#[cfg(test)]
#[path = "graphql_introspection_audit_test.rs"]
mod graphql_introspection_audit_test;

#[cfg(test)]
#[path = "hardware_api_audit_test.rs"]
mod hardware_api_audit_test;

#[cfg(test)]
#[path = "phase_error_test.rs"]
mod phase_error_test;

#[cfg(test)]
#[path = "checkpoint_test.rs"]
mod checkpoint_test;

#[cfg(test)]
#[path = "convergence_test.rs"]
mod convergence_test;

#[cfg(test)]
#[path = "endpoint_similarity_test.rs"]
mod endpoint_similarity_test;

#[cfg(test)]
#[path = "fetch_credential_audit_test.rs"]
mod fetch_credential_audit_test;

#[cfg(test)]
#[path = "file_access_audit_test.rs"]
mod file_access_audit_test;

#[cfg(test)]
#[path = "form_audit_test.rs"]
mod form_audit_test;

#[cfg(test)]
#[path = "actor_test.rs"]
mod actor_test;

#[cfg(test)]
#[path = "api_endpoint_leak_audit_test.rs"]
mod api_endpoint_leak_audit_test;

#[cfg(test)]
#[path = "api_version_audit_test.rs"]
mod api_version_audit_test;

#[cfg(test)]
#[path = "interactive_test.rs"]
mod interactive_test;

#[cfg(test)]
#[path = "pipeline_composer_test.rs"]
mod pipeline_composer_test;

#[cfg(test)]
#[path = "distributed_test.rs"]
mod distributed_test;

#[cfg(test)]
#[path = "distributed_transport_test.rs"]
mod distributed_transport_test;

#[cfg(test)]
#[path = "hypothesis_bridge_test.rs"]
mod hypothesis_bridge_test;

#[cfg(test)]
#[path = "idle_detection_audit_test.rs"]
mod idle_detection_audit_test;

#[cfg(test)]
#[path = "idor_analyzer_test.rs"]
mod idor_analyzer_test;

#[cfg(test)]
#[path = "auth_session_test.rs"]
mod auth_session_test;

#[cfg(test)]
#[path = "base_tag_audit_test.rs"]
mod base_tag_audit_test;

#[cfg(test)]
#[path = "cve_correlator_test.rs"]
mod cve_correlator_test;

#[cfg(test)]
#[path = "scan_strategy_test.rs"]
mod scan_strategy_test;

#[cfg(test)]
#[path = "s3_scanner_test.rs"]
mod s3_scanner_test;

#[cfg(test)]
#[path = "shared_buffer_audit_test.rs"]
mod shared_buffer_audit_test;

#[cfg(test)]
#[path = "shodan_lookup_test.rs"]
mod shodan_lookup_test;

#[cfg(test)]
#[path = "tls_scanner_test.rs"]
mod tls_scanner_test;

#[cfg(test)]
#[path = "header_audit_test.rs"]
mod header_audit_test;

#[cfg(test)]
#[path = "html_parser_test.rs"]
mod html_parser_test;

#[cfg(test)]
#[path = "robots_parser_test.rs"]
mod robots_parser_test;

#[cfg(test)]
#[path = "dns_enumerator_test.rs"]
mod dns_enumerator_test;

#[cfg(test)]
#[path = "cors_preflight_audit_test.rs"]
mod cors_preflight_audit_test;

#[cfg(test)]
#[path = "cors_scanner_test.rs"]
mod cors_scanner_test;

#[cfg(test)]
#[path = "crlf_injection_audit_test.rs"]
mod crlf_injection_audit_test;

#[cfg(test)]
#[path = "cookie_audit_test.rs"]
mod cookie_audit_test;

#[cfg(test)]
#[path = "cookie_prefix_audit_test.rs"]
mod cookie_prefix_audit_test;

#[cfg(test)]
#[path = "meta_redirect_audit_test.rs"]
mod meta_redirect_audit_test;

#[cfg(test)]
#[path = "meta_tag_audit_test.rs"]
mod meta_tag_audit_test;

#[cfg(test)]
#[path = "method_override_audit_test.rs"]
mod method_override_audit_test;

#[cfg(test)]
#[path = "method_scanner_test.rs"]
mod method_scanner_test;

#[cfg(test)]
#[path = "mixed_content_test.rs"]
mod mixed_content_test;

#[cfg(test)]
#[path = "open_redirect_param_audit_test.rs"]
mod open_redirect_param_audit_test;

#[cfg(test)]
#[path = "opener_audit_test.rs"]
mod opener_audit_test;

#[cfg(test)]
#[path = "path_traversal_audit_test.rs"]
mod path_traversal_audit_test;

#[cfg(test)]
#[path = "redirect_scanner_test.rs"]
mod redirect_scanner_test;

#[cfg(test)]
#[path = "request_smuggling_audit_test.rs"]
mod request_smuggling_audit_test;

#[cfg(test)]
#[path = "iframe_audit_test.rs"]
mod iframe_audit_test;

#[cfg(test)]
#[path = "info_disclosure_test.rs"]
mod info_disclosure_test;

#[cfg(test)]
#[path = "inline_handler_audit_test.rs"]
mod inline_handler_audit_test;

#[cfg(test)]
#[path = "intersection_observer_audit_test.rs"]
mod intersection_observer_audit_test;

#[cfg(test)]
#[path = "subdomain_takeover_test.rs"]
mod subdomain_takeover_test;

#[cfg(test)]
#[path = "email_security_test.rs"]
mod email_security_test;

#[cfg(test)]
#[path = "csp_analyzer_test.rs"]
mod csp_analyzer_test;

#[cfg(test)]
#[path = "csp_nonce_audit_test.rs"]
mod csp_nonce_audit_test;

#[cfg(test)]
#[path = "csp_report_leak_audit_test.rs"]
mod csp_report_leak_audit_test;

#[cfg(test)]
#[path = "hsts_preload_test.rs"]
mod hsts_preload_test;

#[cfg(test)]
#[path = "http_version_test.rs"]
mod http_version_test;

#[cfg(test)]
#[path = "viewport_audit_test.rs"]
mod viewport_audit_test;

#[cfg(test)]
#[path = "waf_detector_test.rs"]
mod waf_detector_test;

#[cfg(test)]
#[path = "rate_limit_detector_test.rs"]
mod rate_limit_detector_test;

#[cfg(test)]
#[path = "screen_capture_audit_test.rs"]
mod screen_capture_audit_test;

#[cfg(test)]
#[path = "security_txt_test.rs"]
mod security_txt_test;

#[cfg(test)]
#[path = "selection_audit_test.rs"]
mod selection_audit_test;

#[cfg(test)]
#[path = "webhid_audit_test.rs"]
mod webhid_audit_test;

#[cfg(test)]
#[path = "web_serial_audit_test.rs"]
mod web_serial_audit_test;

#[cfg(test)]
#[path = "web_share_audit_test.rs"]
mod web_share_audit_test;

#[cfg(test)]
#[path = "web_bluetooth_audit_test.rs"]
mod web_bluetooth_audit_test;

#[cfg(test)]
#[path = "web_transport_audit_test.rs"]
mod web_transport_audit_test;

#[cfg(test)]
#[path = "web_nfc_audit_test.rs"]
mod web_nfc_audit_test;

#[cfg(test)]
#[path = "presentation_audit_test.rs"]
mod presentation_audit_test;

#[cfg(test)]
#[path = "window_management_audit_test.rs"]
mod window_management_audit_test;

#[cfg(test)]
#[path = "webusb_audit_test.rs"]
mod webusb_audit_test;

#[cfg(test)]
#[path = "tech_detector_test.rs"]
mod tech_detector_test;

#[cfg(test)]
#[path = "permissions_api_audit_test.rs"]
mod permissions_api_audit_test;

#[cfg(test)]
#[path = "permissions_policy_test.rs"]
mod permissions_policy_test;

#[cfg(test)]
#[path = "ambient_light_audit_test.rs"]
mod ambient_light_audit_test;

#[cfg(test)]
#[path = "cache_audit_test.rs"]
mod cache_audit_test;

#[cfg(test)]
#[path = "cache_poison_audit_test.rs"]
mod cache_poison_audit_test;

#[cfg(test)]
#[path = "comment_leak_test.rs"]
mod comment_leak_test;

#[cfg(test)]
#[path = "content_disposition_audit_test.rs"]
mod content_disposition_audit_test;

#[cfg(test)]
#[path = "content_index_audit_test.rs"]
mod content_index_audit_test;

#[cfg(test)]
#[path = "contact_picker_audit_test.rs"]
mod contact_picker_audit_test;

#[cfg(test)]
#[path = "compute_pressure_audit_test.rs"]
mod compute_pressure_audit_test;

#[cfg(test)]
#[path = "local_font_audit_test.rs"]
mod local_font_audit_test;

#[cfg(test)]
#[path = "js_library_scanner_test.rs"]
mod js_library_scanner_test;

#[cfg(test)]
#[path = "jwt_header_audit_test.rs"]
mod jwt_header_audit_test;

#[cfg(test)]
#[path = "recon_client_test.rs"]
mod recon_client_test;

#[cfg(test)]
#[path = "sourcemap_detector_test.rs"]
mod sourcemap_detector_test;

#[cfg(test)]
#[path = "speech_api_audit_test.rs"]
mod speech_api_audit_test;

#[cfg(test)]
#[path = "sri_checker_test.rs"]
mod sri_checker_test;

#[cfg(test)]
#[path = "sensitive_file_audit_test.rs"]
mod sensitive_file_audit_test;

#[cfg(test)]
#[path = "service_worker_audit_test.rs"]
mod service_worker_audit_test;

#[cfg(test)]
#[path = "session_fixation_audit_test.rs"]
mod session_fixation_audit_test;

#[cfg(test)]
#[path = "sse_audit_test.rs"]
mod sse_audit_test;

#[cfg(test)]
#[path = "ssrf_redirect_audit_test.rs"]
mod ssrf_redirect_audit_test;

#[cfg(test)]
#[path = "storage_audit_test.rs"]
mod storage_audit_test;

#[cfg(test)]
#[path = "storage_access_audit_test.rs"]
mod storage_access_audit_test;

#[cfg(test)]
#[path = "dangerous_js_audit_test.rs"]
mod dangerous_js_audit_test;

#[cfg(test)]
#[path = "document_domain_audit_test.rs"]
mod document_domain_audit_test;

#[cfg(test)]
#[path = "dom_clobbering_audit_test.rs"]
mod dom_clobbering_audit_test;

#[cfg(test)]
#[path = "drag_drop_audit_test.rs"]
mod drag_drop_audit_test;

#[cfg(test)]
#[path = "eyedropper_audit_test.rs"]
mod eyedropper_audit_test;

#[cfg(test)]
#[path = "fullscreen_audit_test.rs"]
mod fullscreen_audit_test;

#[cfg(test)]
#[path = "file_system_access_audit_test.rs"]
mod file_system_access_audit_test;

#[cfg(test)]
#[path = "nel_audit_test.rs"]
mod nel_audit_test;

#[cfg(test)]
#[path = "navigation_api_audit_test.rs"]
mod navigation_api_audit_test;

#[cfg(test)]
#[path = "mutation_observer_audit_test.rs"]
mod mutation_observer_audit_test;

#[cfg(test)]
#[path = "link_header_audit_test.rs"]
mod link_header_audit_test;

#[cfg(test)]
#[path = "mass_assign_audit_test.rs"]
mod mass_assign_audit_test;

#[cfg(test)]
#[path = "reporting_endpoints_audit_test.rs"]
mod reporting_endpoints_audit_test;

#[cfg(test)]
#[path = "reporting_api_audit_test.rs"]
mod reporting_api_audit_test;

#[cfg(test)]
#[path = "template_injection_audit_test.rs"]
mod template_injection_audit_test;

#[cfg(test)]
#[path = "third_party_script_audit_test.rs"]
mod third_party_script_audit_test;

#[cfg(test)]
#[path = "timing_allow_origin_audit_test.rs"]
mod timing_allow_origin_audit_test;

#[cfg(test)]
#[path = "topics_api_audit_test.rs"]
mod topics_api_audit_test;

#[cfg(test)]
#[path = "trusted_types_audit_test.rs"]
mod trusted_types_audit_test;

#[cfg(test)]
#[path = "verb_tamper_audit_test.rs"]
mod verb_tamper_audit_test;

#[cfg(test)]
#[path = "clear_site_data_audit_test.rs"]
mod clear_site_data_audit_test;

#[cfg(test)]
#[path = "clickjack_audit_test.rs"]
mod clickjack_audit_test;

#[cfg(test)]
#[path = "sourcemap_header_audit_test.rs"]
mod sourcemap_header_audit_test;

#[cfg(test)]
#[path = "etag_audit_test.rs"]
mod etag_audit_test;

#[cfg(test)]
#[path = "www_authenticate_audit_test.rs"]
mod www_authenticate_audit_test;

#[cfg(test)]
#[path = "proxy_header_audit_test.rs"]
mod proxy_header_audit_test;

#[cfg(test)]
#[path = "dns_prefetch_control_audit_test.rs"]
mod dns_prefetch_control_audit_test;

#[cfg(test)]
#[path = "jsonp_audit_test.rs"]
mod jsonp_audit_test;

#[cfg(test)]
#[path = "hidden_input_audit_test.rs"]
mod hidden_input_audit_test;

#[cfg(test)]
#[path = "host_header_audit_test.rs"]
mod host_header_audit_test;

#[cfg(test)]
#[path = "postmessage_audit_test.rs"]
mod postmessage_audit_test;

#[cfg(test)]
#[path = "preconnect_audit_test.rs"]
mod preconnect_audit_test;

#[cfg(test)]
#[path = "prototype_pollution_audit_test.rs"]
mod prototype_pollution_audit_test;

#[cfg(test)]
#[path = "error_page_audit_test.rs"]
mod error_page_audit_test;

#[cfg(test)]
#[path = "referrer_audit_test.rs"]
mod referrer_audit_test;

#[cfg(test)]
#[path = "wasm_audit_test.rs"]
mod wasm_audit_test;

#[cfg(test)]
#[path = "wake_lock_audit_test.rs"]
mod wake_lock_audit_test;

#[cfg(test)]
#[path = "object_url_audit_test.rs"]
mod object_url_audit_test;

#[cfg(test)]
#[path = "resource_timing_audit_test.rs"]
mod resource_timing_audit_test;

#[cfg(test)]
#[path = "resize_observer_audit_test.rs"]
mod resize_observer_audit_test;

#[cfg(test)]
#[path = "credential_harvest_audit_test.rs"]
mod credential_harvest_audit_test;

#[cfg(test)]
#[path = "credential_api_audit_test.rs"]
mod credential_api_audit_test;

#[cfg(test)]
#[path = "payment_form_audit_test.rs"]
mod payment_form_audit_test;

#[cfg(test)]
#[path = "payment_request_audit_test.rs"]
mod payment_request_audit_test;

#[cfg(test)]
#[path = "perf_observer_audit_test.rs"]
mod perf_observer_audit_test;

#[cfg(test)]
#[path = "pip_audit_test.rs"]
mod pip_audit_test;

#[cfg(test)]
#[path = "window_name_audit_test.rs"]
mod window_name_audit_test;

#[cfg(test)]
#[path = "wireless_api_audit_test.rs"]
mod wireless_api_audit_test;

#[cfg(test)]
#[path = "webcrypto_audit_test.rs"]
mod webcrypto_audit_test;

#[cfg(test)]
#[path = "web_locks_audit_test.rs"]
mod web_locks_audit_test;

#[cfg(test)]
#[path = "clipboard_audit_test.rs"]
mod clipboard_audit_test;

#[cfg(test)]
#[path = "geolocation_audit_test.rs"]
mod geolocation_audit_test;

#[cfg(test)]
#[path = "gamepad_audit_test.rs"]
mod gamepad_audit_test;

#[cfg(test)]
#[path = "webrtc_audit_test.rs"]
mod webrtc_audit_test;

#[cfg(test)]
#[path = "notification_audit_test.rs"]
mod notification_audit_test;

#[cfg(test)]
#[path = "battery_audit_test.rs"]
mod battery_audit_test;

#[cfg(test)]
#[path = "background_sync_audit_test.rs"]
mod background_sync_audit_test;

#[cfg(test)]
#[path = "broadcast_channel_audit_test.rs"]
mod broadcast_channel_audit_test;

#[cfg(test)]
#[path = "canvas_fingerprint_audit_test.rs"]
mod canvas_fingerprint_audit_test;

#[cfg(test)]
#[path = "websocket_audit_test.rs"]
mod websocket_audit_test;

#[cfg(test)]
#[path = "xfo_audit_test.rs"]
mod xfo_audit_test;

#[cfg(test)]
#[path = "coop_coep_audit_test.rs"]
mod coop_coep_audit_test;

#[cfg(test)]
#[path = "corp_audit_test.rs"]
mod corp_audit_test;

#[cfg(test)]
#[path = "content_type_audit_test.rs"]
mod content_type_audit_test;

#[cfg(test)]
#[path = "content_type_confusion_audit_test.rs"]
mod content_type_confusion_audit_test;

#[cfg(test)]
#[path = "server_timing_audit_test.rs"]
mod server_timing_audit_test;

#[cfg(test)]
#[path = "dependency_confusion_audit_test.rs"]
mod dependency_confusion_audit_test;

#[cfg(test)]
#[path = "deprecated_header_audit_test.rs"]
mod deprecated_header_audit_test;

#[cfg(test)]
#[path = "deserialization_audit_test.rs"]
mod deserialization_audit_test;

#[cfg(test)]
#[path = "device_motion_audit_test.rs"]
mod device_motion_audit_test;

#[cfg(test)]
#[path = "digital_goods_audit_test.rs"]
mod digital_goods_audit_test;

#[cfg(test)]
#[path = "expose_headers_audit_test.rs"]
mod expose_headers_audit_test;

#[cfg(test)]
#[path = "integration_validation_test.rs"]
mod integration_validation_test;

#[cfg(test)]
#[path = "util_test.rs"]
mod util_test;
