mod anti_forensics;
mod cors_exploit;
mod csp_bypass;
mod csrf_bypass;
mod detection_scorer;
mod encoding_transformer;
mod fingerprint_db;
mod fingerprint_rotator;
mod header_transformer;
mod http2_fingerprint;
mod payload_obfuscator;
mod persona;
mod proxy_chain;
mod rate_limit_bypass;
mod session_manager;
mod timing_controller;
mod tls_clienthello;
mod tls_config;
mod tor_manager;
mod traffic_shaper;
mod transport;
mod waf_evasion_orchestrator;
pub mod waf_grammar;
mod response_injection;
mod verb_tampering;

pub use anti_forensics::*;
pub use cors_exploit::*;
pub use csp_bypass::*;
pub use csrf_bypass::*;
pub use detection_scorer::*;
pub use encoding_transformer::*;
pub use fingerprint_db::*;
pub use fingerprint_rotator::*;
pub use header_transformer::*;
pub use http2_fingerprint::*;
pub use payload_obfuscator::*;
pub use persona::*;
pub use proxy_chain::*;
pub use rate_limit_bypass::*;
pub use session_manager::*;
pub use timing_controller::*;
pub use tls_clienthello::*;
pub use tls_config::*;
pub use tor_manager::*;
pub use traffic_shaper::*;
pub use transport::*;
pub use waf_evasion_orchestrator::*;
pub use waf_grammar::*;
pub use response_injection::*;
pub use verb_tampering::*;

pub mod adaptive_evasion;
pub mod desync_library;
pub mod dns_poison;
pub mod encoding_ladder_v2;
pub mod evasion_catalogue;
pub mod ip_reputation;
pub mod ip_spoof_headers;
pub mod network_discovery;
pub mod tls_attacks;
pub mod waf_fingerprinter_v2;
pub mod waf_rule_reverser;

pub use adaptive_evasion::*;
pub use desync_library::*;
pub use dns_poison::*;
pub use encoding_ladder_v2::*;
pub use evasion_catalogue::*;
pub use ip_reputation::*;
pub use ip_spoof_headers::*;
pub use network_discovery::*;
pub use tls_attacks::*;
pub use waf_fingerprinter_v2::*;
pub use waf_rule_reverser::*;

#[cfg(test)]
#[path = "adaptive_evasion_test.rs"]
mod adaptive_evasion_test;

#[cfg(test)]
#[path = "desync_library_test.rs"]
mod desync_library_test;

#[cfg(test)]
#[path = "dns_poison_test.rs"]
mod dns_poison_test;

#[cfg(test)]
#[path = "encoding_ladder_v2_test.rs"]
mod encoding_ladder_v2_test;

#[cfg(test)]
#[path = "evasion_catalogue_test.rs"]
mod evasion_catalogue_test;

#[cfg(test)]
#[path = "ip_reputation_test.rs"]
mod ip_reputation_test;

#[cfg(test)]
#[path = "ip_spoof_headers_test.rs"]
mod ip_spoof_headers_test;

#[cfg(test)]
#[path = "network_discovery_test.rs"]
mod network_discovery_test;

#[cfg(test)]
#[path = "tls_attacks_test.rs"]
mod tls_attacks_test;

#[cfg(test)]
#[path = "waf_fingerprinter_v2_test.rs"]
mod waf_fingerprinter_v2_test;

#[cfg(test)]
#[path = "waf_rule_reverser_test.rs"]
mod waf_rule_reverser_test;

#[cfg(test)]
#[path = "cors_exploit_test.rs"]
mod cors_exploit_test;

#[cfg(test)]
#[path = "csp_bypass_test.rs"]
mod csp_bypass_test;

#[cfg(test)]
#[path = "csrf_bypass_test.rs"]
mod csrf_bypass_test;

#[cfg(test)]
#[path = "payload_obfuscator_test.rs"]
mod payload_obfuscator_test;

#[cfg(test)]
#[path = "persona_test.rs"]
mod persona_test;

#[cfg(test)]
#[path = "session_manager_test.rs"]
mod session_manager_test;

#[cfg(test)]
#[path = "timing_controller_test.rs"]
mod timing_controller_test;

#[cfg(test)]
#[path = "tls_config_test.rs"]
mod tls_config_test;

#[cfg(test)]
#[path = "anti_forensics_test.rs"]
mod anti_forensics_test;

#[cfg(test)]
#[path = "detection_scorer_test.rs"]
mod detection_scorer_test;

#[cfg(test)]
#[path = "encoding_transformer_test.rs"]
mod encoding_transformer_test;

#[cfg(test)]
#[path = "fingerprint_db_test.rs"]
mod fingerprint_db_test;

#[cfg(test)]
#[path = "fingerprint_rotator_test.rs"]
mod fingerprint_rotator_test;

#[cfg(test)]
#[path = "header_transformer_test.rs"]
mod header_transformer_test;

#[cfg(test)]
#[path = "http2_fingerprint_test.rs"]
mod http2_fingerprint_test;

#[cfg(test)]
#[path = "proxy_chain_test.rs"]
mod proxy_chain_test;

#[cfg(test)]
#[path = "rate_limit_bypass_test.rs"]
mod rate_limit_bypass_test;

#[cfg(test)]
#[path = "response_injection_test.rs"]
mod response_injection_test;

#[cfg(test)]
#[path = "tls_clienthello_test.rs"]
mod tls_clienthello_test;

#[cfg(test)]
#[path = "tor_manager_test.rs"]
mod tor_manager_test;

#[cfg(test)]
#[path = "traffic_shaper_test.rs"]
mod traffic_shaper_test;

#[cfg(test)]
#[path = "transport_test.rs"]
mod transport_test;

#[cfg(test)]
#[path = "verb_tampering_test.rs"]
mod verb_tampering_test;

#[cfg(test)]
#[path = "waf_evasion_orchestrator_test.rs"]
mod waf_evasion_orchestrator_test;

#[cfg(test)]
#[path = "waf_grammar_test.rs"]
mod waf_grammar_test;
