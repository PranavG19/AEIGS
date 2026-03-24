mod cors_exploit;
mod csp_bypass;
mod csrf_bypass;
mod encoding_transformer;
mod fingerprint_db;
mod header_transformer;
mod http2_fingerprint;
mod payload_obfuscator;
mod persona;
mod rate_limit_bypass;
mod session_manager;
mod timing_controller;
mod tls_clienthello;
mod tls_config;
mod transport;
pub mod waf_grammar;

pub use cors_exploit::*;
pub use csp_bypass::*;
pub use csrf_bypass::*;
pub use encoding_transformer::*;
pub use fingerprint_db::*;
pub use header_transformer::*;
pub use http2_fingerprint::*;
pub use payload_obfuscator::*;
pub use persona::*;
pub use rate_limit_bypass::*;
pub use session_manager::*;
pub use timing_controller::*;
pub use tls_clienthello::*;
pub use tls_config::*;
pub use transport::*;
pub use waf_grammar::*;

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
