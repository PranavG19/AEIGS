pub mod bot_detection_probe;
pub mod confirmation;
pub mod cors_detector;
pub mod defense_profile;
pub mod executor;
pub mod header_analyzer;
pub mod idor_tester;
pub mod mass_assignment_tester;
pub mod mutator;
pub mod oracle;
pub mod payload_selector;
pub mod race_tester;
pub mod rate_limit_detector;
pub mod request_patterns;
pub mod scheduler;
pub mod stealth_config;
pub mod streaming_fuzzer;
pub mod waf_fingerprinter;

pub use bot_detection_probe::*;
pub use confirmation::*;
pub use cors_detector::*;
pub use defense_profile::*;
pub use header_analyzer::*;
pub use idor_tester::*;
pub use mass_assignment_tester::*;
pub use race_tester::*;
pub use rate_limit_detector::*;
pub use waf_fingerprinter::*;

#[cfg(test)]
#[path = "scheduler_test.rs"]
mod scheduler_test;

#[cfg(test)]
#[path = "mutator_test.rs"]
mod mutator_test;

#[cfg(test)]
#[path = "executor_test.rs"]
mod executor_test;

#[cfg(test)]
#[path = "oracle_test.rs"]
mod oracle_test;

#[cfg(test)]
#[path = "stealth_config_test.rs"]
mod stealth_config_test;

#[cfg(test)]
#[path = "defense_profile_test.rs"]
mod defense_profile_test;

#[cfg(test)]
#[path = "payload_selector_test.rs"]
mod payload_selector_test;

#[cfg(test)]
#[path = "request_patterns_test.rs"]
mod request_patterns_test;

#[cfg(test)]
#[path = "confirmation_test.rs"]
mod confirmation_test;

#[cfg(test)]
#[path = "race_tester_test.rs"]
mod race_tester_test;
