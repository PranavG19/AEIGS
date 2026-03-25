#![allow(ambiguous_glob_reexports)]

pub mod bot_detection_probe;
pub mod campaign_manager;
pub mod cloud_detector;
pub mod command_injection_gen;
pub mod comparative_fuzzer;
pub mod confirmation;
pub mod cors_detector;
pub mod coverage_guided_fuzzer;
pub mod coverage_tracker;
pub mod defense_profile;
pub mod deserialization_attacks;
pub mod executor;
pub mod graphql_tester;
pub mod h2_protocol_attacks;
pub mod header_analyzer;
pub mod header_smuggling;
pub mod idor_tester;
pub mod jailbreak_mutator;
pub mod llm_oracle;
pub mod mass_assignment_tester;
pub mod mutation_strategy;
pub mod mutator;
pub mod nosql_exploitation;
pub mod oracle;
pub mod param_pollution;
pub mod payload_scorer;
pub mod payload_selector;
pub mod protocol_fuzzer;
pub mod race_tester;
pub mod rate_limit_detector;
pub mod request_patterns;
pub mod scheduler;
pub mod smuggling_detector;
pub mod stealth_config;
pub mod streaming_fuzzer;
pub mod subdomain_takeover;
pub mod waf_fingerprinter;
pub mod websocket_binary_fuzzer;
pub mod xxe_engine;

pub mod anomaly_detector;
pub mod input_validation_bypass;
pub mod prototype_pollution_tester;
pub mod redos_engine;
pub mod sqli_second_order;

pub use anomaly_detector::*;
pub use bot_detection_probe::*;
pub use campaign_manager::*;
pub use cloud_detector::*;
pub use command_injection_gen::*;
pub use comparative_fuzzer::*;
pub use coverage_guided_fuzzer::*;
pub use confirmation::*;
pub use cors_detector::*;
pub use coverage_tracker::*;
pub use defense_profile::*;
pub use deserialization_attacks::*;
pub use executor::*;
pub use graphql_tester::*;
pub use h2_protocol_attacks::*;
pub use header_analyzer::*;
pub use header_smuggling::*;
pub use idor_tester::*;
pub use input_validation_bypass::*;
pub use jailbreak_mutator::*;
pub use llm_oracle::*;
pub use mass_assignment_tester::*;
pub use mutation_strategy::*;
pub use mutator::*;
pub use nosql_exploitation::*;
pub use oracle::*;
pub use param_pollution::*;
pub use payload_scorer::*;
pub use payload_selector::*;
pub use protocol_fuzzer::*;
pub use prototype_pollution_tester::*;
pub use race_tester::*;
pub use rate_limit_detector::*;
pub use redos_engine::*;
pub use request_patterns::*;
pub use scheduler::*;
pub use smuggling_detector::*;
pub use sqli_second_order::*;
pub use stealth_config::*;
pub use streaming_fuzzer::*;
pub use subdomain_takeover::*;
pub use waf_fingerprinter::*;
pub use websocket_binary_fuzzer::*;
pub use xxe_engine::*;

#[cfg(test)]
#[path = "anomaly_detector_test.rs"]
mod anomaly_detector_test;

#[cfg(test)]
#[path = "bot_detection_probe_test.rs"]
mod bot_detection_probe_test;

#[cfg(test)]
#[path = "campaign_manager_test.rs"]
mod campaign_manager_test;

#[cfg(test)]
#[path = "comparative_fuzzer_test.rs"]
mod comparative_fuzzer_test;

#[cfg(test)]
#[path = "command_injection_gen_test.rs"]
mod command_injection_gen_test;

#[cfg(test)]
#[path = "confirmation_test.rs"]
mod confirmation_test;

#[cfg(test)]
#[path = "cors_detector_test.rs"]
mod cors_detector_test;

#[cfg(test)]
#[path = "coverage_guided_fuzzer_test.rs"]
mod coverage_guided_fuzzer_test;

#[cfg(test)]
#[path = "coverage_tracker_test.rs"]
mod coverage_tracker_test;

#[cfg(test)]
#[path = "defense_profile_test.rs"]
mod defense_profile_test;

#[cfg(test)]
#[path = "deserialization_attacks_test.rs"]
mod deserialization_attacks_test;

#[cfg(test)]
#[path = "executor_test.rs"]
mod executor_test;

#[cfg(test)]
#[path = "graphql_tester_test.rs"]
mod graphql_tester_test;

#[cfg(test)]
#[path = "h2_protocol_attacks_test.rs"]
mod h2_protocol_attacks_test;

#[cfg(test)]
#[path = "header_analyzer_test.rs"]
mod header_analyzer_test;

#[cfg(test)]
#[path = "header_smuggling_test.rs"]
mod header_smuggling_test;

#[cfg(test)]
#[path = "idor_tester_test.rs"]
mod idor_tester_test;

#[cfg(test)]
#[path = "jailbreak_mutator_test.rs"]
mod jailbreak_mutator_test;

#[cfg(test)]
#[path = "llm_oracle_test.rs"]
mod llm_oracle_test;

#[cfg(test)]
#[path = "mass_assignment_tester_test.rs"]
mod mass_assignment_tester_test;

#[cfg(test)]
#[path = "mutator_test.rs"]
mod mutator_test;

#[cfg(test)]
#[path = "mutation_strategy_test.rs"]
mod mutation_strategy_test;

#[cfg(test)]
#[path = "nosql_exploitation_test.rs"]
mod nosql_exploitation_test;

#[cfg(test)]
#[path = "oracle_test.rs"]
mod oracle_test;

#[cfg(test)]
#[path = "param_pollution_test.rs"]
mod param_pollution_test;

#[cfg(test)]
#[path = "payload_selector_test.rs"]
mod payload_selector_test;

#[cfg(test)]
#[path = "prototype_pollution_tester_test.rs"]
mod prototype_pollution_tester_test;

#[cfg(test)]
#[path = "protocol_fuzzer_test.rs"]
mod protocol_fuzzer_test;

#[cfg(test)]
#[path = "race_tester_test.rs"]
mod race_tester_test;

#[cfg(test)]
#[path = "rate_limit_detector_test.rs"]
mod rate_limit_detector_test;

#[cfg(test)]
#[path = "request_patterns_test.rs"]
mod request_patterns_test;

#[cfg(test)]
#[path = "scheduler_test.rs"]
mod scheduler_test;

#[cfg(test)]
#[path = "stealth_config_test.rs"]
mod stealth_config_test;

#[cfg(test)]
#[path = "streaming_fuzzer_test.rs"]
mod streaming_fuzzer_test;

#[cfg(test)]
#[path = "subdomain_takeover_test.rs"]
mod subdomain_takeover_test;

#[cfg(test)]
#[path = "waf_fingerprinter_test.rs"]
mod waf_fingerprinter_test;

#[cfg(test)]
#[path = "xxe_engine_test.rs"]
mod xxe_engine_test;

#[cfg(test)]
#[path = "payload_scorer_test.rs"]
mod payload_scorer_test;

#[cfg(test)]
#[path = "input_validation_bypass_test.rs"]
mod input_validation_bypass_test;

#[cfg(test)]
#[path = "redos_engine_test.rs"]
mod redos_engine_test;

#[cfg(test)]
#[path = "sqli_second_order_test.rs"]
mod sqli_second_order_test;

#[cfg(test)]
#[path = "websocket_binary_fuzzer_test.rs"]
mod websocket_binary_fuzzer_test;

#[cfg(test)]
#[path = "cloud_detector_test.rs"]
mod cloud_detector_test;

#[cfg(test)]
#[path = "smuggling_detector_test.rs"]
mod smuggling_detector_test;
