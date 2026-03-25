#![allow(ambiguous_glob_reexports)]

pub mod attack_graph;
pub mod business_logic_tester;
pub mod graph_export;
pub mod graph_visualizer;
pub mod network_pivot;
pub mod path_analysis;
pub mod probabilistic_chains;
pub mod redirect_chain_builder;
pub mod ssrf_cloud_pivot;
pub mod cors_credential_chain;
pub mod dns_exfiltration;
pub mod idor_patterns;
pub mod privilege_escalation;

pub use attack_graph::*;
pub use business_logic_tester::*;
pub use graph_export::*;
pub use graph_visualizer::*;
pub use network_pivot::*;
pub use path_analysis::*;
pub use probabilistic_chains::*;
pub use redirect_chain_builder::*;
pub use ssrf_cloud_pivot::*;
pub use cors_credential_chain::*;
pub use dns_exfiltration::*;
pub use idor_patterns::*;
pub use privilege_escalation::*;

#[cfg(test)]
#[path = "attack_graph_test.rs"]
mod attack_graph_test;

#[cfg(test)]
#[path = "business_logic_tester_test.rs"]
mod business_logic_tester_test;

#[cfg(test)]
#[path = "graph_export_test.rs"]
mod graph_export_test;

#[cfg(test)]
#[path = "path_analysis_test.rs"]
mod path_analysis_test;

#[cfg(test)]
#[path = "probabilistic_chains_test.rs"]
mod probabilistic_chains_test;

#[cfg(test)]
#[path = "network_pivot_test.rs"]
mod network_pivot_test;

#[cfg(test)]
#[path = "redirect_chain_builder_test.rs"]
mod redirect_chain_builder_test;

#[cfg(test)]
#[path = "ssrf_cloud_pivot_test.rs"]
mod ssrf_cloud_pivot_test;

#[cfg(test)]
#[path = "graph_visualizer_test.rs"]
mod graph_visualizer_test;

#[cfg(test)]
#[path = "cors_credential_chain_test.rs"]
mod cors_credential_chain_test;

#[cfg(test)]
#[path = "dns_exfiltration_test.rs"]
mod dns_exfiltration_test;

#[cfg(test)]
#[path = "idor_patterns_test.rs"]
mod idor_patterns_test;

#[cfg(test)]
#[path = "privilege_escalation_test.rs"]
mod privilege_escalation_test;
