#![allow(ambiguous_glob_reexports)]

pub mod attack_graph;
pub mod business_logic_tester;
pub mod cors_credential_chain;
pub mod dns_exfiltration;
pub mod graph_export;
pub mod graph_visualizer;
pub mod idor_patterns;
pub mod network_pivot;
pub mod path_analysis;
pub mod privilege_escalation;
pub mod probabilistic_chains;
pub mod redirect_chain_builder;
pub mod ssrf_cloud_pivot;

pub use attack_graph::*;
pub use business_logic_tester::*;
pub use cors_credential_chain::*;
pub use dns_exfiltration::*;
pub use graph_export::*;
pub use graph_visualizer::*;
pub use idor_patterns::*;
pub use network_pivot::*;
pub use path_analysis::*;
pub use privilege_escalation::*;
pub use probabilistic_chains::*;
pub use redirect_chain_builder::*;
pub use ssrf_cloud_pivot::*;

pub mod attack_tree;
pub mod credential_harvest;
pub mod db_exfil_planner;
pub mod defense_effectiveness;
pub mod file_exfil_planner;
pub mod impact_propagation;
pub mod kill_chain_mapper;
pub mod oob_exfil;
pub mod remediation_prioritizer;
pub mod side_channel_extract;

pub use attack_tree::*;
pub use credential_harvest::*;
pub use db_exfil_planner::*;
pub use defense_effectiveness::*;
pub use file_exfil_planner::*;
pub use impact_propagation::*;
pub use kill_chain_mapper::*;
pub use oob_exfil::*;
pub use remediation_prioritizer::*;
pub use side_channel_extract::*;

#[cfg(test)]
#[path = "attack_tree_test.rs"]
mod attack_tree_test;

#[cfg(test)]
#[path = "credential_harvest_test.rs"]
mod credential_harvest_test;

#[cfg(test)]
#[path = "db_exfil_planner_test.rs"]
mod db_exfil_planner_test;

#[cfg(test)]
#[path = "defense_effectiveness_test.rs"]
mod defense_effectiveness_test;

#[cfg(test)]
#[path = "file_exfil_planner_test.rs"]
mod file_exfil_planner_test;

#[cfg(test)]
#[path = "impact_propagation_test.rs"]
mod impact_propagation_test;

#[cfg(test)]
#[path = "kill_chain_mapper_test.rs"]
mod kill_chain_mapper_test;

#[cfg(test)]
#[path = "oob_exfil_test.rs"]
mod oob_exfil_test;

#[cfg(test)]
#[path = "remediation_prioritizer_test.rs"]
mod remediation_prioritizer_test;

#[cfg(test)]
#[path = "side_channel_extract_test.rs"]
mod side_channel_extract_test;

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
