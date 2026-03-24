pub mod attack_surface_mapper;
pub mod class_mapper;
pub mod compliance_mapper;
pub mod context_adjuster;
pub mod cvss_scorer;
pub mod report_generator;
pub mod security_header_analyzer;

pub use attack_surface_mapper::*;
pub use class_mapper::*;
pub use compliance_mapper::*;
pub use context_adjuster::*;
pub use cvss_scorer::*;
pub use report_generator::*;
pub use security_header_analyzer::*;

#[cfg(test)]
#[path = "attack_surface_mapper_test.rs"]
mod attack_surface_mapper_test;

#[cfg(test)]
#[path = "cvss_scorer_test.rs"]
mod cvss_scorer_test;

#[cfg(test)]
#[path = "class_mapper_test.rs"]
mod class_mapper_test;

#[cfg(test)]
#[path = "context_adjuster_test.rs"]
mod context_adjuster_test;

#[cfg(test)]
#[path = "compliance_mapper_test.rs"]
mod compliance_mapper_test;

#[cfg(test)]
#[path = "report_generator_test.rs"]
mod report_generator_test;

#[cfg(test)]
#[path = "security_header_analyzer_test.rs"]
mod security_header_analyzer_test;
