#![allow(ambiguous_glob_reexports)]

pub mod attack_narrative;
pub mod certificate_serializer;
pub mod evidence_packager;
pub mod executive_report;
pub mod narrative;
pub mod narrative_gen;
pub mod report_format;
pub mod risk_scorer;
pub mod sarif_emitter;
pub mod scan_comparison;
pub mod scan_metrics;

pub use attack_narrative::*;
pub use certificate_serializer::*;
pub use evidence_packager::*;
pub use executive_report::*;
pub use narrative::*;
pub use narrative_gen::*;
pub use report_format::*;
pub use risk_scorer::*;
pub use sarif_emitter::*;
pub use scan_comparison::*;
pub use scan_metrics::*;

pub mod html_report;
pub mod remediation_guide;
pub mod risk_dashboard;
pub mod summary_card;

pub use html_report::*;
pub use remediation_guide::*;
pub use risk_dashboard::*;
pub use summary_card::*;

#[cfg(test)]
#[path = "html_report_test.rs"]
mod html_report_test;

#[cfg(test)]
#[path = "remediation_guide_test.rs"]
mod remediation_guide_test;

#[cfg(test)]
#[path = "risk_dashboard_test.rs"]
mod risk_dashboard_test;

#[cfg(test)]
#[path = "summary_card_test.rs"]
mod summary_card_test;

#[cfg(test)]
#[path = "attack_narrative_test.rs"]
mod attack_narrative_test;

#[cfg(test)]
#[path = "report_format_test.rs"]
mod report_format_test;

#[cfg(test)]
#[path = "narrative_test.rs"]
mod narrative_test;

#[cfg(test)]
#[path = "risk_scorer_test.rs"]
mod risk_scorer_test;

#[cfg(test)]
#[path = "sarif_emitter_test.rs"]
mod sarif_emitter_test;

#[cfg(test)]
#[path = "certificate_serializer_test.rs"]
mod certificate_serializer_test;

#[cfg(test)]
#[path = "narrative_gen_test.rs"]
mod narrative_gen_test;

#[cfg(test)]
#[path = "evidence_packager_test.rs"]
mod evidence_packager_test;

#[cfg(test)]
#[path = "executive_report_test.rs"]
mod executive_report_test;

#[cfg(test)]
#[path = "scan_metrics_test.rs"]
mod scan_metrics_test;

#[cfg(test)]
#[path = "scan_comparison_test.rs"]
mod scan_comparison_test;
