pub mod certificate_serializer;
pub mod narrative;
pub mod narrative_gen;
pub mod report_format;
pub mod risk_scorer;
pub mod sarif_emitter;

pub use certificate_serializer::*;
pub use narrative::*;
pub use narrative_gen::*;
pub use report_format::*;
pub use risk_scorer::*;
pub use sarif_emitter::*;

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
