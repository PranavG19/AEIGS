pub mod audit;
pub mod capability;
pub mod defense_context;
pub mod edge;
pub mod finding;
pub mod ipc;
pub mod node;
pub mod operation;
pub mod request;
pub mod scan_event;
pub mod scope_attestation;
pub mod target_validation;

#[cfg(test)]
#[path = "protocol_test.rs"]
mod protocol_test;

#[cfg(test)]
#[path = "finding_test.rs"]
mod finding_test;

#[cfg(test)]
#[path = "scan_event_test.rs"]
mod scan_event_test;
