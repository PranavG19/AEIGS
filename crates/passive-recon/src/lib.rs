pub mod dep_confusion;
pub mod dependency_parser;
pub mod filesystem_walker;
pub mod supply_chain_monitor;
pub mod tls_scanner;
pub mod vuln_database;

pub use dep_confusion::*;
pub use dependency_parser::*;
pub use filesystem_walker::*;
pub use supply_chain_monitor::*;
pub use tls_scanner::*;
pub use vuln_database::*;

#[cfg(test)]
#[path = "dependency_parser_test.rs"]
mod dependency_parser_test;

#[cfg(test)]
#[path = "vuln_database_test.rs"]
mod vuln_database_test;

#[cfg(test)]
#[path = "filesystem_walker_test.rs"]
mod filesystem_walker_test;

#[cfg(test)]
#[path = "dep_confusion_test.rs"]
mod dep_confusion_test;

#[cfg(test)]
#[path = "supply_chain_monitor_test.rs"]
mod supply_chain_monitor_test;

#[cfg(test)]
#[path = "tls_scanner_test.rs"]
mod tls_scanner_test;
