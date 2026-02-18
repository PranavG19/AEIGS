pub mod dependency_parser;
pub mod vuln_database;

#[cfg(test)]
#[path = "dependency_parser_test.rs"]
mod dependency_parser_test;

#[cfg(test)]
#[path = "vuln_database_test.rs"]
mod vuln_database_test;
