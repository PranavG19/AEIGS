pub mod auth_flow;
pub mod auth_matrix;
pub mod graphql_discovery;
pub mod introspection;
pub mod route_parser;

#[cfg(test)]
#[path = "auth_flow_test.rs"]
mod auth_flow_test;

#[cfg(test)]
#[path = "route_parser_test.rs"]
mod route_parser_test;

#[cfg(test)]
#[path = "introspection_test.rs"]
mod introspection_test;

#[cfg(test)]
#[path = "auth_matrix_test.rs"]
mod auth_matrix_test;

#[cfg(test)]
#[path = "graphql_discovery_test.rs"]
mod graphql_discovery_test;
