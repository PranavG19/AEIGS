pub mod api_version_attack;
pub mod auth_flow;
pub mod auth_matrix;
pub mod graphql_attack_engine;
pub mod graphql_discovery;
pub mod graphql_subscription_abuse;
pub mod introspection;
pub mod oauth_attack_engine;
pub mod route_parser;
pub mod session_exploitation;

pub use api_version_attack::*;
pub use auth_flow::*;
pub use auth_matrix::*;
pub use graphql_attack_engine::*;
pub use graphql_discovery::*;
pub use graphql_subscription_abuse::*;
pub use introspection::*;
pub use oauth_attack_engine::*;
pub use route_parser::*;
pub use session_exploitation::*;

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

#[cfg(test)]
#[path = "api_version_attack_test.rs"]
mod api_version_attack_test;

#[cfg(test)]
#[path = "graphql_attack_engine_test.rs"]
mod graphql_attack_engine_test;

#[cfg(test)]
#[path = "graphql_subscription_abuse_test.rs"]
mod graphql_subscription_abuse_test;

#[cfg(test)]
#[path = "oauth_attack_engine_test.rs"]
mod oauth_attack_engine_test;

#[cfg(test)]
#[path = "session_exploitation_test.rs"]
mod session_exploitation_test;
