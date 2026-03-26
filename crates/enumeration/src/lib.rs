#![allow(ambiguous_glob_reexports)]

pub mod api_auth_tester;
pub mod api_doc_discovery;
pub mod api_version_attack;
pub mod api_version_diff;
pub mod auth_flow;
pub mod auth_matrix;
pub mod graphql_attack_engine;
pub mod graphql_discovery;
pub mod graphql_field_auth;
pub mod graphql_mutation_abuse;
pub mod graphql_persisted_queries;
pub mod graphql_subscription_abuse;
pub mod grpc_security;
pub mod introspection;
pub mod oauth_attack_engine;
pub mod oauth_leakage_detector;
pub mod openapi_security;
pub mod rest_abuse_patterns;
pub mod route_parser;
pub mod session_exploitation;

pub use api_auth_tester::*;
pub use api_doc_discovery::*;
pub use api_version_attack::*;
pub use api_version_diff::*;
pub use auth_flow::*;
pub use auth_matrix::*;
pub use graphql_attack_engine::*;
pub use graphql_discovery::*;
pub use graphql_field_auth::*;
pub use graphql_mutation_abuse::*;
pub use graphql_persisted_queries::*;
pub use graphql_subscription_abuse::*;
pub use grpc_security::*;
pub use introspection::*;
pub use oauth_attack_engine::*;
pub use oauth_leakage_detector::*;
pub use openapi_security::*;
pub use rest_abuse_patterns::*;
pub use route_parser::*;
pub use session_exploitation::*;

pub mod content_negotiation;
pub mod gateway_bypass;
pub mod graphql_reconstructor;
pub mod grpc_exploiter;
pub mod mobile_api_tester;
pub mod signing_bypass;
pub mod webhook_tester;

pub use content_negotiation::*;
pub use gateway_bypass::*;
pub use graphql_reconstructor::*;
pub use grpc_exploiter::*;
pub use mobile_api_tester::*;
pub use signing_bypass::*;
pub use webhook_tester::*;

pub mod api_schema_drift_v2;
pub mod csrf_entropy_v2;
pub mod graphql_bypass_v3;
pub use api_schema_drift_v2::*;
pub use csrf_entropy_v2::*;
pub use graphql_bypass_v3::*;

#[cfg(test)]
#[path = "api_schema_drift_v2_test.rs"]
mod api_schema_drift_v2_test;

#[cfg(test)]
#[path = "csrf_entropy_v2_test.rs"]
mod csrf_entropy_v2_test;

#[cfg(test)]
#[path = "graphql_bypass_v3_test.rs"]
mod graphql_bypass_v3_test;

#[cfg(test)]
#[path = "content_negotiation_test.rs"]
mod content_negotiation_test;

#[cfg(test)]
#[path = "gateway_bypass_test.rs"]
mod gateway_bypass_test;

#[cfg(test)]
#[path = "mobile_api_tester_test.rs"]
mod mobile_api_tester_test;

#[cfg(test)]
#[path = "signing_bypass_test.rs"]
mod signing_bypass_test;

#[cfg(test)]
#[path = "webhook_tester_test.rs"]
mod webhook_tester_test;

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
#[path = "oauth_leakage_detector_test.rs"]
mod oauth_leakage_detector_test;

#[cfg(test)]
#[path = "session_exploitation_test.rs"]
mod session_exploitation_test;

#[cfg(test)]
#[path = "openapi_security_test.rs"]
mod openapi_security_test;

#[cfg(test)]
#[path = "grpc_security_test.rs"]
mod grpc_security_test;

#[cfg(test)]
#[path = "rest_abuse_patterns_test.rs"]
mod rest_abuse_patterns_test;

#[cfg(test)]
#[path = "api_auth_tester_test.rs"]
mod api_auth_tester_test;

#[cfg(test)]
#[path = "api_doc_discovery_test.rs"]
mod api_doc_discovery_test;

#[cfg(test)]
#[path = "api_version_diff_test.rs"]
mod api_version_diff_test;

#[cfg(test)]
#[path = "graphql_field_auth_test.rs"]
mod graphql_field_auth_test;

#[cfg(test)]
#[path = "graphql_persisted_queries_test.rs"]
mod graphql_persisted_queries_test;

#[cfg(test)]
#[path = "grpc_exploiter_test.rs"]
mod grpc_exploiter_test;

#[cfg(test)]
#[path = "graphql_reconstructor_test.rs"]
mod graphql_reconstructor_test;
