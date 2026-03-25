#[cfg(test)]
mod tests {
    use crate::openapi_security::{AuthSchemeType, AuthStrength, OpenApiSecurityAnalyzer};
    use serde_json::json;

    fn minimal_spec_with_security() -> serde_json::Value {
        json!({
            "openapi": "3.0.0",
            "info": { "title": "Test API", "version": "1.0" },
            "components": {
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                        "bearerFormat": "JWT"
                    },
                    "apiKeyQuery": {
                        "type": "apiKey",
                        "in": "query",
                        "name": "api_key"
                    },
                    "basicAuth": {
                        "type": "http",
                        "scheme": "basic"
                    },
                    "oauthFlow": {
                        "type": "oauth2",
                        "flows": {
                            "implicit": {
                                "authorizationUrl": "https://example.com/oauth",
                                "scopes": {}
                            }
                        }
                    }
                }
            },
            "security": [{ "bearerAuth": [] }],
            "paths": {
                "/users": {
                    "get": {
                        "responses": {
                            "200": {
                                "description": "user list",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "array",
                                            "items": {
                                                "type": "object",
                                                "properties": {
                                                    "id": { "type": "integer" },
                                                    "email": { "type": "string" },
                                                    "password_hash": { "type": "string" },
                                                    "ssn": { "type": "string" }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "parameters": [
                            {
                                "name": "search",
                                "in": "query",
                                "schema": { "type": "string" }
                            },
                            {
                                "name": "limit",
                                "in": "query",
                                "schema": {
                                    "type": "integer",
                                    "minimum": 1,
                                    "maximum": 100
                                }
                            }
                        ]
                    },
                    "post": {
                        "security": [],
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "name": { "type": "string", "maxLength": 255 },
                                            "role": { "type": "string" }
                                        }
                                    }
                                }
                            }
                        },
                        "responses": { "201": { "description": "created" } }
                    }
                },
                "/health": {
                    "get": {
                        "security": [],
                        "responses": { "200": { "description": "ok" } }
                    }
                },
                "/admin/settings": {
                    "put": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "setting": { "type": "string" }
                                        },
                                        "additionalProperties": false
                                    }
                                }
                            }
                        },
                        "responses": {
                            "200": {
                                "description": "ok",
                                "headers": {
                                    "X-RateLimit-Limit": {
                                        "schema": { "type": "integer" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        })
    }

    #[test]
    fn analyze_auth_schemes_detects_all_types() {
        let spec = minimal_spec_with_security();
        let analyzer = OpenApiSecurityAnalyzer::new(spec);
        let assessments = analyzer.analyze_auth_schemes();

        assert_eq!(assessments.len(), 4);

        let bearer = assessments.iter().find(|a| a.name == "bearerAuth").unwrap();
        assert_eq!(bearer.scheme_type, AuthSchemeType::Http);
        assert_eq!(bearer.strength, AuthStrength::Strong);

        let api_key = assessments
            .iter()
            .find(|a| a.name == "apiKeyQuery")
            .unwrap();
        assert_eq!(api_key.scheme_type, AuthSchemeType::ApiKey);
        assert_eq!(api_key.strength, AuthStrength::Weak);
        assert!(api_key.issues.iter().any(|i| i.contains("query string")));

        let basic = assessments.iter().find(|a| a.name == "basicAuth").unwrap();
        assert_eq!(basic.scheme_type, AuthSchemeType::Http);
        assert_eq!(basic.strength, AuthStrength::Weak);
        assert!(basic.issues.iter().any(|i| i.contains("base64")));

        let oauth = assessments.iter().find(|a| a.name == "oauthFlow").unwrap();
        assert_eq!(oauth.scheme_type, AuthSchemeType::OAuth2);
        assert!(oauth.issues.iter().any(|i| i.contains("Implicit flow")));
    }

    #[test]
    fn detect_unauthenticated_endpoints() {
        let spec = minimal_spec_with_security();
        let analyzer = OpenApiSecurityAnalyzer::new(spec);
        let report = analyzer.analyze();

        let unauth_paths: Vec<&str> = report
            .unauthenticated_endpoints
            .iter()
            .map(|e| e.path.as_str())
            .collect();

        assert!(unauth_paths.contains(&"/health"));
        assert!(unauth_paths.contains(&"/users"));

        let users_post = report
            .unauthenticated_endpoints
            .iter()
            .find(|e| e.path == "/users" && e.method == "POST")
            .unwrap();
        assert!(!users_post.has_auth);
    }

    #[test]
    fn authenticated_endpoint_has_schemes() {
        let spec = minimal_spec_with_security();
        let analyzer = OpenApiSecurityAnalyzer::new(spec);
        let coverage = analyzer.analyze_endpoint_auth_coverage();

        let users_get = coverage
            .iter()
            .find(|e| e.path == "/users" && e.method == "GET")
            .unwrap();
        assert!(users_get.has_auth);
        assert!(users_get.auth_schemes.contains(&"bearerAuth".to_string()));
    }

    #[test]
    fn detect_parameter_validation_issues() {
        let spec = minimal_spec_with_security();
        let analyzer = OpenApiSecurityAnalyzer::new(spec);
        let issues = analyzer.analyze_parameter_validation();

        let search_issue = issues
            .iter()
            .find(|i| i.parameter_name == "search")
            .unwrap();
        assert!(
            search_issue
                .missing_constraints
                .iter()
                .any(|c| c.contains("maxLength"))
        );

        let limit_issues = issues
            .iter()
            .filter(|i| i.parameter_name == "limit")
            .count();
        assert_eq!(limit_issues, 0, "limit param has min/max so no issues");
    }

    #[test]
    fn detect_sensitive_data_in_responses() {
        let spec = minimal_spec_with_security();
        let analyzer = OpenApiSecurityAnalyzer::new(spec);
        let exposures = analyzer.analyze_sensitive_data_exposure();

        assert!(!exposures.is_empty());
        let users_exposure = exposures.iter().find(|e| e.path == "/users").unwrap();
        assert!(
            users_exposure
                .sensitive_fields
                .iter()
                .any(|f| f.contains("email"))
        );
        assert!(
            users_exposure
                .sensitive_fields
                .iter()
                .any(|f| f.contains("password"))
        );
        assert!(
            users_exposure
                .sensitive_fields
                .iter()
                .any(|f| f.contains("ssn"))
        );
        assert_eq!(users_exposure.field_category, "credentials");
    }

    #[test]
    fn detect_schema_bypass_risks() {
        let spec = minimal_spec_with_security();
        let analyzer = OpenApiSecurityAnalyzer::new(spec);
        let risks = analyzer.analyze_schema_bypass();

        let users_post_risk = risks
            .iter()
            .find(|r| r.path == "/users" && r.method == "POST");
        assert!(
            users_post_risk.is_some(),
            "POST /users allows additionalProperties by default"
        );

        let admin_put_risk = risks
            .iter()
            .find(|r| r.path == "/admin/settings" && r.method == "PUT");
        assert!(
            admin_put_risk.is_none(),
            "PUT /admin/settings explicitly disallows additionalProperties"
        );
    }

    #[test]
    fn detect_rate_limit_gaps() {
        let spec = minimal_spec_with_security();
        let analyzer = OpenApiSecurityAnalyzer::new(spec);
        let gaps = analyzer.analyze_rate_limit_gaps();

        let users_gap = gaps
            .iter()
            .find(|g| g.path == "/users" && g.method == "GET");
        assert!(users_gap.is_some(), "/users GET has no rate limit");

        let admin_gap = gaps
            .iter()
            .find(|g| g.path == "/admin/settings" && g.method == "PUT");
        assert!(
            admin_gap.is_none(),
            "/admin/settings has X-RateLimit-Limit header"
        );
    }

    #[test]
    fn full_report_summary_counts() {
        let spec = minimal_spec_with_security();
        let analyzer = OpenApiSecurityAnalyzer::new(spec);
        let report = analyzer.analyze();

        assert!(report.total_endpoints > 0);
        assert!(report.endpoints_without_auth > 0);
        assert!(report.endpoints_without_auth <= report.total_endpoints);
    }

    #[test]
    fn empty_spec_produces_empty_report() {
        let spec = json!({ "openapi": "3.0.0", "info": { "title": "Empty", "version": "1.0" }, "paths": {} });
        let analyzer = OpenApiSecurityAnalyzer::new(spec);
        let report = analyzer.analyze();

        assert_eq!(report.total_endpoints, 0);
        assert!(report.auth_assessments.is_empty());
        assert!(report.unauthenticated_endpoints.is_empty());
    }

    #[test]
    fn openid_connect_rated_strong() {
        let spec = json!({
            "openapi": "3.0.0",
            "info": { "title": "T", "version": "1.0" },
            "components": {
                "securitySchemes": {
                    "oidc": {
                        "type": "openIdConnect",
                        "openIdConnectUrl": "https://example.com/.well-known/openid-configuration"
                    }
                }
            },
            "paths": {}
        });
        let analyzer = OpenApiSecurityAnalyzer::new(spec);
        let assessments = analyzer.analyze_auth_schemes();
        assert_eq!(assessments.len(), 1);
        assert_eq!(assessments[0].strength, AuthStrength::Strong);
    }
}
