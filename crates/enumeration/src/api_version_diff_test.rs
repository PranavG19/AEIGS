#[cfg(test)]
mod tests {
    use crate::api_version_diff::{
        ApiVersionDiffer, ApiVersionSpec, FieldChangeType, SecurityImpact,
    };
    use serde_json::json;

    fn v1_spec() -> ApiVersionSpec {
        ApiVersionSpec {
            version: "v1".to_string(),
            spec: json!({
                "openapi": "3.0.0",
                "info": { "title": "API", "version": "1.0" },
                "security": [{ "bearerAuth": [] }],
                "paths": {
                    "/users": {
                        "get": {
                            "parameters": [
                                { "name": "page", "in": "query" },
                                { "name": "limit", "in": "query" }
                            ],
                            "responses": {
                                "200": {
                                    "description": "ok",
                                    "headers": {
                                        "X-RateLimit-Limit": { "schema": { "type": "integer" } }
                                    },
                                    "content": {
                                        "application/json": {
                                            "schema": {
                                                "type": "object",
                                                "properties": {
                                                    "id": { "type": "integer" },
                                                    "name": { "type": "string" },
                                                    "email": { "type": "string" }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "post": {
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "name": { "type": "string", "maxLength": 255 },
                                                "email": { "type": "string", "format": "email" }
                                            }
                                        }
                                    }
                                }
                            },
                            "responses": { "201": { "description": "created" } }
                        }
                    },
                    "/legacy": {
                        "get": {
                            "responses": { "200": { "description": "ok" } }
                        }
                    }
                }
            }),
        }
    }

    fn v2_spec() -> ApiVersionSpec {
        ApiVersionSpec {
            version: "v2".to_string(),
            spec: json!({
                "openapi": "3.0.0",
                "info": { "title": "API", "version": "2.0" },
                "security": [{ "bearerAuth": [] }],
                "paths": {
                    "/users": {
                        "get": {
                            "parameters": [
                                { "name": "page", "in": "query" },
                                { "name": "limit", "in": "query" },
                                { "name": "sort", "in": "query" }
                            ],
                            "responses": {
                                "200": {
                                    "description": "ok",
                                    "content": {
                                        "application/json": {
                                            "schema": {
                                                "type": "object",
                                                "properties": {
                                                    "id": { "type": "integer" },
                                                    "name": { "type": "string" },
                                                    "email": { "type": "string" },
                                                    "phone": { "type": "string" },
                                                    "salary": { "type": "number" }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "post": {
                            "security": [],
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "name": { "type": "string" },
                                                "email": { "type": "string", "format": "email" },
                                                "role": { "type": "integer" }
                                            }
                                        }
                                    }
                                }
                            },
                            "responses": { "201": { "description": "created" } }
                        }
                    },
                    "/legacy": {
                        "get": {
                            "deprecated": true,
                            "responses": { "200": { "description": "ok" } }
                        }
                    },
                    "/admin": {
                        "get": {
                            "responses": { "200": { "description": "ok" } }
                        }
                    }
                }
            }),
        }
    }

    #[test]
    fn detects_new_and_removed_endpoints() {
        let report = ApiVersionDiffer::diff(&v1_spec(), &v2_spec());

        assert!(
            report
                .endpoints_only_in_new
                .iter()
                .any(|(p, _)| p == "/admin"),
            "v2 adds /admin"
        );

        assert_eq!(report.old_version, "v1");
        assert_eq!(report.new_version, "v2");
    }

    #[test]
    fn detects_added_parameter() {
        let report = ApiVersionDiffer::diff(&v1_spec(), &v2_spec());

        let sort_added = report
            .field_diffs
            .iter()
            .find(|d| d.field_name == "sort" && d.change_type == FieldChangeType::Added);
        assert!(sort_added.is_some(), "sort parameter added in v2");
    }

    #[test]
    fn detects_added_body_field() {
        let report = ApiVersionDiffer::diff(&v1_spec(), &v2_spec());

        let role_added = report
            .field_diffs
            .iter()
            .find(|d| d.field_name == "role" && d.change_type == FieldChangeType::Added);
        assert!(role_added.is_some(), "role body field added in v2");
    }

    #[test]
    fn detects_removed_constraint() {
        let report = ApiVersionDiffer::diff(&v1_spec(), &v2_spec());

        let maxlen_removed = report.field_diffs.iter().find(|d| {
            d.field_name.contains("name")
                && d.field_name.contains("maxLength")
                && d.change_type == FieldChangeType::ConstraintRemoved
        });
        assert!(
            maxlen_removed.is_some(),
            "maxLength removed from name field in v2"
        );
        assert_eq!(
            maxlen_removed.unwrap().security_impact,
            SecurityImpact::High
        );
    }

    #[test]
    fn detects_auth_removal() {
        let report = ApiVersionDiffer::diff(&v1_spec(), &v2_spec());

        let post_auth = report
            .auth_diffs
            .iter()
            .find(|d| d.path == "/users" && d.method == "POST");
        assert!(post_auth.is_some(), "POST /users auth changed");
        let auth_diff = post_auth.unwrap();
        assert!(auth_diff.auth_removed);
        assert_eq!(auth_diff.security_impact, SecurityImpact::Critical);
    }

    #[test]
    fn detects_deprecated_endpoints() {
        let report = ApiVersionDiffer::diff(&v1_spec(), &v2_spec());

        let legacy = report
            .deprecated_endpoints
            .iter()
            .find(|d| d.path == "/legacy");
        assert!(legacy.is_some());
        assert!(legacy.unwrap().still_accessible);
        assert_eq!(legacy.unwrap().deprecated_in_version, "v2");
    }

    #[test]
    fn detects_response_field_additions_with_data_leak() {
        let report = ApiVersionDiffer::diff(&v1_spec(), &v2_spec());

        let response_diff = report
            .response_diffs
            .iter()
            .find(|d| d.path == "/users" && d.method == "GET" && d.status_code == "200");
        assert!(response_diff.is_some());
        let rd = response_diff.unwrap();
        assert!(
            rd.fields_added.contains(&"phone".to_string())
                || rd.fields_added.contains(&"salary".to_string())
        );
        assert!(
            rd.potential_data_leak,
            "phone and salary are sensitive — data leak flagged"
        );
    }

    #[test]
    fn detects_rate_limit_removal() {
        let report = ApiVersionDiffer::diff(&v1_spec(), &v2_spec());

        let rate_diff = report
            .rate_limit_diffs
            .iter()
            .find(|d| d.path == "/users" && d.method == "GET");
        assert!(rate_diff.is_some());
        let rd = rate_diff.unwrap();
        assert!(rd.old_has_rate_limit);
        assert!(!rd.new_has_rate_limit);
        assert_eq!(rd.security_impact, SecurityImpact::High);
    }

    #[test]
    fn security_regression_count() {
        let report = ApiVersionDiffer::diff(&v1_spec(), &v2_spec());
        assert!(
            report.security_regressions >= 3,
            "auth removal + constraint removal + rate limit removal + data leak = at least 3 regressions, got {}",
            report.security_regressions
        );
    }

    #[test]
    fn identical_specs_produce_empty_diff() {
        let spec = v1_spec();
        let report = ApiVersionDiffer::diff(&spec, &spec);

        assert!(report.field_diffs.is_empty());
        assert!(report.auth_diffs.is_empty());
        assert!(report.response_diffs.is_empty());
        assert!(report.rate_limit_diffs.is_empty());
        assert!(report.endpoints_only_in_old.is_empty());
        assert!(report.endpoints_only_in_new.is_empty());
        assert_eq!(report.security_regressions, 0);
        assert_eq!(report.security_improvements, 0);
    }

    #[test]
    fn empty_specs_produce_empty_diff() {
        let empty_v1 = ApiVersionSpec {
            version: "v1".to_string(),
            spec: json!({ "openapi": "3.0.0", "paths": {} }),
        };
        let empty_v2 = ApiVersionSpec {
            version: "v2".to_string(),
            spec: json!({ "openapi": "3.0.0", "paths": {} }),
        };
        let report = ApiVersionDiffer::diff(&empty_v1, &empty_v2);
        assert_eq!(report.security_regressions, 0);
    }

    #[test]
    fn security_improvements_counted() {
        let old = ApiVersionSpec {
            version: "v1".to_string(),
            spec: json!({
                "openapi": "3.0.0",
                "paths": {
                    "/data": {
                        "get": {
                            "security": [],
                            "responses": { "200": { "description": "ok" } }
                        }
                    }
                }
            }),
        };
        let new = ApiVersionSpec {
            version: "v2".to_string(),
            spec: json!({
                "openapi": "3.0.0",
                "paths": {
                    "/data": {
                        "get": {
                            "security": [{ "bearerAuth": [] }],
                            "responses": { "200": { "description": "ok" } }
                        }
                    }
                }
            }),
        };
        let report = ApiVersionDiffer::diff(&old, &new);

        let auth_added = report.auth_diffs.iter().find(|d| d.auth_added);
        assert!(auth_added.is_some());
        assert!(report.security_improvements >= 1);
    }
}
