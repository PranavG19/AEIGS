#[cfg(test)]
mod tests {
    use crate::introspection::{
        parse_graphql_introspection, parse_openapi_json, IntrospectionError, ParameterLocation,
    };

    #[test]
    fn parse_openapi_basic_spec() {
        let spec = r#"{
            "openapi": "3.0.0",
            "paths": {
                "/users": {
                    "get": {
                        "summary": "List users",
                        "parameters": [
                            {
                                "name": "limit",
                                "in": "query",
                                "required": false,
                                "schema": { "type": "integer" }
                            }
                        ]
                    },
                    "post": {
                        "summary": "Create user",
                        "parameters": []
                    }
                }
            }
        }"#;

        let endpoints = parse_openapi_json(spec).unwrap();
        assert_eq!(endpoints.len(), 2);

        let get_endpoint = endpoints.iter().find(|e| e.method == "GET").unwrap();
        assert_eq!(get_endpoint.path, "/users");
        assert_eq!(get_endpoint.parameters.len(), 1);
        assert_eq!(get_endpoint.parameters[0].name, "limit");
        assert_eq!(get_endpoint.parameters[0].location, ParameterLocation::Query);
        assert_eq!(get_endpoint.parameters[0].param_type, "integer");
        assert!(!get_endpoint.parameters[0].required);
        assert_eq!(
            get_endpoint.description,
            Some("List users".to_string())
        );
    }

    #[test]
    fn parse_openapi_with_path_parameters() {
        let spec = r#"{
            "paths": {
                "/users/{id}": {
                    "get": {
                        "parameters": [
                            {
                                "name": "id",
                                "in": "path",
                                "required": true,
                                "schema": { "type": "integer" }
                            }
                        ]
                    }
                }
            }
        }"#;

        let endpoints = parse_openapi_json(spec).unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].parameters[0].location, ParameterLocation::Path);
        assert!(endpoints[0].parameters[0].required);
    }

    #[test]
    fn parse_openapi_empty_paths() {
        let spec = r#"{ "paths": {} }"#;
        let endpoints = parse_openapi_json(spec).unwrap();
        assert!(endpoints.is_empty());
    }

    #[test]
    fn parse_openapi_invalid_json() {
        let result = parse_openapi_json("not json{{{");
        assert!(matches!(result, Err(IntrospectionError::JsonParseError(_))));
    }

    #[test]
    fn parse_graphql_queries() {
        let response = r#"{
            "data": {
                "__schema": {
                    "queryType": {
                        "fields": [
                            { "name": "users", "args": [{ "name": "limit" }] },
                            { "name": "user", "args": [{ "name": "id" }] }
                        ]
                    },
                    "mutationType": null
                }
            }
        }"#;

        let endpoints = parse_graphql_introspection(response).unwrap();
        assert_eq!(endpoints.len(), 2);
        assert!(endpoints[0].path.contains("users"));
        assert_eq!(endpoints[0].method, "POST");
        assert_eq!(endpoints[0].parameters.len(), 1);
        assert_eq!(endpoints[0].parameters[0].name, "limit");
    }

    #[test]
    fn parse_graphql_mutations() {
        let response = r#"{
            "data": {
                "__schema": {
                    "queryType": null,
                    "mutationType": {
                        "fields": [
                            { "name": "createUser", "args": [{ "name": "input" }] }
                        ]
                    }
                }
            }
        }"#;

        let endpoints = parse_graphql_introspection(response).unwrap();
        assert_eq!(endpoints.len(), 1);
        assert!(endpoints[0].path.contains("createUser"));
        assert!(endpoints[0]
            .description
            .as_ref()
            .unwrap()
            .contains("Mutation"));
    }

    #[test]
    fn parse_graphql_missing_data_returns_error() {
        let response = r#"{ "data": null }"#;
        let result = parse_graphql_introspection(response);
        assert!(matches!(result, Err(IntrospectionError::InvalidSchema(_))));
    }

    #[test]
    fn parse_graphql_invalid_json() {
        let result = parse_graphql_introspection("bad json");
        assert!(matches!(result, Err(IntrospectionError::JsonParseError(_))));
    }

    #[test]
    fn parameter_location_display() {
        assert_eq!(ParameterLocation::Path.to_string(), "path");
        assert_eq!(ParameterLocation::Query.to_string(), "query");
        assert_eq!(ParameterLocation::Header.to_string(), "header");
        assert_eq!(ParameterLocation::Body.to_string(), "body");
    }

    #[test]
    fn error_display_is_descriptive() {
        let err = IntrospectionError::InvalidSchema("bad".to_string());
        assert!(err.to_string().contains("invalid schema"));

        let err = IntrospectionError::NetworkError("timeout".to_string());
        assert!(err.to_string().contains("network error"));
    }

    #[test]
    fn openapi_header_parameter_location() {
        let spec = r#"{
            "paths": {
                "/protected": {
                    "get": {
                        "parameters": [
                            { "name": "Authorization", "in": "header", "required": true }
                        ]
                    }
                }
            }
        }"#;

        let endpoints = parse_openapi_json(spec).unwrap();
        assert_eq!(
            endpoints[0].parameters[0].location,
            ParameterLocation::Header
        );
    }

    #[test]
    fn openapi_default_param_type_is_string() {
        let spec = r#"{
            "paths": {
                "/test": {
                    "get": {
                        "parameters": [
                            { "name": "q", "in": "query", "required": false }
                        ]
                    }
                }
            }
        }"#;

        let endpoints = parse_openapi_json(spec).unwrap();
        assert_eq!(endpoints[0].parameters[0].param_type, "string");
    }

    #[test]
    fn openapi_multiple_methods_same_path() {
        let spec = r#"{
            "paths": {
                "/items": {
                    "get": { "summary": "list" },
                    "post": { "summary": "create" },
                    "delete": { "summary": "delete all" }
                }
            }
        }"#;

        let endpoints = parse_openapi_json(spec).unwrap();
        assert_eq!(endpoints.len(), 3);
    }
}
