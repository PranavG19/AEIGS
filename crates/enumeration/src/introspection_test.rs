#[cfg(test)]
mod tests {
    use crate::introspection::{
        IntrospectionError, ParameterLocation, parse_graphql_introspection, parse_graphql_sdl,
        parse_openapi_json,
    };

    #[test]
    fn parse_openapi_basic_spec() {
        let spec = r#"{
            "openapi": "3.0.0",
            "info": { "title": "Test", "version": "1.0" },
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
                        ],
                        "responses": {
                            "200": { "description": "ok" }
                        }
                    },
                    "post": {
                        "summary": "Create user",
                        "parameters": [],
                        "responses": {
                            "201": { "description": "created" }
                        }
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
        assert_eq!(
            get_endpoint.parameters[0].location,
            ParameterLocation::Query
        );
        assert_eq!(get_endpoint.parameters[0].param_type, "integer");
        assert!(!get_endpoint.parameters[0].required);
        assert_eq!(get_endpoint.description, Some("List users".to_string()));
    }

    #[test]
    fn parse_openapi_with_path_parameters() {
        let spec = r#"{
            "openapi": "3.0.0",
            "info": { "title": "Test", "version": "1.0" },
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
                        ],
                        "responses": {
                            "200": { "description": "ok" }
                        }
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
        let spec = r#"{
            "openapi": "3.0.0",
            "info": { "title": "Test", "version": "1.0" },
            "paths": {}
        }"#;
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
                    "queryType": { "name": "Query" },
                    "mutationType": null,
                    "subscriptionType": null,
                    "types": [
                        {
                            "name": "Query",
                            "kind": "OBJECT",
                            "fields": [
                                {
                                    "name": "users",
                                    "args": [
                                        { "name": "limit", "type": { "kind": "SCALAR", "name": "Int", "ofType": null } }
                                    ],
                                    "type": { "kind": "LIST", "name": null, "ofType": { "kind": "OBJECT", "name": "User", "ofType": null } }
                                },
                                {
                                    "name": "user",
                                    "args": [
                                        { "name": "id", "type": { "kind": "NON_NULL", "name": null, "ofType": { "kind": "SCALAR", "name": "ID", "ofType": null } } }
                                    ],
                                    "type": { "kind": "OBJECT", "name": "User", "ofType": null }
                                }
                            ]
                        }
                    ]
                }
            }
        }"#;

        let endpoints = parse_graphql_introspection(response).unwrap();
        assert_eq!(endpoints.len(), 2);
        assert_eq!(endpoints[0].path, "/graphql");
        assert_eq!(endpoints[0].method, "POST");
        assert_eq!(endpoints[0].parameters.len(), 1);
        assert_eq!(endpoints[0].parameters[0].name, "limit");
        assert_eq!(endpoints[0].parameters[0].param_type, "Int");
        assert!(!endpoints[0].parameters[0].required);
        assert!(endpoints[0].description.as_ref().unwrap().contains("users"));
        assert_eq!(endpoints[1].parameters[0].name, "id");
        assert_eq!(endpoints[1].parameters[0].param_type, "ID!");
        assert!(endpoints[1].parameters[0].required);
        assert_eq!(endpoints[0].response_type, Some("[User]".to_string()));
    }

    #[test]
    fn parse_graphql_mutations() {
        let response = r#"{
            "data": {
                "__schema": {
                    "queryType": null,
                    "mutationType": { "name": "Mutation" },
                    "subscriptionType": null,
                    "types": [
                        {
                            "name": "Mutation",
                            "kind": "OBJECT",
                            "fields": [
                                {
                                    "name": "createUser",
                                    "args": [
                                        { "name": "input", "type": { "kind": "NON_NULL", "name": null, "ofType": { "kind": "INPUT_OBJECT", "name": "CreateUserInput", "ofType": null } } }
                                    ],
                                    "type": { "kind": "OBJECT", "name": "User", "ofType": null }
                                }
                            ]
                        }
                    ]
                }
            }
        }"#;

        let endpoints = parse_graphql_introspection(response).unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].path, "/graphql");
        assert!(
            endpoints[0]
                .description
                .as_ref()
                .unwrap()
                .contains("Mutation")
        );
        assert_eq!(endpoints[0].parameters[0].name, "input");
        assert_eq!(endpoints[0].parameters[0].param_type, "CreateUserInput!");
        assert!(endpoints[0].parameters[0].required);
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
    fn parse_graphql_sdl_queries_and_mutations() {
        let sdl = r#"
            type Query {
                users(limit: Int): [User]
                user(id: ID!): User
            }
            type Mutation {
                createUser(input: CreateUserInput!): User
            }
            type User {
                id: ID!
                name: String
            }
            input CreateUserInput {
                name: String!
            }
        "#;

        let endpoints = parse_graphql_sdl(sdl).unwrap();
        assert_eq!(endpoints.len(), 3);

        let query_users = &endpoints[0];
        assert_eq!(query_users.path, "/graphql");
        assert_eq!(query_users.method, "POST");
        assert_eq!(query_users.parameters[0].name, "limit");
        assert_eq!(query_users.parameters[0].param_type, "Int");
        assert!(!query_users.parameters[0].required);
        assert_eq!(query_users.response_type, Some("[User]".to_string()));

        let mutation = &endpoints[2];
        assert!(mutation.description.as_ref().unwrap().contains("Mutation"));
        assert_eq!(mutation.parameters[0].param_type, "CreateUserInput!");
        assert!(mutation.parameters[0].required);
    }

    #[test]
    fn parse_graphql_sdl_subscriptions() {
        let sdl = r#"
            type Query {
                ping: String
            }
            type Subscription {
                messageAdded(channelId: ID!): Message
                userStatusChanged: UserStatus
            }
            type Message {
                id: ID!
                text: String
            }
            type UserStatus {
                userId: ID!
                online: Boolean
            }
        "#;

        let endpoints = parse_graphql_sdl(sdl).unwrap();
        let subs: Vec<_> = endpoints
            .iter()
            .filter(|e| {
                e.description
                    .as_ref()
                    .is_some_and(|d| d.contains("Subscription"))
            })
            .collect();
        assert_eq!(subs.len(), 2);
        assert!(
            subs[0]
                .description
                .as_ref()
                .unwrap()
                .contains("messageAdded")
        );
        assert_eq!(subs[0].parameters.len(), 1);
        assert_eq!(subs[0].parameters[0].name, "channelId");
        assert_eq!(subs[0].parameters[0].param_type, "ID!");
        assert!(subs[0].parameters[0].required);
    }

    #[test]
    fn parse_graphql_sdl_invalid_schema() {
        let result = parse_graphql_sdl("not a schema {{{");
        assert!(matches!(result, Err(IntrospectionError::InvalidSchema(_))));
    }

    #[test]
    fn parse_graphql_sdl_custom_root_type_names() {
        let sdl = r#"
            schema {
                query: RootQuery
                mutation: RootMutation
            }
            type RootQuery {
                version: String
            }
            type RootMutation {
                reset: Boolean
            }
        "#;

        let endpoints = parse_graphql_sdl(sdl).unwrap();
        assert_eq!(endpoints.len(), 2);
        assert!(endpoints[0].description.as_ref().unwrap().contains("Query"));
        assert!(
            endpoints[1]
                .description
                .as_ref()
                .unwrap()
                .contains("Mutation")
        );
    }

    #[test]
    fn parse_graphql_sdl_no_root_types_yields_empty() {
        let sdl = r#"
            type User {
                id: ID!
                name: String
            }
        "#;

        let endpoints = parse_graphql_sdl(sdl).unwrap();
        assert!(endpoints.is_empty());
    }

    #[test]
    fn parameter_location_display() {
        assert_eq!(ParameterLocation::Path.to_string(), "path");
        assert_eq!(ParameterLocation::Query.to_string(), "query");
        assert_eq!(ParameterLocation::Header.to_string(), "header");
        assert_eq!(ParameterLocation::Cookie.to_string(), "cookie");
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
            "openapi": "3.0.0",
            "info": { "title": "Test", "version": "1.0" },
            "paths": {
                "/protected": {
                    "get": {
                        "parameters": [
                            {
                                "name": "Authorization",
                                "in": "header",
                                "required": true,
                                "schema": { "type": "string" }
                            }
                        ],
                        "responses": {
                            "200": { "description": "ok" }
                        }
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
            "openapi": "3.0.0",
            "info": { "title": "Test", "version": "1.0" },
            "paths": {
                "/test": {
                    "get": {
                        "parameters": [
                            {
                                "name": "q",
                                "in": "query",
                                "required": false,
                                "schema": {}
                            }
                        ],
                        "responses": {
                            "200": { "description": "ok" }
                        }
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
            "openapi": "3.0.0",
            "info": { "title": "Test", "version": "1.0" },
            "paths": {
                "/items": {
                    "get": {
                        "summary": "list",
                        "responses": { "200": { "description": "ok" } }
                    },
                    "post": {
                        "summary": "create",
                        "responses": { "201": { "description": "created" } }
                    },
                    "delete": {
                        "summary": "delete all",
                        "responses": { "204": { "description": "no content" } }
                    }
                }
            }
        }"#;

        let endpoints = parse_openapi_json(spec).unwrap();
        assert_eq!(endpoints.len(), 3);
    }

    #[test]
    fn openapi_security_schemes_from_operation() {
        let spec = r#"{
            "openapi": "3.0.0",
            "info": { "title": "Test", "version": "1.0" },
            "paths": {
                "/secure": {
                    "get": {
                        "security": [{ "bearerAuth": [] }],
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        }"#;

        let endpoints = parse_openapi_json(spec).unwrap();
        assert_eq!(endpoints[0].security_schemes, vec!["bearerAuth"]);
    }

    #[test]
    fn openapi_security_schemes_from_global() {
        let spec = r#"{
            "openapi": "3.0.0",
            "info": { "title": "Test", "version": "1.0" },
            "security": [{ "apiKey": [] }],
            "paths": {
                "/data": {
                    "get": {
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        }"#;

        let endpoints = parse_openapi_json(spec).unwrap();
        assert_eq!(endpoints[0].security_schemes, vec!["apiKey"]);
    }

    #[test]
    fn openapi_operation_security_overrides_global() {
        let spec = r#"{
            "openapi": "3.0.0",
            "info": { "title": "Test", "version": "1.0" },
            "security": [{ "apiKey": [] }],
            "paths": {
                "/admin": {
                    "get": {
                        "security": [{ "oauth2": [] }],
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        }"#;

        let endpoints = parse_openapi_json(spec).unwrap();
        assert_eq!(endpoints[0].security_schemes, vec!["oauth2"]);
    }

    #[test]
    fn openapi_request_content_types() {
        let spec = r#"{
            "openapi": "3.0.0",
            "info": { "title": "Test", "version": "1.0" },
            "paths": {
                "/upload": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {},
                                "multipart/form-data": {}
                            }
                        },
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        }"#;

        let endpoints = parse_openapi_json(spec).unwrap();
        assert_eq!(endpoints[0].request_content_types.len(), 2);
        assert!(
            endpoints[0]
                .request_content_types
                .contains(&"application/json".to_string())
        );
        assert!(
            endpoints[0]
                .request_content_types
                .contains(&"multipart/form-data".to_string())
        );
    }

    #[test]
    fn openapi_response_status_codes() {
        let spec = r#"{
            "openapi": "3.0.0",
            "info": { "title": "Test", "version": "1.0" },
            "paths": {
                "/items": {
                    "post": {
                        "responses": {
                            "201": { "description": "created" },
                            "400": { "description": "bad request" },
                            "500": { "description": "server error" }
                        }
                    }
                }
            }
        }"#;

        let endpoints = parse_openapi_json(spec).unwrap();
        assert_eq!(endpoints[0].response_status_codes, vec![201, 400, 500]);
    }

    #[test]
    fn openapi_no_security_yields_empty() {
        let spec = r#"{
            "openapi": "3.0.0",
            "info": { "title": "Test", "version": "1.0" },
            "paths": {
                "/public": {
                    "get": {
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        }"#;

        let endpoints = parse_openapi_json(spec).unwrap();
        assert!(endpoints[0].security_schemes.is_empty());
        assert!(endpoints[0].request_content_types.is_empty());
    }

    #[test]
    fn openapi_missing_required_fields_returns_error() {
        let result = parse_openapi_json(r#"{ "paths": {} }"#);
        assert!(matches!(result, Err(IntrospectionError::JsonParseError(_))));
    }

    #[test]
    fn openapi_request_body_json_object_yields_body_params() {
        let spec = r#"{
            "openapi": "3.0.0",
            "info": { "title": "Test", "version": "1.0" },
            "paths": {
                "/users": {
                    "post": {
                        "summary": "Create user",
                        "requestBody": {
                            "required": true,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "username": { "type": "string" },
                                            "password": { "type": "string" }
                                        }
                                    }
                                }
                            }
                        },
                        "responses": { "201": { "description": "created" } }
                    }
                }
            }
        }"#;

        let endpoints = parse_openapi_json(spec).unwrap();
        assert_eq!(endpoints.len(), 1);

        let body_params: Vec<_> = endpoints[0]
            .parameters
            .iter()
            .filter(|p| p.location == ParameterLocation::Body)
            .collect();
        assert_eq!(body_params.len(), 2);

        let mut names: Vec<&str> = body_params.iter().map(|p| p.name.as_str()).collect();
        names.sort();
        assert_eq!(names, vec!["password", "username"]);

        for p in &body_params {
            assert!(p.required);
            assert_eq!(p.param_type, "string");
        }
    }

    #[test]
    fn openapi_no_request_body_yields_no_body_params() {
        let spec = r#"{
            "openapi": "3.0.0",
            "info": { "title": "Test", "version": "1.0" },
            "paths": {
                "/items": {
                    "get": {
                        "parameters": [
                            {
                                "name": "filter",
                                "in": "query",
                                "required": false,
                                "schema": { "type": "string" }
                            }
                        ],
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        }"#;

        let endpoints = parse_openapi_json(spec).unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].parameters.len(), 1);
        assert_eq!(
            endpoints[0].parameters[0].location,
            ParameterLocation::Query
        );
    }

    #[test]
    fn openapi_request_body_multipart_form_data_yields_body_params() {
        let spec = r#"{
            "openapi": "3.0.0",
            "info": { "title": "Test", "version": "1.0" },
            "paths": {
                "/upload": {
                    "post": {
                        "requestBody": {
                            "required": false,
                            "content": {
                                "multipart/form-data": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "file": { "type": "string" }
                                        }
                                    }
                                }
                            }
                        },
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        }"#;

        let endpoints = parse_openapi_json(spec).unwrap();
        assert_eq!(endpoints.len(), 1);

        let body_params: Vec<_> = endpoints[0]
            .parameters
            .iter()
            .filter(|p| p.location == ParameterLocation::Body)
            .collect();
        assert_eq!(body_params.len(), 1);
        assert_eq!(body_params[0].name, "file");
        assert_eq!(body_params[0].param_type, "string");
        assert!(!body_params[0].required);
    }

    #[test]
    fn openapi_request_body_form_urlencoded_yields_body_params() {
        let spec = r#"{
            "openapi": "3.0.0",
            "info": { "title": "Test", "version": "1.0" },
            "paths": {
                "/login": {
                    "post": {
                        "requestBody": {
                            "required": true,
                            "content": {
                                "application/x-www-form-urlencoded": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "username": { "type": "string" },
                                            "password": { "type": "string" }
                                        }
                                    }
                                }
                            }
                        },
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        }"#;

        let endpoints = parse_openapi_json(spec).unwrap();
        assert_eq!(endpoints.len(), 1);

        let body_params: Vec<_> = endpoints[0]
            .parameters
            .iter()
            .filter(|p| p.location == ParameterLocation::Body)
            .collect();
        assert_eq!(body_params.len(), 2);

        let mut names: Vec<&str> = body_params.iter().map(|p| p.name.as_str()).collect();
        names.sort();
        assert_eq!(names, vec!["password", "username"]);

        for p in &body_params {
            assert!(p.required);
            assert_eq!(p.param_type, "string");
        }
    }

    #[test]
    fn openapi_request_body_multiple_content_types_extracts_all() {
        let spec = r#"{
            "openapi": "3.0.0",
            "info": { "title": "Test", "version": "1.0" },
            "paths": {
                "/submit": {
                    "post": {
                        "requestBody": {
                            "required": true,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "name": { "type": "string" },
                                            "age": { "type": "integer" }
                                        }
                                    }
                                },
                                "application/x-www-form-urlencoded": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "name": { "type": "string" },
                                            "age": { "type": "integer" }
                                        }
                                    }
                                }
                            }
                        },
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        }"#;

        let endpoints = parse_openapi_json(spec).unwrap();
        assert_eq!(endpoints.len(), 1);

        let body_params: Vec<_> = endpoints[0]
            .parameters
            .iter()
            .filter(|p| p.location == ParameterLocation::Body)
            .collect();
        assert_eq!(body_params.len(), 4);

        let mut names: Vec<&str> = body_params.iter().map(|p| p.name.as_str()).collect();
        names.sort();
        assert_eq!(names, vec!["age", "age", "name", "name"]);
    }

    #[test]
    fn openapi_request_body_unsupported_content_type_yields_no_body_params() {
        let spec = r#"{
            "openapi": "3.0.0",
            "info": { "title": "Test", "version": "1.0" },
            "paths": {
                "/raw": {
                    "post": {
                        "requestBody": {
                            "required": false,
                            "content": {
                                "application/octet-stream": {
                                    "schema": {
                                        "type": "string"
                                    }
                                }
                            }
                        },
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        }"#;

        let endpoints = parse_openapi_json(spec).unwrap();
        assert_eq!(endpoints.len(), 1);
        assert!(
            endpoints[0]
                .parameters
                .iter()
                .all(|p| p.location != ParameterLocation::Body)
        );
    }

    #[test]
    fn openapi_request_body_non_object_schema_yields_no_body_params() {
        let spec = r#"{
            "openapi": "3.0.0",
            "info": { "title": "Test", "version": "1.0" },
            "paths": {
                "/batch": {
                    "post": {
                        "requestBody": {
                            "required": true,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": { "type": "string" }
                                    }
                                }
                            }
                        },
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        }"#;

        let endpoints = parse_openapi_json(spec).unwrap();
        assert_eq!(endpoints.len(), 1);
        assert!(
            endpoints[0]
                .parameters
                .iter()
                .all(|p| p.location != ParameterLocation::Body)
        );
    }

    #[test]
    fn error_display_json_parse_error() {
        let e: IntrospectionError = serde_json::from_str::<serde_json::Value>("{{bad")
            .unwrap_err()
            .into();
        assert!(e.to_string().contains("json parse error"));
    }

    #[test]
    fn openapi_cookie_parameter_location() {
        let spec = r#"{
            "openapi": "3.0.0",
            "info": { "title": "Test", "version": "1.0" },
            "paths": {
                "/session": {
                    "get": {
                        "parameters": [
                            {
                                "name": "session_id",
                                "in": "cookie",
                                "required": false,
                                "schema": { "type": "string" }
                            }
                        ],
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        }"#;

        let endpoints = parse_openapi_json(spec).unwrap();
        assert_eq!(
            endpoints[0].parameters[0].location,
            ParameterLocation::Cookie
        );
    }

    #[test]
    fn openapi_schema_type_number_object_array_boolean() {
        let spec = r#"{
            "openapi": "3.0.0",
            "info": { "title": "Test", "version": "1.0" },
            "paths": {
                "/types": {
                    "get": {
                        "parameters": [
                            {
                                "name": "price",
                                "in": "query",
                                "required": false,
                                "schema": { "type": "number" }
                            },
                            {
                                "name": "meta",
                                "in": "query",
                                "required": false,
                                "schema": { "type": "object" }
                            },
                            {
                                "name": "tags",
                                "in": "query",
                                "required": false,
                                "schema": { "type": "array" }
                            },
                            {
                                "name": "active",
                                "in": "query",
                                "required": false,
                                "schema": { "type": "boolean" }
                            }
                        ],
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        }"#;

        let endpoints = parse_openapi_json(spec).unwrap();
        let params = &endpoints[0].parameters;
        assert_eq!(
            params
                .iter()
                .find(|p| p.name == "price")
                .unwrap()
                .param_type,
            "number"
        );
        assert_eq!(
            params.iter().find(|p| p.name == "meta").unwrap().param_type,
            "object"
        );
        assert_eq!(
            params.iter().find(|p| p.name == "tags").unwrap().param_type,
            "array"
        );
        assert_eq!(
            params
                .iter()
                .find(|p| p.name == "active")
                .unwrap()
                .param_type,
            "boolean"
        );
    }

    #[test]
    fn openapi_response_status_code_range_is_ignored() {
        // The "2XX" range-style status code should be silently dropped;
        // only the numeric "201" code should appear in the output.
        let spec = r#"{
            "openapi": "3.0.0",
            "info": { "title": "Test", "version": "1.0" },
            "paths": {
                "/items": {
                    "post": {
                        "responses": {
                            "201": { "description": "created" },
                            "2XX": { "description": "other success" }
                        }
                    }
                }
            }
        }"#;

        let endpoints = parse_openapi_json(spec).unwrap();
        assert_eq!(endpoints[0].response_status_codes, vec![201]);
    }

    #[test]
    fn graphql_introspection_subscription_type_emitted() {
        let response = r#"{
            "data": {
                "__schema": {
                    "queryType": { "name": "Query" },
                    "mutationType": null,
                    "subscriptionType": { "name": "Subscription" },
                    "types": [
                        {
                            "name": "Query",
                            "kind": "OBJECT",
                            "fields": [
                                {
                                    "name": "ping",
                                    "args": [],
                                    "type": { "kind": "SCALAR", "name": "String", "ofType": null }
                                }
                            ]
                        },
                        {
                            "name": "Subscription",
                            "kind": "OBJECT",
                            "fields": [
                                {
                                    "name": "events",
                                    "args": [],
                                    "type": { "kind": "SCALAR", "name": "String", "ofType": null }
                                }
                            ]
                        }
                    ]
                }
            }
        }"#;

        let endpoints = parse_graphql_introspection(response).unwrap();
        let sub = endpoints.iter().find(|e| {
            e.description
                .as_deref()
                .is_some_and(|d| d.contains("Subscription"))
        });
        assert!(sub.is_some());
    }

    #[test]
    fn graphql_introspection_non_object_type_and_null_fields_skipped() {
        // A SCALAR type and an OBJECT type with null fields must not appear as endpoints.
        let response = r#"{
            "data": {
                "__schema": {
                    "queryType": { "name": "Query" },
                    "mutationType": null,
                    "subscriptionType": null,
                    "types": [
                        {
                            "name": "Query",
                            "kind": "OBJECT",
                            "fields": [
                                {
                                    "name": "version",
                                    "args": [],
                                    "type": { "kind": "SCALAR", "name": "String", "ofType": null }
                                }
                            ]
                        },
                        {
                            "name": "SomeScalar",
                            "kind": "SCALAR",
                            "fields": null
                        },
                        {
                            "name": "EmptyObject",
                            "kind": "OBJECT",
                            "fields": null
                        }
                    ]
                }
            }
        }"#;

        let endpoints = parse_graphql_introspection(response).unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].description.as_deref(), Some("Query: version"));
    }

    #[test]
    fn graphql_introspection_builtin_and_dunder_types_skipped() {
        // __Schema and String (builtin scalar) must be filtered out before SDL emission.
        let response = r#"{
            "data": {
                "__schema": {
                    "queryType": { "name": "Query" },
                    "mutationType": null,
                    "subscriptionType": null,
                    "types": [
                        {
                            "name": "Query",
                            "kind": "OBJECT",
                            "fields": [
                                {
                                    "name": "ping",
                                    "args": [],
                                    "type": { "kind": "SCALAR", "name": "String", "ofType": null }
                                }
                            ]
                        },
                        {
                            "name": "__Schema",
                            "kind": "OBJECT",
                            "fields": []
                        },
                        {
                            "name": "String",
                            "kind": "SCALAR",
                            "fields": null
                        }
                    ]
                }
            }
        }"#;

        let endpoints = parse_graphql_introspection(response).unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].description.as_deref(), Some("Query: ping"));
    }

    #[test]
    fn graphql_introspection_field_with_args_emitted() {
        // A field that has arguments must produce parenthesised args in the SDL,
        // exercising the emit_field args branch.
        let response = r#"{
            "data": {
                "__schema": {
                    "queryType": { "name": "Query" },
                    "mutationType": null,
                    "subscriptionType": null,
                    "types": [
                        {
                            "name": "Query",
                            "kind": "OBJECT",
                            "fields": [
                                {
                                    "name": "user",
                                    "args": [
                                        {
                                            "name": "id",
                                            "type": {
                                                "kind": "NON_NULL",
                                                "name": null,
                                                "ofType": { "kind": "SCALAR", "name": "ID", "ofType": null }
                                            }
                                        }
                                    ],
                                    "type": { "kind": "OBJECT", "name": "User", "ofType": null }
                                }
                            ]
                        }
                    ]
                }
            }
        }"#;

        let endpoints = parse_graphql_introspection(response).unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].parameters[0].name, "id");
        assert_eq!(endpoints[0].parameters[0].param_type, "ID!");
        assert!(endpoints[0].parameters[0].required);
    }

    #[test]
    fn graphql_introspection_field_type_null_defaults_to_string() {
        // A field with a null type ref must not panic; type_ref_to_sdl returns "String".
        let response = r#"{
            "data": {
                "__schema": {
                    "queryType": { "name": "Query" },
                    "mutationType": null,
                    "subscriptionType": null,
                    "types": [
                        {
                            "name": "Query",
                            "kind": "OBJECT",
                            "fields": [
                                {
                                    "name": "mystery",
                                    "args": [],
                                    "type": null
                                }
                            ]
                        }
                    ]
                }
            }
        }"#;

        let endpoints = parse_graphql_introspection(response).unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].response_type.as_deref(), Some("String"));
    }
}
