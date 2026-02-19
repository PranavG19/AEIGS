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
}
