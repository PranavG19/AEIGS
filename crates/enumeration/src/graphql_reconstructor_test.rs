#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::graphql_reconstructor::{
        build_batch_queries, extract_suggestions_from_error, render_sdl, GraphqlArgument,
        GraphqlField, GraphqlReconstructor, GraphqlReconstructorConfig, GraphqlSchema, GraphqlType,
        COMMON_ENUM_VALUES, COMMON_FIELD_NAMES,
    };

    fn sample_config() -> GraphqlReconstructorConfig {
        GraphqlReconstructorConfig::new("http://localhost:4000/graphql")
    }

    #[test]
    fn config_defaults() {
        let config = sample_config();
        assert_eq!(config.max_field_guesses, 100);
        assert_eq!(config.batch_size, 10);
        assert_eq!(config.timeout_ms, 5000);
    }

    #[test]
    fn config_builder_chain() {
        let config = GraphqlReconstructorConfig::new("http://example.com/graphql")
            .with_max_field_guesses(50)
            .with_batch_size(5)
            .with_timeout_ms(10000);
        assert_eq!(config.max_field_guesses, 50);
        assert_eq!(config.batch_size, 5);
        assert_eq!(config.timeout_ms, 10000);
    }

    #[test]
    fn extract_suggestions_single_did_you_mean() {
        let error = r#"{"errors":[{"message":"Cannot query field \"userz\" on type \"Query\". Did you mean \"user\" or \"users\"?"}]}"#;
        let suggestions = extract_suggestions_from_error(error);
        assert!(suggestions.contains(&"user".to_string()));
        assert!(suggestions.contains(&"users".to_string()));
    }

    #[test]
    fn extract_suggestions_multiple_suggestions() {
        let error = r#"{"errors":[{"message":"Did you mean \"name\", \"email\", or \"role\"?"}]}"#;
        let suggestions = extract_suggestions_from_error(error);
        assert!(suggestions.contains(&"name".to_string()));
        assert!(suggestions.contains(&"email".to_string()));
        assert!(suggestions.contains(&"role".to_string()));
    }

    #[test]
    fn extract_suggestions_no_match() {
        let error = r#"{"errors":[{"message":"Syntax Error: Unexpected token"}]}"#;
        let suggestions = extract_suggestions_from_error(error);
        assert!(suggestions.is_empty());
    }

    #[test]
    fn extract_suggestions_deduplicates() {
        let error = r#"Did you mean "name"? Did you mean "name" or "email"?"#;
        let suggestions = extract_suggestions_from_error(error);
        assert_eq!(
            suggestions.iter().filter(|s| *s == "name").count(),
            1,
            "name should appear exactly once"
        );
    }

    #[test]
    fn extract_suggestions_ignores_invalid_names() {
        let error = r#"Did you mean "123invalid" or "valid_name"?"#;
        let suggestions = extract_suggestions_from_error(error);
        assert!(!suggestions.contains(&"123invalid".to_string()));
        assert!(suggestions.contains(&"valid_name".to_string()));
    }

    #[test]
    fn extract_suggestions_backslash_quoted() {
        let error = r#"Cannot query field \"foo\" on type \"Query\". Did you mean \"bar\"?"#;
        let suggestions = extract_suggestions_from_error(error);
        assert!(suggestions.contains(&"bar".to_string()));
    }

    #[test]
    fn discover_type_fields_returns_common_names() {
        let config =
            GraphqlReconstructorConfig::new("http://localhost/graphql").with_max_field_guesses(5);
        let reconstructor = GraphqlReconstructor::new(config);
        let fields = reconstructor.discover_type_fields("Query");

        assert_eq!(fields.len(), 5);
        assert_eq!(fields[0].name, COMMON_FIELD_NAMES[0]);
        assert_eq!(fields[4].name, COMMON_FIELD_NAMES[4]);
    }

    #[test]
    fn discover_type_fields_respects_max() {
        let config =
            GraphqlReconstructorConfig::new("http://localhost/graphql").with_max_field_guesses(3);
        let reconstructor = GraphqlReconstructor::new(config);
        let fields = reconstructor.discover_type_fields("Query");
        assert_eq!(fields.len(), 3);
    }

    #[test]
    fn discover_type_fields_caps_at_common_list_length() {
        let config = GraphqlReconstructorConfig::new("http://localhost/graphql")
            .with_max_field_guesses(9999);
        let reconstructor = GraphqlReconstructor::new(config);
        let fields = reconstructor.discover_type_fields("Query");
        assert_eq!(fields.len(), COMMON_FIELD_NAMES.len());
    }

    #[test]
    fn batch_discover_extracts_from_errors() {
        let reconstructor = GraphqlReconstructor::new(sample_config());
        let error_responses = [
            r#"Did you mean "user" or "admin"?"#,
            r#"Did you mean "role"?"#,
        ];

        let fields = reconstructor.batch_discover("Query", &["extra"], &error_responses.map(|s| s));
        let names: Vec<&str> = fields.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"user"));
        assert!(names.contains(&"admin"));
        assert!(names.contains(&"role"));
        assert!(names.contains(&"extra"));
    }

    #[test]
    fn batch_discover_deduplicates() {
        let reconstructor = GraphqlReconstructor::new(sample_config());
        let error_responses = [r#"Did you mean "user"?"#, r#"Did you mean "user"?"#];

        let fields = reconstructor.batch_discover("Query", &[], &error_responses.map(|s| s));
        let user_count = fields.iter().filter(|f| f.name == "user").count();
        assert_eq!(user_count, 1);
    }

    #[test]
    fn discover_enum_values_returns_common_values() {
        let reconstructor = GraphqlReconstructor::new(sample_config());
        let field = GraphqlField {
            name: "status".to_string(),
            field_type: GraphqlType::Enum("Status".to_string()),
            is_nullable: true,
            arguments: Vec::new(),
        };

        let values = reconstructor.discover_enum_values(&field);
        assert_eq!(values.len(), COMMON_ENUM_VALUES.len());
        assert!(values.contains(&"ACTIVE".to_string()));
        assert!(values.contains(&"ADMIN".to_string()));
        assert!(values.contains(&"DESC".to_string()));
    }

    #[test]
    fn discover_directives_includes_builtins() {
        let reconstructor = GraphqlReconstructor::new(sample_config());
        let directives = reconstructor.discover_directives();

        let names: Vec<&str> = directives.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"skip"));
        assert!(names.contains(&"include"));
        assert!(names.contains(&"deprecated"));
    }

    #[test]
    fn discover_directives_skip_has_if_argument() {
        let reconstructor = GraphqlReconstructor::new(sample_config());
        let directives = reconstructor.discover_directives();
        let skip = directives.iter().find(|d| d.name == "skip").unwrap();

        assert_eq!(skip.arguments.len(), 1);
        assert_eq!(skip.arguments[0].name, "if");
        assert_eq!(
            skip.arguments[0].arg_type,
            GraphqlType::NonNull(Box::new(GraphqlType::Scalar("Boolean".to_string())))
        );
    }

    #[test]
    fn reconstruct_schema_sets_root_types() {
        let reconstructor = GraphqlReconstructor::new(sample_config());
        let mut types = HashMap::new();
        types.insert(
            "Query".to_string(),
            vec![GraphqlField {
                name: "user".to_string(),
                field_type: GraphqlType::Object("User".to_string()),
                is_nullable: true,
                arguments: Vec::new(),
            }],
        );
        types.insert(
            "Mutation".to_string(),
            vec![GraphqlField {
                name: "createUser".to_string(),
                field_type: GraphqlType::Object("User".to_string()),
                is_nullable: true,
                arguments: Vec::new(),
            }],
        );

        let schema = reconstructor.reconstruct_schema(&types);
        assert_eq!(schema.query_type, Some("Query".to_string()));
        assert_eq!(schema.mutation_type, Some("Mutation".to_string()));
        assert!(!schema.directives.is_empty());
    }

    #[test]
    fn reconstruct_schema_without_mutation() {
        let reconstructor = GraphqlReconstructor::new(sample_config());
        let mut types = HashMap::new();
        types.insert("Query".to_string(), vec![]);

        let schema = reconstructor.reconstruct_schema(&types);
        assert_eq!(schema.query_type, Some("Query".to_string()));
        assert!(schema.mutation_type.is_none());
    }

    #[test]
    fn render_sdl_produces_valid_syntax() {
        let mut types = HashMap::new();
        types.insert(
            "Query".to_string(),
            vec![
                GraphqlField {
                    name: "user".to_string(),
                    field_type: GraphqlType::Object("User".to_string()),
                    is_nullable: true,
                    arguments: vec![GraphqlArgument {
                        name: "id".to_string(),
                        arg_type: GraphqlType::NonNull(Box::new(GraphqlType::Scalar(
                            "ID".to_string(),
                        ))),
                        default_value: None,
                    }],
                },
                GraphqlField {
                    name: "users".to_string(),
                    field_type: GraphqlType::List(Box::new(GraphqlType::Object(
                        "User".to_string(),
                    ))),
                    is_nullable: true,
                    arguments: Vec::new(),
                },
            ],
        );
        types.insert(
            "User".to_string(),
            vec![
                GraphqlField {
                    name: "id".to_string(),
                    field_type: GraphqlType::Scalar("ID".to_string()),
                    is_nullable: false,
                    arguments: Vec::new(),
                },
                GraphqlField {
                    name: "name".to_string(),
                    field_type: GraphqlType::Scalar("String".to_string()),
                    is_nullable: true,
                    arguments: Vec::new(),
                },
            ],
        );

        let schema = GraphqlSchema {
            types,
            directives: Vec::new(),
            query_type: Some("Query".to_string()),
            mutation_type: None,
        };

        let sdl = render_sdl(&schema);

        assert!(sdl.contains("schema {"));
        assert!(sdl.contains("query: Query"));
        assert!(sdl.contains("type Query {"));
        assert!(sdl.contains("user(id: ID!): User"));
        assert!(sdl.contains("users: [User]"));
        assert!(sdl.contains("type User {"));
        assert!(sdl.contains("id: ID!"));
        assert!(sdl.contains("name: String"));
    }

    #[test]
    fn render_sdl_with_directives() {
        let schema = GraphqlSchema {
            types: HashMap::new(),
            directives: vec![crate::graphql_reconstructor::GraphqlDirective {
                name: "skip".to_string(),
                locations: vec!["FIELD".to_string()],
                arguments: vec![GraphqlArgument {
                    name: "if".to_string(),
                    arg_type: GraphqlType::NonNull(Box::new(GraphqlType::Scalar(
                        "Boolean".to_string(),
                    ))),
                    default_value: None,
                }],
            }],
            query_type: None,
            mutation_type: None,
        };

        let sdl = render_sdl(&schema);
        assert!(sdl.contains("directive @skip(if: Boolean!) on FIELD"));
    }

    #[test]
    fn render_sdl_non_nullable_fields() {
        let mut types = HashMap::new();
        types.insert(
            "User".to_string(),
            vec![GraphqlField {
                name: "id".to_string(),
                field_type: GraphqlType::Scalar("ID".to_string()),
                is_nullable: false,
                arguments: Vec::new(),
            }],
        );

        let schema = GraphqlSchema {
            types,
            directives: Vec::new(),
            query_type: None,
            mutation_type: None,
        };

        let sdl = render_sdl(&schema);
        assert!(sdl.contains("id: ID!"));
    }

    #[test]
    fn render_sdl_empty_schema() {
        let schema = GraphqlSchema::new();
        let sdl = render_sdl(&schema);
        assert!(sdl.is_empty() || sdl.trim().is_empty());
    }

    #[test]
    fn graphql_type_display() {
        assert_eq!(
            GraphqlType::Scalar("String".to_string()).to_string(),
            "String"
        );
        assert_eq!(GraphqlType::Object("User".to_string()).to_string(), "User");
        assert_eq!(
            GraphqlType::List(Box::new(GraphqlType::Scalar("Int".to_string()))).to_string(),
            "[Int]"
        );
        assert_eq!(
            GraphqlType::NonNull(Box::new(GraphqlType::Scalar("ID".to_string()))).to_string(),
            "ID!"
        );
        assert_eq!(
            GraphqlType::Enum("Status".to_string()).to_string(),
            "Status"
        );
    }

    #[test]
    fn build_batch_queries_groups_by_size() {
        let candidates = &["a", "b", "c", "d", "e"];
        let queries = build_batch_queries(candidates, 2);

        assert_eq!(queries.len(), 3);
        assert!(queries[0].contains("f0_a: a"));
        assert!(queries[0].contains("f1_b: b"));
        assert!(queries[1].contains("f0_c: c"));
        assert!(queries[1].contains("f1_d: d"));
        assert!(queries[2].contains("f0_e: e"));
    }

    #[test]
    fn build_batch_queries_single_batch() {
        let candidates = &["x", "y"];
        let queries = build_batch_queries(candidates, 10);
        assert_eq!(queries.len(), 1);
        assert!(queries[0].contains("f0_x: x"));
        assert!(queries[0].contains("f1_y: y"));
    }

    #[test]
    fn build_batch_queries_empty_input() {
        let queries = build_batch_queries(&[], 5);
        assert!(queries.is_empty());
    }

    #[test]
    fn common_field_names_contains_security_relevant_fields() {
        assert!(COMMON_FIELD_NAMES.contains(&"password"));
        assert!(COMMON_FIELD_NAMES.contains(&"token"));
        assert!(COMMON_FIELD_NAMES.contains(&"secret"));
        assert!(COMMON_FIELD_NAMES.contains(&"admin"));
        assert!(COMMON_FIELD_NAMES.contains(&"role"));
    }

    #[test]
    fn common_enum_values_contains_role_values() {
        assert!(COMMON_ENUM_VALUES.contains(&"ADMIN"));
        assert!(COMMON_ENUM_VALUES.contains(&"USER"));
        assert!(COMMON_ENUM_VALUES.contains(&"MODERATOR"));
    }

    #[test]
    fn schema_default_is_empty() {
        let schema = GraphqlSchema::default();
        assert!(schema.types.is_empty());
        assert!(schema.directives.is_empty());
        assert!(schema.query_type.is_none());
        assert!(schema.mutation_type.is_none());
    }
}
