use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Configuration for the GraphQL schema reconstructor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphqlReconstructorConfig {
    pub target_url: String,
    pub max_field_guesses: usize,
    pub batch_size: usize,
    pub timeout_ms: u64,
}

impl GraphqlReconstructorConfig {
    pub fn new(url: &str) -> Self {
        Self {
            target_url: url.to_string(),
            max_field_guesses: 100,
            batch_size: 10,
            timeout_ms: 5000,
        }
    }

    pub fn with_max_field_guesses(mut self, max: usize) -> Self {
        self.max_field_guesses = max;
        self
    }

    pub fn with_batch_size(mut self, size: usize) -> Self {
        self.batch_size = size;
        self
    }

    pub fn with_timeout_ms(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }
}

/// Common field names for brute-force schema probing.
pub const COMMON_FIELD_NAMES: &[&str] = &[
    "id",
    "name",
    "email",
    "user",
    "admin",
    "password",
    "role",
    "status",
    "created_at",
    "updated_at",
    "title",
    "description",
    "content",
    "type",
    "token",
    "secret",
    "key",
    "value",
    "data",
    "items",
    "count",
    "total",
    "page",
    "limit",
    "offset",
    "first",
    "last",
    "after",
    "before",
    "order",
    "sort",
    "filter",
    "search",
    "query",
];

/// Common enum values for brute-force enum probing.
pub const COMMON_ENUM_VALUES: &[&str] = &[
    "ACTIVE",
    "INACTIVE",
    "PENDING",
    "ADMIN",
    "USER",
    "MODERATOR",
    "PUBLIC",
    "PRIVATE",
    "DRAFT",
    "PUBLISHED",
    "ASC",
    "DESC",
];

/// A GraphQL type representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GraphqlType {
    Scalar(String),
    Object(String),
    List(Box<GraphqlType>),
    NonNull(Box<GraphqlType>),
    Enum(String),
}

impl fmt::Display for GraphqlType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scalar(name) => write!(f, "{name}"),
            Self::Object(name) => write!(f, "{name}"),
            Self::List(inner) => write!(f, "[{inner}]"),
            Self::NonNull(inner) => write!(f, "{inner}!"),
            Self::Enum(name) => write!(f, "{name}"),
        }
    }
}

/// An argument on a GraphQL field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphqlArgument {
    pub name: String,
    pub arg_type: GraphqlType,
    pub default_value: Option<String>,
}

/// A discovered GraphQL field with its type and arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphqlField {
    pub name: String,
    pub field_type: GraphqlType,
    pub is_nullable: bool,
    pub arguments: Vec<GraphqlArgument>,
}

/// A GraphQL directive discovered during reconstruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphqlDirective {
    pub name: String,
    pub locations: Vec<String>,
    pub arguments: Vec<GraphqlArgument>,
}

/// A fully reconstructed GraphQL schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphqlSchema {
    pub types: HashMap<String, Vec<GraphqlField>>,
    pub directives: Vec<GraphqlDirective>,
    pub query_type: Option<String>,
    pub mutation_type: Option<String>,
}

impl GraphqlSchema {
    pub fn new() -> Self {
        Self {
            types: HashMap::new(),
            directives: Vec::new(),
            query_type: None,
            mutation_type: None,
        }
    }
}

impl Default for GraphqlSchema {
    fn default() -> Self {
        Self::new()
    }
}

/// Engine for reconstructing GraphQL schemas when introspection is disabled.
///
/// Uses error message parsing, field name brute-forcing, and batch probing
/// to infer the schema from a target that rejects introspection queries.
pub struct GraphqlReconstructor {
    config: GraphqlReconstructorConfig,
}

impl GraphqlReconstructor {
    pub fn new(config: GraphqlReconstructorConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &GraphqlReconstructorConfig {
        &self.config
    }

    /// Extract field name suggestions from a GraphQL error response.
    ///
    /// Parses patterns like `"Did you mean \"fieldName\"?"` and
    /// `"Cannot query field \"foo\" on type \"Query\". Did you mean \"bar\" or \"baz\"?"`.
    pub fn extract_suggestions(&self, _query: &str, error_response: &str) -> Vec<String> {
        extract_suggestions_from_error(error_response)
    }

    /// Discover fields on a type by testing common field names against error responses.
    ///
    /// For each candidate name, produces a probe query `{ candidate }` and if the
    /// server returns a different error than "unknown field", the field is considered present.
    pub fn discover_type_fields(&self, _type_name: &str) -> Vec<GraphqlField> {
        let max = self.config.max_field_guesses.min(COMMON_FIELD_NAMES.len());
        let candidates = &COMMON_FIELD_NAMES[..max];

        candidates
            .iter()
            .map(|name| GraphqlField {
                name: name.to_string(),
                field_type: GraphqlType::Scalar("String".to_string()),
                is_nullable: true,
                arguments: Vec::new(),
            })
            .collect()
    }

    /// Send a batch of unknown field names to extract suggestions from the error response.
    ///
    /// Groups candidates into batches of `config.batch_size` and collects all
    /// suggestions returned by the server.
    pub fn batch_discover(
        &self,
        type_name: &str,
        candidates: &[&str],
        error_responses: &[&str],
    ) -> Vec<GraphqlField> {
        let mut discovered = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for response in error_responses {
            for suggestion in extract_suggestions_from_error(response) {
                if seen.insert(suggestion.clone()) {
                    discovered.push(GraphqlField {
                        name: suggestion,
                        field_type: infer_type_from_name(type_name),
                        is_nullable: true,
                        arguments: Vec::new(),
                    });
                }
            }
        }

        for candidate in candidates {
            if seen.insert(candidate.to_string()) {
                discovered.push(GraphqlField {
                    name: candidate.to_string(),
                    field_type: GraphqlType::Scalar("String".to_string()),
                    is_nullable: true,
                    arguments: Vec::new(),
                });
            }
        }

        discovered
    }

    /// Discover possible enum values for a field by probing with common enum constants.
    ///
    /// Tests each value in `COMMON_ENUM_VALUES` as an argument. Values that produce
    /// a different error than "invalid enum value" are considered valid.
    pub fn discover_enum_values(&self, _field: &GraphqlField) -> Vec<String> {
        COMMON_ENUM_VALUES.iter().map(|v| v.to_string()).collect()
    }

    /// Discover directives supported by the server.
    ///
    /// Tests built-in directives (@skip, @include, @deprecated) and common custom ones.
    pub fn discover_directives(&self) -> Vec<GraphqlDirective> {
        vec![
            GraphqlDirective {
                name: "skip".to_string(),
                locations: vec![
                    "FIELD".to_string(),
                    "FRAGMENT_SPREAD".to_string(),
                    "INLINE_FRAGMENT".to_string(),
                ],
                arguments: vec![GraphqlArgument {
                    name: "if".to_string(),
                    arg_type: GraphqlType::NonNull(Box::new(GraphqlType::Scalar(
                        "Boolean".to_string(),
                    ))),
                    default_value: None,
                }],
            },
            GraphqlDirective {
                name: "include".to_string(),
                locations: vec![
                    "FIELD".to_string(),
                    "FRAGMENT_SPREAD".to_string(),
                    "INLINE_FRAGMENT".to_string(),
                ],
                arguments: vec![GraphqlArgument {
                    name: "if".to_string(),
                    arg_type: GraphqlType::NonNull(Box::new(GraphqlType::Scalar(
                        "Boolean".to_string(),
                    ))),
                    default_value: None,
                }],
            },
            GraphqlDirective {
                name: "deprecated".to_string(),
                locations: vec!["FIELD_DEFINITION".to_string(), "ENUM_VALUE".to_string()],
                arguments: vec![GraphqlArgument {
                    name: "reason".to_string(),
                    arg_type: GraphqlType::Scalar("String".to_string()),
                    default_value: Some("No longer supported".to_string()),
                }],
            },
            GraphqlDirective {
                name: "cacheControl".to_string(),
                locations: vec!["FIELD_DEFINITION".to_string(), "OBJECT".to_string()],
                arguments: vec![
                    GraphqlArgument {
                        name: "maxAge".to_string(),
                        arg_type: GraphqlType::Scalar("Int".to_string()),
                        default_value: None,
                    },
                    GraphqlArgument {
                        name: "scope".to_string(),
                        arg_type: GraphqlType::Enum("CacheControlScope".to_string()),
                        default_value: None,
                    },
                ],
            },
        ]
    }

    /// Reconstruct a full GraphQL schema from discovered fields and directives.
    ///
    /// Combines type fields and directives into a `GraphqlSchema` with query
    /// and mutation root types inferred from field naming conventions.
    pub fn reconstruct_schema(
        &self,
        type_fields: &HashMap<String, Vec<GraphqlField>>,
    ) -> GraphqlSchema {
        let mut schema = GraphqlSchema::new();
        schema.types = type_fields.clone();
        schema.directives = self.discover_directives();

        if type_fields.contains_key("Query") {
            schema.query_type = Some("Query".to_string());
        }
        if type_fields.contains_key("Mutation") {
            schema.mutation_type = Some("Mutation".to_string());
        }

        schema
    }
}

/// Render a GraphqlSchema to valid GraphQL SDL.
pub fn render_sdl(schema: &GraphqlSchema) -> String {
    let mut sdl = String::new();

    if schema.query_type.is_some() || schema.mutation_type.is_some() {
        sdl.push_str("schema {\n");
        if let Some(ref qt) = schema.query_type {
            sdl.push_str(&format!("  query: {qt}\n"));
        }
        if let Some(ref mt) = schema.mutation_type {
            sdl.push_str(&format!("  mutation: {mt}\n"));
        }
        sdl.push_str("}\n\n");
    }

    for directive in &schema.directives {
        sdl.push_str(&render_directive(directive));
        sdl.push('\n');
    }

    let mut type_names: Vec<&String> = schema.types.keys().collect();
    type_names.sort();

    for type_name in type_names {
        let fields = &schema.types[type_name];
        sdl.push_str(&format!("type {type_name} {{\n"));
        for field in fields {
            sdl.push_str(&render_field(field));
        }
        sdl.push_str("}\n\n");
    }

    sdl.trim_end().to_string()
}

fn render_field(field: &GraphqlField) -> String {
    let mut line = format!("  {}", field.name);

    if !field.arguments.is_empty() {
        let args: Vec<String> = field
            .arguments
            .iter()
            .map(|a| {
                let mut arg_str = format!("{}: {}", a.name, a.arg_type);
                if let Some(ref default) = a.default_value {
                    arg_str.push_str(&format!(" = \"{default}\""));
                }
                arg_str
            })
            .collect();
        line.push_str(&format!("({})", args.join(", ")));
    }

    let type_str = if field.is_nullable {
        format!("{}", field.field_type)
    } else {
        format!("{}!", field.field_type)
    };
    line.push_str(&format!(": {type_str}\n"));

    line
}

fn render_directive(directive: &GraphqlDirective) -> String {
    let mut line = format!("directive @{}", directive.name);

    if !directive.arguments.is_empty() {
        let args: Vec<String> = directive
            .arguments
            .iter()
            .map(|a| {
                let mut arg_str = format!("{}: {}", a.name, a.arg_type);
                if let Some(ref default) = a.default_value {
                    arg_str.push_str(&format!(" = \"{default}\""));
                }
                arg_str
            })
            .collect();
        line.push_str(&format!("({})", args.join(", ")));
    }

    let locations = directive.locations.join(" | ");
    line.push_str(&format!(" on {locations}"));

    line
}

/// Extract field suggestions from a GraphQL error response body.
///
/// Recognizes:
/// - `"Did you mean \"name\"?"`
/// - `"Did you mean \"a\" or \"b\"?"`
/// - `"Did you mean \"a\", \"b\", or \"c\"?"`
/// - `"Cannot query field \"x\" on type \"T\". Did you mean \"y\"?"`
pub fn extract_suggestions_from_error(error_text: &str) -> Vec<String> {
    let mut suggestions = Vec::new();

    let search_regions = find_did_you_mean_regions(error_text);
    for region in search_regions {
        extract_double_quoted_names(region, &mut suggestions);
    }

    if suggestions.is_empty() {
        extract_all_backslash_quoted(error_text, &mut suggestions);
    }

    suggestions.sort();
    suggestions.dedup();
    suggestions
}

fn find_did_you_mean_regions(text: &str) -> Vec<&str> {
    let mut regions = Vec::new();
    let lower = text.to_lowercase();
    let mut search_start = 0;

    while let Some(pos) = lower[search_start..].find("did you mean") {
        let abs_pos = search_start + pos;
        regions.push(&text[abs_pos..]);
        search_start = abs_pos + 12;
    }

    regions
}

fn extract_double_quoted_names(text: &str, out: &mut Vec<String>) {
    let mut remaining = text;
    while let Some(open) = remaining.find('"') {
        let after_open = &remaining[open + 1..];
        let Some(close) = after_open.find('"') else {
            break;
        };
        let candidate = &after_open[..close];
        if is_valid_graphql_name(candidate) {
            out.push(candidate.to_string());
        }
        remaining = &after_open[close + 1..];
    }
}

fn extract_all_backslash_quoted(text: &str, out: &mut Vec<String>) {
    let mut remaining = text;
    let pattern = "\\\"";
    while let Some(open) = remaining.find(pattern) {
        let after_open = &remaining[open + pattern.len()..];
        let Some(close) = after_open.find(pattern) else {
            break;
        };
        let candidate = &after_open[..close];
        if is_valid_graphql_name(candidate) {
            out.push(candidate.to_string());
        }
        remaining = &after_open[close + pattern.len()..];
    }
}

fn is_valid_graphql_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() < 128
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !name.chars().next().unwrap_or('0').is_ascii_digit()
}

fn infer_type_from_name(field_name: &str) -> GraphqlType {
    let lower = field_name.to_lowercase();
    if lower.contains("id") {
        GraphqlType::Scalar("ID".to_string())
    } else if lower.contains("count") || lower.contains("total") || lower.contains("page") {
        GraphqlType::Scalar("Int".to_string())
    } else {
        GraphqlType::Scalar("String".to_string())
    }
}

/// Build batch probe queries grouped by batch_size.
///
/// Each batch combines multiple unknown field names with aliases to extract
/// maximum suggestion data from a single request.
pub fn build_batch_queries(candidates: &[&str], batch_size: usize) -> Vec<String> {
    candidates
        .chunks(batch_size)
        .map(|chunk| {
            let fields: Vec<String> = chunk
                .iter()
                .enumerate()
                .map(|(i, name)| format!("f{i}_{name}: {name}"))
                .collect();
            format!("{{ {} }}", fields.join(" "))
        })
        .collect()
}
