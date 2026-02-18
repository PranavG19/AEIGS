use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntrospectedEndpoint {
    pub path: String,
    pub method: String,
    pub parameters: Vec<EndpointParameter>,
    pub response_type: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointParameter {
    pub name: String,
    pub location: ParameterLocation,
    pub param_type: String,
    pub required: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParameterLocation {
    Path,
    Query,
    Header,
    Body,
}

impl std::fmt::Display for ParameterLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Path => "path",
            Self::Query => "query",
            Self::Header => "header",
            Self::Body => "body",
        };
        write!(f, "{label}")
    }
}

#[derive(Debug)]
pub enum IntrospectionError {
    JsonParseError(serde_json::Error),
    InvalidSchema(String),
    NetworkError(String),
}

impl std::fmt::Display for IntrospectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::JsonParseError(e) => write!(f, "json parse error: {e}"),
            Self::InvalidSchema(msg) => write!(f, "invalid schema: {msg}"),
            Self::NetworkError(msg) => write!(f, "network error: {msg}"),
        }
    }
}

impl std::error::Error for IntrospectionError {}

impl From<serde_json::Error> for IntrospectionError {
    fn from(e: serde_json::Error) -> Self {
        Self::JsonParseError(e)
    }
}

#[derive(Deserialize)]
struct OpenApiSpec {
    #[serde(default)]
    paths: HashMap<String, HashMap<String, OpenApiOperation>>,
}

#[derive(Deserialize)]
struct OpenApiOperation {
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    parameters: Vec<OpenApiParameter>,
}

#[derive(Deserialize)]
struct OpenApiParameter {
    name: String,
    #[serde(rename = "in")]
    location: String,
    #[serde(default)]
    required: bool,
    #[serde(default)]
    schema: Option<OpenApiSchema>,
}

#[derive(Deserialize)]
struct OpenApiSchema {
    #[serde(rename = "type", default)]
    schema_type: Option<String>,
}

pub fn parse_openapi_json(
    json_content: &str,
) -> Result<Vec<IntrospectedEndpoint>, IntrospectionError> {
    let spec: OpenApiSpec = serde_json::from_str(json_content)?;
    let mut endpoints = Vec::new();

    for (path, methods) in &spec.paths {
        for (method, operation) in methods {
            let parameters: Vec<EndpointParameter> = operation
                .parameters
                .iter()
                .map(|p| EndpointParameter {
                    name: p.name.clone(),
                    location: match p.location.as_str() {
                        "path" => ParameterLocation::Path,
                        "query" => ParameterLocation::Query,
                        "header" => ParameterLocation::Header,
                        _ => ParameterLocation::Body,
                    },
                    param_type: p
                        .schema
                        .as_ref()
                        .and_then(|s| s.schema_type.clone())
                        .unwrap_or_else(|| "string".to_string()),
                    required: p.required,
                })
                .collect();

            endpoints.push(IntrospectedEndpoint {
                path: path.clone(),
                method: method.to_uppercase(),
                parameters,
                response_type: None,
                description: operation.summary.clone(),
            });
        }
    }

    endpoints.sort_by(|a, b| a.path.cmp(&b.path).then(a.method.cmp(&b.method)));
    Ok(endpoints)
}

#[derive(Deserialize)]
struct GraphQlIntrospectionResponse {
    data: Option<GraphQlData>,
}

#[derive(Deserialize)]
struct GraphQlData {
    #[serde(rename = "__schema")]
    schema: GraphQlSchema,
}

#[derive(Deserialize)]
struct GraphQlSchema {
    #[serde(rename = "queryType")]
    query_type: Option<GraphQlType>,
    #[serde(rename = "mutationType")]
    mutation_type: Option<GraphQlType>,
}

#[derive(Deserialize)]
struct GraphQlType {
    #[serde(default)]
    fields: Option<Vec<GraphQlField>>,
}

#[derive(Deserialize)]
struct GraphQlField {
    name: String,
    #[serde(default)]
    args: Vec<GraphQlArg>,
}

#[derive(Deserialize)]
struct GraphQlArg {
    name: String,
}

pub fn parse_graphql_introspection(
    json_content: &str,
) -> Result<Vec<IntrospectedEndpoint>, IntrospectionError> {
    let response: GraphQlIntrospectionResponse = serde_json::from_str(json_content)?;
    let mut endpoints = Vec::new();

    let data = response
        .data
        .ok_or_else(|| IntrospectionError::InvalidSchema("missing data field".to_string()))?;

    if let Some(query_type) = &data.schema.query_type
        && let Some(fields) = &query_type.fields
    {
        for field in fields {
            let parameters: Vec<EndpointParameter> = field
                .args
                .iter()
                .map(|a| EndpointParameter {
                    name: a.name.clone(),
                    location: ParameterLocation::Body,
                    param_type: "string".to_string(),
                    required: false,
                })
                .collect();

            endpoints.push(IntrospectedEndpoint {
                path: format!("/graphql?query={}", field.name),
                method: "POST".to_string(),
                parameters,
                response_type: None,
                description: Some(format!("Query: {}", field.name)),
            });
        }
    }

    if let Some(mutation_type) = &data.schema.mutation_type
        && let Some(fields) = &mutation_type.fields
    {
        for field in fields {
            endpoints.push(IntrospectedEndpoint {
                path: format!("/graphql?mutation={}", field.name),
                method: "POST".to_string(),
                parameters: field
                    .args
                    .iter()
                    .map(|a| EndpointParameter {
                        name: a.name.clone(),
                        location: ParameterLocation::Body,
                        param_type: "string".to_string(),
                        required: false,
                    })
                    .collect(),
                response_type: None,
                description: Some(format!("Mutation: {}", field.name)),
            });
        }
    }

    Ok(endpoints)
}
