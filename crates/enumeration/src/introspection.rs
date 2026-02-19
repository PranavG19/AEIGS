use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntrospectedEndpoint {
    pub path: String,
    pub method: String,
    pub parameters: Vec<EndpointParameter>,
    pub response_type: Option<String>,
    pub description: Option<String>,
    pub security_schemes: Vec<String>,
    pub request_content_types: Vec<String>,
    pub response_status_codes: Vec<u16>,
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
    Cookie,
    Body,
}

impl std::fmt::Display for ParameterLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Path => "path",
            Self::Query => "query",
            Self::Header => "header",
            Self::Cookie => "cookie",
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

pub fn parse_openapi_json(
    json_content: &str,
) -> Result<Vec<IntrospectedEndpoint>, IntrospectionError> {
    let spec: openapiv3::OpenAPI = serde_json::from_str(json_content)?;
    let mut endpoints = Vec::new();

    let global_security = spec.security.as_deref().unwrap_or_default();

    for (path, method, operation) in spec.operations() {
        let parameters = extract_parameters(operation);
        let security = extract_security_schemes(operation, global_security);
        let content_types = extract_request_content_types(operation);
        let status_codes = extract_response_status_codes(operation);

        endpoints.push(IntrospectedEndpoint {
            path: path.to_string(),
            method: method.to_uppercase(),
            parameters,
            response_type: None,
            description: operation.summary.clone(),
            security_schemes: security,
            request_content_types: content_types,
            response_status_codes: status_codes,
        });
    }

    endpoints.sort_by(|a, b| a.path.cmp(&b.path).then(a.method.cmp(&b.method)));
    Ok(endpoints)
}

fn extract_parameters(operation: &openapiv3::Operation) -> Vec<EndpointParameter> {
    operation
        .parameters
        .iter()
        .filter_map(|ref_or_param| ref_or_param.as_item())
        .map(|param| {
            let data = param.parameter_data_ref();
            EndpointParameter {
                name: data.name.clone(),
                location: parameter_location(param),
                param_type: extract_schema_type(&data.format),
                required: data.required,
            }
        })
        .collect()
}

fn parameter_location(param: &openapiv3::Parameter) -> ParameterLocation {
    match param {
        openapiv3::Parameter::Path { .. } => ParameterLocation::Path,
        openapiv3::Parameter::Query { .. } => ParameterLocation::Query,
        openapiv3::Parameter::Header { .. } => ParameterLocation::Header,
        openapiv3::Parameter::Cookie { .. } => ParameterLocation::Cookie,
    }
}

fn extract_schema_type(format: &openapiv3::ParameterSchemaOrContent) -> String {
    match format {
        openapiv3::ParameterSchemaOrContent::Schema(ref_or_schema) => {
            if let Some(schema) = ref_or_schema.as_item() {
                schema_kind_to_type_name(&schema.schema_kind)
            } else {
                "string".to_string()
            }
        }
        openapiv3::ParameterSchemaOrContent::Content(_) => "string".to_string(),
    }
}

fn schema_kind_to_type_name(kind: &openapiv3::SchemaKind) -> String {
    match kind {
        openapiv3::SchemaKind::Type(t) => match t {
            openapiv3::Type::String(_) => "string".to_string(),
            openapiv3::Type::Number(_) => "number".to_string(),
            openapiv3::Type::Integer(_) => "integer".to_string(),
            openapiv3::Type::Object(_) => "object".to_string(),
            openapiv3::Type::Array(_) => "array".to_string(),
            openapiv3::Type::Boolean(_) => "boolean".to_string(),
        },
        _ => "string".to_string(),
    }
}

fn extract_security_schemes(
    operation: &openapiv3::Operation,
    global_security: &[openapiv3::SecurityRequirement],
) -> Vec<String> {
    let requirements = operation.security.as_deref().unwrap_or(global_security);
    requirements
        .iter()
        .flat_map(|req| req.keys().cloned())
        .collect()
}

fn extract_request_content_types(operation: &openapiv3::Operation) -> Vec<String> {
    let Some(ref_or_body) = &operation.request_body else {
        return Vec::new();
    };
    let Some(body) = ref_or_body.as_item() else {
        return Vec::new();
    };
    body.content.keys().cloned().collect()
}

fn extract_response_status_codes(operation: &openapiv3::Operation) -> Vec<u16> {
    let mut codes: Vec<u16> = operation
        .responses
        .responses
        .keys()
        .filter_map(|sc| match sc {
            openapiv3::StatusCode::Code(n) => Some(*n),
            openapiv3::StatusCode::Range(_) => None,
        })
        .collect();
    codes.sort();
    codes
}

pub fn parse_graphql_introspection(
    json_content: &str,
) -> Result<Vec<IntrospectedEndpoint>, IntrospectionError> {
    let sdl = introspection_json_to_sdl(json_content)?;
    parse_graphql_sdl(&sdl)
}

pub fn parse_graphql_sdl(sdl: &str) -> Result<Vec<IntrospectedEndpoint>, IntrospectionError> {
    let document = graphql_parser::schema::parse_schema::<&str>(sdl)
        .map_err(|e| IntrospectionError::InvalidSchema(e.to_string()))?;

    let root_types = resolve_root_types(&document);
    let mut endpoints = Vec::new();

    for def in &document.definitions {
        if let graphql_parser::schema::Definition::TypeDefinition(
            graphql_parser::schema::TypeDefinition::Object(obj),
        ) = def
        {
            let operation_kind = classify_root_object(obj.name, &root_types);
            if let Some(kind) = operation_kind {
                collect_field_endpoints(&obj.fields, kind, &mut endpoints);
            }
        }
    }

    Ok(endpoints)
}

#[derive(Debug, Clone, Copy)]
enum GraphQlOperationKind {
    Query,
    Mutation,
    Subscription,
}

struct RootTypeNames {
    query: String,
    mutation: String,
    subscription: String,
}

fn resolve_root_types<'a>(
    document: &graphql_parser::schema::Document<'a, &'a str>,
) -> RootTypeNames {
    for def in &document.definitions {
        if let graphql_parser::schema::Definition::SchemaDefinition(schema) = def {
            return RootTypeNames {
                query: schema.query.unwrap_or("Query").to_string(),
                mutation: schema.mutation.unwrap_or("Mutation").to_string(),
                subscription: schema.subscription.unwrap_or("Subscription").to_string(),
            };
        }
    }
    RootTypeNames {
        query: "Query".to_string(),
        mutation: "Mutation".to_string(),
        subscription: "Subscription".to_string(),
    }
}

fn classify_root_object(name: &str, root_types: &RootTypeNames) -> Option<GraphQlOperationKind> {
    if name == root_types.query {
        Some(GraphQlOperationKind::Query)
    } else if name == root_types.mutation {
        Some(GraphQlOperationKind::Mutation)
    } else if name == root_types.subscription {
        Some(GraphQlOperationKind::Subscription)
    } else {
        None
    }
}

fn collect_field_endpoints<'a>(
    fields: &[graphql_parser::schema::Field<'a, &'a str>],
    kind: GraphQlOperationKind,
    endpoints: &mut Vec<IntrospectedEndpoint>,
) {
    let label = match kind {
        GraphQlOperationKind::Query => "Query",
        GraphQlOperationKind::Mutation => "Mutation",
        GraphQlOperationKind::Subscription => "Subscription",
    };

    for field in fields {
        let parameters = field
            .arguments
            .iter()
            .map(|arg| EndpointParameter {
                name: arg.name.to_string(),
                location: ParameterLocation::Body,
                param_type: format_graphql_type(&arg.value_type),
                required: is_non_null_type(&arg.value_type),
            })
            .collect();

        endpoints.push(IntrospectedEndpoint {
            path: "/graphql".to_string(),
            method: "POST".to_string(),
            parameters,
            response_type: Some(format_graphql_type(&field.field_type)),
            description: Some(format!("{label}: {}", field.name)),
            security_schemes: Vec::new(),
            request_content_types: Vec::new(),
            response_status_codes: Vec::new(),
        });
    }
}

fn format_graphql_type<'a>(ty: &graphql_parser::schema::Type<'a, &'a str>) -> String {
    match ty {
        graphql_parser::schema::Type::NamedType(name) => name.to_string(),
        graphql_parser::schema::Type::ListType(inner) => {
            format!("[{}]", format_graphql_type(inner))
        }
        graphql_parser::schema::Type::NonNullType(inner) => {
            format!("{}!", format_graphql_type(inner))
        }
    }
}

fn is_non_null_type<'a>(ty: &graphql_parser::schema::Type<'a, &'a str>) -> bool {
    matches!(ty, graphql_parser::schema::Type::NonNullType(_))
}

#[derive(Deserialize)]
struct IntrospectionResponse {
    data: Option<IntrospectionData>,
}

#[derive(Deserialize)]
struct IntrospectionData {
    #[serde(rename = "__schema")]
    schema: IntrospectionSchema,
}

#[derive(Deserialize)]
struct IntrospectionSchema {
    #[serde(rename = "queryType")]
    query_type: Option<IntrospectionTypeName>,
    #[serde(rename = "mutationType")]
    mutation_type: Option<IntrospectionTypeName>,
    #[serde(rename = "subscriptionType")]
    subscription_type: Option<IntrospectionTypeName>,
    #[serde(default)]
    types: Vec<IntrospectionFullType>,
}

#[derive(Deserialize)]
struct IntrospectionTypeName {
    name: String,
}

#[derive(Deserialize)]
struct IntrospectionFullType {
    name: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    fields: Option<Vec<IntrospectionField>>,
}

#[derive(Deserialize)]
struct IntrospectionField {
    name: String,
    #[serde(default)]
    args: Vec<IntrospectionInputValue>,
    #[serde(rename = "type")]
    field_type: Option<IntrospectionTypeRef>,
}

#[derive(Deserialize)]
struct IntrospectionInputValue {
    name: String,
    #[serde(rename = "type")]
    value_type: Option<IntrospectionTypeRef>,
}

#[derive(Deserialize)]
struct IntrospectionTypeRef {
    kind: String,
    name: Option<String>,
    #[serde(rename = "ofType")]
    of_type: Option<Box<IntrospectionTypeRef>>,
}

fn introspection_json_to_sdl(json_content: &str) -> Result<String, IntrospectionError> {
    let response: IntrospectionResponse = serde_json::from_str(json_content)?;
    let data = response
        .data
        .ok_or_else(|| IntrospectionError::InvalidSchema("missing data field".to_string()))?;

    let mut sdl = String::new();
    emit_schema_definition(&data.schema, &mut sdl);

    for full_type in &data.schema.types {
        if full_type.name.starts_with("__") || is_builtin_scalar(&full_type.name) {
            continue;
        }
        emit_type_definition(full_type, &mut sdl);
    }

    Ok(sdl)
}

fn emit_schema_definition(schema: &IntrospectionSchema, sdl: &mut String) {
    let q = schema.query_type.as_ref().map(|t| t.name.as_str());
    let m = schema.mutation_type.as_ref().map(|t| t.name.as_str());
    let s = schema.subscription_type.as_ref().map(|t| t.name.as_str());

    if q.is_some() || m.is_some() || s.is_some() {
        sdl.push_str("schema {\n");
        if let Some(name) = q {
            sdl.push_str(&format!("  query: {name}\n"));
        }
        if let Some(name) = m {
            sdl.push_str(&format!("  mutation: {name}\n"));
        }
        if let Some(name) = s {
            sdl.push_str(&format!("  subscription: {name}\n"));
        }
        sdl.push_str("}\n\n");
    }
}

fn emit_type_definition(full_type: &IntrospectionFullType, sdl: &mut String) {
    if full_type.kind != "OBJECT" {
        return;
    }
    let Some(fields) = &full_type.fields else {
        return;
    };
    sdl.push_str(&format!("type {} {{\n", full_type.name));
    for field in fields {
        emit_field(field, sdl);
    }
    sdl.push_str("}\n\n");
}

fn emit_field(field: &IntrospectionField, sdl: &mut String) {
    sdl.push_str(&format!("  {}", field.name));
    if !field.args.is_empty() {
        sdl.push('(');
        let args: Vec<String> = field
            .args
            .iter()
            .map(|a| format!("{}: {}", a.name, type_ref_to_sdl(a.value_type.as_ref())))
            .collect();
        sdl.push_str(&args.join(", "));
        sdl.push(')');
    }
    let return_type = type_ref_to_sdl(field.field_type.as_ref());
    sdl.push_str(&format!(": {return_type}\n"));
}

fn type_ref_to_sdl(type_ref: Option<&IntrospectionTypeRef>) -> String {
    let Some(tr) = type_ref else {
        return "String".to_string();
    };
    match tr.kind.as_str() {
        "NON_NULL" => format!("{}!", type_ref_to_sdl(tr.of_type.as_deref())),
        "LIST" => format!("[{}]", type_ref_to_sdl(tr.of_type.as_deref())),
        _ => tr.name.clone().unwrap_or_else(|| "String".to_string()),
    }
}

fn is_builtin_scalar(name: &str) -> bool {
    matches!(name, "String" | "Int" | "Float" | "Boolean" | "ID")
}
