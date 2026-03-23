use crate::recon_client;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

#[derive(Debug, Clone, PartialEq)]
pub enum DeserializationIssue {
    NodeSerializeRce,
    JsYamlUnsafeLoad,
    EvalCall,
    FunctionConstructor,
    TemplateLiteralInjection,
    DynamicRequire,
    JavaSerializedContentType { content_type: String },
    PhpSerializedBody { indicator: String },
    PythonPickleContentType,
    DotNetViewState { encrypted: bool },
    XmlRpcEndpoint,
    JavaRmiEndpoint,
    AcceptsSerializedInput { content_type: String },
    JsonParseReviver,
}

impl std::fmt::Display for DeserializationIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NodeSerializeRce => write!(f, "node_serialize_rce"),
            Self::JsYamlUnsafeLoad => write!(f, "js_yaml_unsafe_load"),
            Self::EvalCall => write!(f, "eval_call"),
            Self::FunctionConstructor => write!(f, "function_constructor"),
            Self::TemplateLiteralInjection => write!(f, "template_literal_injection"),
            Self::DynamicRequire => write!(f, "dynamic_require"),
            Self::JavaSerializedContentType { content_type } => {
                write!(f, "java_serialized_ct:{content_type}")
            }
            Self::PhpSerializedBody { indicator } => {
                write!(f, "php_serialized:{indicator}")
            }
            Self::PythonPickleContentType => write!(f, "python_pickle_ct"),
            Self::DotNetViewState { encrypted } => {
                write!(f, "dotnet_viewstate:encrypted={encrypted}")
            }
            Self::XmlRpcEndpoint => write!(f, "xmlrpc_endpoint"),
            Self::JavaRmiEndpoint => write!(f, "java_rmi_endpoint"),
            Self::AcceptsSerializedInput { content_type } => {
                write!(f, "accepts_serialized:{content_type}")
            }
            Self::JsonParseReviver => write!(f, "json_parse_reviver"),
        }
    }
}

pub fn deserialization_severity(issue: &DeserializationIssue) -> f64 {
    match issue {
        DeserializationIssue::NodeSerializeRce => 9.5,
        DeserializationIssue::JavaRmiEndpoint => 9.0,
        DeserializationIssue::EvalCall => 8.5,
        DeserializationIssue::FunctionConstructor => 8.5,
        DeserializationIssue::JsYamlUnsafeLoad => 8.0,
        DeserializationIssue::JavaSerializedContentType { .. } => 8.0,
        DeserializationIssue::PythonPickleContentType => 8.0,
        DeserializationIssue::AcceptsSerializedInput { .. } => 7.5,
        DeserializationIssue::DynamicRequire => 7.0,
        DeserializationIssue::PhpSerializedBody { .. } => 7.0,
        DeserializationIssue::TemplateLiteralInjection => 7.0,
        DeserializationIssue::JsonParseReviver => 6.5,
        DeserializationIssue::DotNetViewState { encrypted: false } => 6.5,
        DeserializationIssue::XmlRpcEndpoint => 5.0,
        DeserializationIssue::DotNetViewState { encrypted: true } => 4.0,
    }
}

const JAVA_SERIAL_CONTENT_TYPES: &[&str] = &[
    "application/x-java-serialized-object",
    "application/x-java-object",
];

const PHP_SERIAL_PATTERNS: &[&str] = &["a:0:{}", "O:8:\"stdClass\"", "s:0:\"\";", "a:", "O:"];

const XMLRPC_PATHS: &[&str] = &["/xmlrpc.php", "/xmlrpc", "/RPC2", "/rpc"];

const RMI_PATHS: &[&str] = &["/invoker/JMXInvokerServlet", "/jmx-console", "/web-console"];

pub fn audit_deserialization(target: &str) -> Vec<DeserializationIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };

    let mut issues = Vec::new();

    if let Ok(resp) = client.get(target).send() {
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let body = resp.text().unwrap_or_default();
        issues.extend(analyze_deserialization(&body));
        issues.extend(analyze_content_type_headers(&ct, &body));
    }

    for path in XMLRPC_PATHS {
        let url = format!("{}{}", target.trim_end_matches('/'), path);
        if let Ok(resp) = client.get(&url).send()
            && resp.status().is_success()
        {
            let body = resp.text().unwrap_or_default();
            if body.contains("xml-rpc")
                || body.contains("XML-RPC")
                || body.contains("<methodResponse")
            {
                issues.push(DeserializationIssue::XmlRpcEndpoint);
                break;
            }
        }
    }

    for path in RMI_PATHS {
        let url = format!("{}{}", target.trim_end_matches('/'), path);
        if let Ok(resp) = client.get(&url).send()
            && resp.status().is_success()
        {
            issues.push(DeserializationIssue::JavaRmiEndpoint);
            break;
        }
    }

    issues
}

pub fn analyze_deserialization(body: &str) -> Vec<DeserializationIssue> {
    let mut issues = Vec::new();

    if body.contains("_$$ND_FUNC$$_") || body.contains("node-serialize") {
        issues.push(DeserializationIssue::NodeSerializeRce);
    }

    if body.contains("yaml.load(") && !body.contains("yaml.safeLoad(") {
        issues.push(DeserializationIssue::JsYamlUnsafeLoad);
    }

    if body.contains("eval(") {
        issues.push(DeserializationIssue::EvalCall);
    }

    if body.contains("new Function(") || body.contains("Function(") {
        issues.push(DeserializationIssue::FunctionConstructor);
    }

    if body.contains("${") && body.contains("`") {
        issues.push(DeserializationIssue::TemplateLiteralInjection);
    }

    if body.contains("require(") && !body.contains("require('") && !body.contains("require(\"") {
        issues.push(DeserializationIssue::DynamicRequire);
    }

    if body.contains("JSON.parse(") && body.contains("reviver") {
        issues.push(DeserializationIssue::JsonParseReviver);
    }

    issues
}

pub fn analyze_content_type_headers(content_type: &str, body: &str) -> Vec<DeserializationIssue> {
    let mut issues = Vec::new();

    for &java_ct in JAVA_SERIAL_CONTENT_TYPES {
        if content_type.contains(java_ct) {
            issues.push(DeserializationIssue::JavaSerializedContentType {
                content_type: content_type.to_string(),
            });
            break;
        }
    }

    if content_type.contains("application/python-pickle") {
        issues.push(DeserializationIssue::PythonPickleContentType);
    }

    if content_type.contains("application/x-httpd-php") || content_type.contains("text/html") {
        for &pattern in PHP_SERIAL_PATTERNS {
            if body.contains(pattern) {
                issues.push(DeserializationIssue::PhpSerializedBody {
                    indicator: pattern.to_string(),
                });
                break;
            }
        }
    }

    if body.contains("__VIEWSTATE") {
        let encrypted = body.contains("__VIEWSTATEENCRYPTED");
        issues.push(DeserializationIssue::DotNetViewState { encrypted });
    }

    issues
}

pub fn analyze_accepts_serialized(
    accept_header: &str,
    content_type_header: &str,
) -> Vec<DeserializationIssue> {
    let mut issues = Vec::new();

    for &java_ct in JAVA_SERIAL_CONTENT_TYPES {
        if accept_header.contains(java_ct) || content_type_header.contains(java_ct) {
            issues.push(DeserializationIssue::AcceptsSerializedInput {
                content_type: java_ct.to_string(),
            });
        }
    }

    if accept_header.contains("application/x-php-serialized")
        || content_type_header.contains("application/x-php-serialized")
    {
        issues.push(DeserializationIssue::AcceptsSerializedInput {
            content_type: "application/x-php-serialized".to_string(),
        });
    }

    if accept_header.contains("application/python-pickle")
        || content_type_header.contains("application/python-pickle")
    {
        issues.push(DeserializationIssue::AcceptsSerializedInput {
            content_type: "application/python-pickle".to_string(),
        });
    }

    issues
}

pub fn deserialization_to_operations(
    issues: &[DeserializationIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InsecureDeserialization,
                deserialization_severity(issue),
                0.8,
            )
        })
        .collect()
}
