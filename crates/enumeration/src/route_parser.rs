use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredRoute {
    pub path_pattern: String,
    pub http_method: HttpMethod,
    pub handler_name: Option<String>,
    pub framework: Framework,
    pub source_file: String,
    pub line_number: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Options,
    Head,
    Any,
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Patch => "PATCH",
            Self::Options => "OPTIONS",
            Self::Head => "HEAD",
            Self::Any => "ANY",
        };
        write!(f, "{label}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Framework {
    Express,
    Flask,
    Django,
    FastApi,
    Spring,
    Rails,
    GoNet,
    Actix,
    Axum,
}

impl std::fmt::Display for Framework {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Express => "express",
            Self::Flask => "flask",
            Self::Django => "django",
            Self::FastApi => "fastapi",
            Self::Spring => "spring",
            Self::Rails => "rails",
            Self::GoNet => "go-net-http",
            Self::Actix => "actix-web",
            Self::Axum => "axum",
        };
        write!(f, "{label}")
    }
}

#[derive(Debug)]
pub enum RouteParseError {
    IoError(std::io::Error),
    UnsupportedFramework(String),
}

impl std::fmt::Display for RouteParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError(e) => write!(f, "io error: {e}"),
            Self::UnsupportedFramework(fw) => write!(f, "unsupported framework: {fw}"),
        }
    }
}

impl std::error::Error for RouteParseError {}

impl From<std::io::Error> for RouteParseError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

pub fn parse_routes_from_file(
    path: &Path,
    framework: Framework,
) -> Result<Vec<DiscoveredRoute>, RouteParseError> {
    let content = std::fs::read_to_string(path)?;
    let source_file = path.display().to_string();
    parse_routes_from_source(&content, &source_file, framework)
}

pub fn parse_routes_from_source(
    source: &str,
    source_file: &str,
    framework: Framework,
) -> Result<Vec<DiscoveredRoute>, RouteParseError> {
    match framework {
        Framework::Express => Ok(parse_express_routes(source, source_file)),
        Framework::Flask => Ok(parse_flask_routes(source, source_file)),
        Framework::FastApi => Ok(parse_fastapi_routes(source, source_file)),
        Framework::Django => Ok(parse_django_routes(source, source_file)),
        Framework::Spring => Ok(parse_spring_routes(source, source_file)),
        _ => Err(RouteParseError::UnsupportedFramework(
            framework.to_string(),
        )),
    }
}

fn parse_express_routes(source: &str, source_file: &str) -> Vec<DiscoveredRoute> {
    let mut routes = Vec::new();
    let method_patterns = [
        ("app.get(", HttpMethod::Get),
        ("app.post(", HttpMethod::Post),
        ("app.put(", HttpMethod::Put),
        ("app.delete(", HttpMethod::Delete),
        ("app.patch(", HttpMethod::Patch),
        ("app.use(", HttpMethod::Any),
        ("router.get(", HttpMethod::Get),
        ("router.post(", HttpMethod::Post),
        ("router.put(", HttpMethod::Put),
        ("router.delete(", HttpMethod::Delete),
        ("router.patch(", HttpMethod::Patch),
    ];

    for (line_num, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        for (pattern, method) in &method_patterns {
            if let Some(rest) = trimmed.strip_prefix(pattern)
                && let Some(path) = extract_quoted_string(rest)
            {
                routes.push(DiscoveredRoute {
                    path_pattern: path,
                    http_method: *method,
                    handler_name: extract_handler_name(rest),
                    framework: Framework::Express,
                    source_file: source_file.to_string(),
                    line_number: Some(line_num as u32 + 1),
                });
            }
        }
    }

    routes
}

fn parse_flask_routes(source: &str, source_file: &str) -> Vec<DiscoveredRoute> {
    let mut routes = Vec::new();

    let lines: Vec<&str> = source.lines().collect();
    for (line_num, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        if let Some(rest) = trimmed.strip_prefix("@app.route(")
            && let Some(path) = extract_quoted_string(rest)
        {
            let methods = extract_flask_methods(rest);
            let handler = lines
                .get(line_num + 1)
                .and_then(|next| extract_python_function_name(next));

            for method in methods {
                routes.push(DiscoveredRoute {
                    path_pattern: path.clone(),
                    http_method: method,
                    handler_name: handler.clone(),
                    framework: Framework::Flask,
                    source_file: source_file.to_string(),
                    line_number: Some(line_num as u32 + 1),
                });
            }
        }

        let flask_method_decorators = [
            ("@app.get(", HttpMethod::Get),
            ("@app.post(", HttpMethod::Post),
            ("@app.put(", HttpMethod::Put),
            ("@app.delete(", HttpMethod::Delete),
        ];

        for (pattern, method) in &flask_method_decorators {
            if let Some(rest) = trimmed.strip_prefix(pattern)
                && let Some(path) = extract_quoted_string(rest)
            {
                let handler = lines
                    .get(line_num + 1)
                    .and_then(|next| extract_python_function_name(next));

                routes.push(DiscoveredRoute {
                    path_pattern: path,
                    http_method: *method,
                    handler_name: handler,
                    framework: Framework::Flask,
                    source_file: source_file.to_string(),
                    line_number: Some(line_num as u32 + 1),
                });
            }
        }
    }

    routes
}

fn parse_fastapi_routes(source: &str, source_file: &str) -> Vec<DiscoveredRoute> {
    let mut routes = Vec::new();
    let lines: Vec<&str> = source.lines().collect();

    let decorators = [
        ("@app.get(", HttpMethod::Get),
        ("@app.post(", HttpMethod::Post),
        ("@app.put(", HttpMethod::Put),
        ("@app.delete(", HttpMethod::Delete),
        ("@app.patch(", HttpMethod::Patch),
        ("@router.get(", HttpMethod::Get),
        ("@router.post(", HttpMethod::Post),
        ("@router.put(", HttpMethod::Put),
        ("@router.delete(", HttpMethod::Delete),
        ("@router.patch(", HttpMethod::Patch),
    ];

    for (line_num, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        for (pattern, method) in &decorators {
            if let Some(rest) = trimmed.strip_prefix(pattern)
                && let Some(path) = extract_quoted_string(rest)
            {
                let handler = lines
                    .get(line_num + 1)
                    .and_then(|next| extract_python_function_name(next));

                routes.push(DiscoveredRoute {
                    path_pattern: path,
                    http_method: *method,
                    handler_name: handler,
                    framework: Framework::FastApi,
                    source_file: source_file.to_string(),
                    line_number: Some(line_num as u32 + 1),
                });
            }
        }
    }

    routes
}

fn parse_django_routes(source: &str, source_file: &str) -> Vec<DiscoveredRoute> {
    let mut routes = Vec::new();

    for (line_num, line) in source.lines().enumerate() {
        let trimmed = line.trim();

        if let Some(rest) = trimmed.strip_prefix("path(")
            && let Some(path) = extract_quoted_string(rest)
        {
            let handler = extract_django_view_name(rest);
            routes.push(DiscoveredRoute {
                path_pattern: format!("/{path}"),
                http_method: HttpMethod::Any,
                handler_name: handler,
                framework: Framework::Django,
                source_file: source_file.to_string(),
                line_number: Some(line_num as u32 + 1),
            });
        }
    }

    routes
}

fn parse_spring_routes(source: &str, source_file: &str) -> Vec<DiscoveredRoute> {
    let mut routes = Vec::new();

    let annotations = [
        ("@GetMapping(", HttpMethod::Get),
        ("@PostMapping(", HttpMethod::Post),
        ("@PutMapping(", HttpMethod::Put),
        ("@DeleteMapping(", HttpMethod::Delete),
        ("@PatchMapping(", HttpMethod::Patch),
        ("@RequestMapping(", HttpMethod::Any),
    ];

    for (line_num, line) in source.lines().enumerate() {
        let trimmed = line.trim();

        for (annotation, method) in &annotations {
            if let Some(rest) = trimmed.strip_prefix(annotation)
                && let Some(path) = extract_quoted_string(rest)
            {
                routes.push(DiscoveredRoute {
                    path_pattern: path,
                    http_method: *method,
                    handler_name: None,
                    framework: Framework::Spring,
                    source_file: source_file.to_string(),
                    line_number: Some(line_num as u32 + 1),
                });
            }
        }
    }

    routes
}

fn extract_quoted_string(s: &str) -> Option<String> {
    let s = s.trim();
    for quote in ['"', '\''] {
        if s.starts_with(quote)
            && let Some(end) = s[1..].find(quote)
        {
            return Some(s[1..end + 1].to_string());
        }
    }
    None
}

fn extract_handler_name(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.split(',').collect();
    if parts.len() >= 2 {
        let handler = parts[1]
            .trim()
            .trim_end_matches(';')
            .trim_end_matches(')')
            .trim();
        if !handler.is_empty() {
            return Some(handler.to_string());
        }
    }
    None
}

fn extract_python_function_name(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if let Some(rest) = trimmed.strip_prefix("def ")
        && let Some(paren) = rest.find('(')
    {
        let name = rest[..paren].trim();
        if !name.is_empty() {
            return Some(name.to_string());
        }
    }
    if let Some(rest) = trimmed.strip_prefix("async def ")
        && let Some(paren) = rest.find('(')
    {
        let name = rest[..paren].trim();
        if !name.is_empty() {
            return Some(name.to_string());
        }
    }
    None
}

fn extract_flask_methods(decorator: &str) -> Vec<HttpMethod> {
    if let Some(methods_start) = decorator.find("methods=") {
        let rest = &decorator[methods_start + 8..];
        let mut methods = Vec::new();
        for method_name in ["GET", "POST", "PUT", "DELETE", "PATCH"] {
            if rest.contains(method_name) {
                methods.push(match method_name {
                    "GET" => HttpMethod::Get,
                    "POST" => HttpMethod::Post,
                    "PUT" => HttpMethod::Put,
                    "DELETE" => HttpMethod::Delete,
                    "PATCH" => HttpMethod::Patch,
                    _ => unreachable!(),
                });
            }
        }
        if methods.is_empty() {
            vec![HttpMethod::Get]
        } else {
            methods
        }
    } else {
        vec![HttpMethod::Get]
    }
}

fn extract_django_view_name(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.split(',').collect();
    if parts.len() >= 2 {
        let view = parts[1]
            .trim()
            .trim_end_matches(')')
            .trim_end_matches(',')
            .trim();
        if !view.is_empty() {
            return Some(view.to_string());
        }
    }
    None
}
