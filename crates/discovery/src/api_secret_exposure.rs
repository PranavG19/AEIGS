/// API secret exposure detector.
///
/// Finds leaked API secrets in public places: GitHub code search patterns,
/// GitLab snippets, npm package contents, Docker Hub image layers,
/// Postman public workspaces, and Swagger UI with embedded auth tokens.
use regex::Regex;

/// Source where a secret might be exposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExposureSource {
    GitHubCodeSearch,
    GitLabSnippets,
    NpmPackageContents,
    DockerHubImageLayers,
    PostmanPublicWorkspaces,
    SwaggerUiEmbeddedTokens,
}

impl std::fmt::Display for ExposureSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GitHubCodeSearch => write!(f, "GitHub Code Search"),
            Self::GitLabSnippets => write!(f, "GitLab Snippets"),
            Self::NpmPackageContents => write!(f, "npm Package Contents"),
            Self::DockerHubImageLayers => write!(f, "Docker Hub Image Layers"),
            Self::PostmanPublicWorkspaces => write!(f, "Postman Public Workspaces"),
            Self::SwaggerUiEmbeddedTokens => write!(f, "Swagger UI Embedded Tokens"),
        }
    }
}

impl ExposureSource {
    pub fn all() -> &'static [ExposureSource] {
        &[
            Self::GitHubCodeSearch,
            Self::GitLabSnippets,
            Self::NpmPackageContents,
            Self::DockerHubImageLayers,
            Self::PostmanPublicWorkspaces,
            Self::SwaggerUiEmbeddedTokens,
        ]
    }
}

/// Type of secret detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecretType {
    AwsAccessKey,
    AwsSecretKey,
    GcpServiceAccountKey,
    AzureStorageKey,
    GitHubToken,
    GitLabToken,
    SlackToken,
    SlackWebhook,
    StripeSecretKey,
    StripePublishableKey,
    TwilioApiKey,
    SendGridApiKey,
    MailgunApiKey,
    HerokuApiKey,
    JwtToken,
    GenericApiKey,
    GenericSecret,
    PrivateKey,
    DatabaseUrl,
    OAuthClientSecret,
    FirebaseKey,
    GoogleMapsKey,
    AlgoliaApiKey,
    DigitalOceanToken,
}

impl std::fmt::Display for SecretType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AwsAccessKey => write!(f, "AWS Access Key"),
            Self::AwsSecretKey => write!(f, "AWS Secret Key"),
            Self::GcpServiceAccountKey => write!(f, "GCP Service Account Key"),
            Self::AzureStorageKey => write!(f, "Azure Storage Key"),
            Self::GitHubToken => write!(f, "GitHub Token"),
            Self::GitLabToken => write!(f, "GitLab Token"),
            Self::SlackToken => write!(f, "Slack Token"),
            Self::SlackWebhook => write!(f, "Slack Webhook"),
            Self::StripeSecretKey => write!(f, "Stripe Secret Key"),
            Self::StripePublishableKey => write!(f, "Stripe Publishable Key"),
            Self::TwilioApiKey => write!(f, "Twilio API Key"),
            Self::SendGridApiKey => write!(f, "SendGrid API Key"),
            Self::MailgunApiKey => write!(f, "Mailgun API Key"),
            Self::HerokuApiKey => write!(f, "Heroku API Key"),
            Self::JwtToken => write!(f, "JWT Token"),
            Self::GenericApiKey => write!(f, "Generic API Key"),
            Self::GenericSecret => write!(f, "Generic Secret"),
            Self::PrivateKey => write!(f, "Private Key"),
            Self::DatabaseUrl => write!(f, "Database URL"),
            Self::OAuthClientSecret => write!(f, "OAuth Client Secret"),
            Self::FirebaseKey => write!(f, "Firebase Key"),
            Self::GoogleMapsKey => write!(f, "Google Maps Key"),
            Self::AlgoliaApiKey => write!(f, "Algolia API Key"),
            Self::DigitalOceanToken => write!(f, "DigitalOcean Token"),
        }
    }
}

/// Severity of a leaked secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecretSeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl SecretSeverity {
    pub fn score(&self) -> f64 {
        match self {
            Self::Informational => 0.1,
            Self::Low => 0.3,
            Self::Medium => 0.5,
            Self::High => 0.8,
            Self::Critical => 1.0,
        }
    }
}

/// Map a secret type to its severity.
pub fn severity_for_secret(secret_type: SecretType) -> SecretSeverity {
    match secret_type {
        SecretType::AwsAccessKey | SecretType::AwsSecretKey => SecretSeverity::Critical,
        SecretType::GcpServiceAccountKey => SecretSeverity::Critical,
        SecretType::AzureStorageKey => SecretSeverity::Critical,
        SecretType::PrivateKey => SecretSeverity::Critical,
        SecretType::DatabaseUrl => SecretSeverity::Critical,
        SecretType::StripeSecretKey => SecretSeverity::Critical,
        SecretType::OAuthClientSecret => SecretSeverity::High,
        SecretType::GitHubToken => SecretSeverity::High,
        SecretType::GitLabToken => SecretSeverity::High,
        SecretType::SlackToken => SecretSeverity::High,
        SecretType::TwilioApiKey => SecretSeverity::High,
        SecretType::SendGridApiKey => SecretSeverity::High,
        SecretType::MailgunApiKey => SecretSeverity::High,
        SecretType::HerokuApiKey => SecretSeverity::High,
        SecretType::DigitalOceanToken => SecretSeverity::High,
        SecretType::JwtToken => SecretSeverity::High,
        SecretType::FirebaseKey => SecretSeverity::Medium,
        SecretType::GoogleMapsKey => SecretSeverity::Medium,
        SecretType::AlgoliaApiKey => SecretSeverity::Medium,
        SecretType::SlackWebhook => SecretSeverity::Medium,
        SecretType::StripePublishableKey => SecretSeverity::Low,
        SecretType::GenericApiKey => SecretSeverity::Medium,
        SecretType::GenericSecret => SecretSeverity::Medium,
    }
}

/// A regex pattern paired with its secret classification.
pub struct SecretPattern {
    pub secret_type: SecretType,
    pub pattern: &'static str,
    pub description: &'static str,
}

/// All built-in secret detection patterns.
pub const SECRET_PATTERNS: &[SecretPattern] = &[
    SecretPattern {
        secret_type: SecretType::AwsAccessKey,
        pattern: r"(?:AKIA|ASIA)[0-9A-Z]{16}",
        description: "AWS Access Key ID (starts with AKIA or ASIA)",
    },
    SecretPattern {
        secret_type: SecretType::AwsSecretKey,
        pattern: r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*[A-Za-z0-9/+=]{40}",
        description: "AWS Secret Access Key assignment",
    },
    SecretPattern {
        secret_type: SecretType::GcpServiceAccountKey,
        pattern: r#""type"\s*:\s*"service_account""#,
        description: "GCP service account JSON key file",
    },
    SecretPattern {
        secret_type: SecretType::AzureStorageKey,
        pattern: r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",
        description: "Azure Storage connection string",
    },
    SecretPattern {
        secret_type: SecretType::GitHubToken,
        pattern: r"gh[pousr]_[A-Za-z0-9_]{36,255}",
        description: "GitHub personal access token or fine-grained token",
    },
    SecretPattern {
        secret_type: SecretType::GitLabToken,
        pattern: r"glpat-[A-Za-z0-9\-_]{20,}",
        description: "GitLab personal access token",
    },
    SecretPattern {
        secret_type: SecretType::SlackToken,
        pattern: r"xox[bporas]-[0-9]{10,}-[A-Za-z0-9\-]+",
        description: "Slack bot, user, or app token",
    },
    SecretPattern {
        secret_type: SecretType::SlackWebhook,
        pattern: r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
        description: "Slack incoming webhook URL",
    },
    SecretPattern {
        secret_type: SecretType::StripeSecretKey,
        pattern: r"sk_live_[A-Za-z0-9]{24,}",
        description: "Stripe live secret key",
    },
    SecretPattern {
        secret_type: SecretType::StripePublishableKey,
        pattern: r"pk_live_[A-Za-z0-9]{24,}",
        description: "Stripe live publishable key",
    },
    SecretPattern {
        secret_type: SecretType::TwilioApiKey,
        pattern: r"SK[0-9a-fA-F]{32}",
        description: "Twilio API key",
    },
    SecretPattern {
        secret_type: SecretType::SendGridApiKey,
        pattern: r"SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}",
        description: "SendGrid API key",
    },
    SecretPattern {
        secret_type: SecretType::HerokuApiKey,
        pattern: r"(?i)heroku[_\-]?api[_\-]?key\s*[=:]\s*[0-9a-fA-F\-]{36}",
        description: "Heroku API key",
    },
    SecretPattern {
        secret_type: SecretType::PrivateKey,
        pattern: r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        description: "PEM-encoded private key header",
    },
    SecretPattern {
        secret_type: SecretType::JwtToken,
        pattern: r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]+",
        description: "JSON Web Token (three-part base64url)",
    },
    SecretPattern {
        secret_type: SecretType::DatabaseUrl,
        pattern: r#"(?i)(?:postgres|mysql|mongodb|redis)://[^\s"'<>]+:[^\s"'<>]+@[^\s"'<>]+"#,
        description: "Database connection URL with credentials",
    },
    SecretPattern {
        secret_type: SecretType::FirebaseKey,
        pattern: r"AIza[0-9A-Za-z\-_]{35}",
        description: "Firebase / Google API key",
    },
    SecretPattern {
        secret_type: SecretType::MailgunApiKey,
        pattern: r"key-[0-9a-zA-Z]{32}",
        description: "Mailgun API key",
    },
    SecretPattern {
        secret_type: SecretType::DigitalOceanToken,
        pattern: r"dop_v1_[a-f0-9]{64}",
        description: "DigitalOcean personal access token",
    },
    SecretPattern {
        secret_type: SecretType::AlgoliaApiKey,
        pattern: r"(?i)algolia[_\-]?api[_\-]?key\s*[=:]\s*[a-f0-9]{32}",
        description: "Algolia API key",
    },
    SecretPattern {
        secret_type: SecretType::GenericApiKey,
        pattern: r#"(?i)(?:api[_\-]?key|apikey)\s*[=:]\s*['"][A-Za-z0-9\-_]{16,}['"]"#,
        description: "Generic API key assignment in code",
    },
    SecretPattern {
        secret_type: SecretType::GenericSecret,
        pattern: r#"(?i)(?:secret|password|passwd|token)\s*[=:]\s*['"][^\s'"]{8,}['"]"#,
        description: "Generic secret/password/token assignment",
    },
    SecretPattern {
        secret_type: SecretType::OAuthClientSecret,
        pattern: r#"(?i)client[_\-]?secret\s*[=:]\s*['"][A-Za-z0-9\-_]{16,}['"]"#,
        description: "OAuth client secret",
    },
    SecretPattern {
        secret_type: SecretType::GoogleMapsKey,
        pattern: r"AIza[0-9A-Za-z\-_]{35}",
        description: "Google Maps API key (same format as Firebase)",
    },
];

/// Compile all secret patterns into regex matchers.
pub fn compile_patterns() -> Vec<(SecretType, Regex, &'static str)> {
    SECRET_PATTERNS
        .iter()
        .filter_map(|sp| {
            Regex::new(sp.pattern)
                .ok()
                .map(|re| (sp.secret_type, re, sp.description))
        })
        .collect()
}

/// A single match of a secret in text content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMatch {
    pub secret_type: SecretType,
    pub matched_text: String,
    pub description: String,
    pub start: usize,
    pub end: usize,
}

/// Scan a text blob for all matching secret patterns. Returns de-duplicated matches.
pub fn scan_text_for_secrets(text: &str) -> Vec<SecretMatch> {
    let compiled = compile_patterns();
    let mut matches = Vec::new();
    let mut seen_spans: std::collections::HashSet<(usize, usize)> =
        std::collections::HashSet::new();

    for (secret_type, re, description) in &compiled {
        for m in re.find_iter(text) {
            let span = (m.start(), m.end());
            if seen_spans.contains(&span) {
                continue;
            }
            seen_spans.insert(span);
            matches.push(SecretMatch {
                secret_type: *secret_type,
                matched_text: m.as_str().to_string(),
                description: description.to_string(),
                start: m.start(),
                end: m.end(),
            });
        }
    }
    matches
}

/// GitHub code search query patterns for finding secrets related to a domain.
pub fn github_search_queries(domain: &str) -> Vec<String> {
    vec![
        format!("\"{}\" password", domain),
        format!("\"{}\" secret", domain),
        format!("\"{}\" api_key", domain),
        format!("\"{}\" apikey", domain),
        format!("\"{}\" token", domain),
        format!("\"{}\" AWS_SECRET_ACCESS_KEY", domain),
        format!("\"{}\" PRIVATE KEY", domain),
        format!("\"{}\" client_secret", domain),
        format!("\"{}\" jdbc:", domain),
        format!("\"{}\" mongodb://", domain),
        format!("\"{}\" redis://", domain),
        format!("\"{}\" postgres://", domain),
    ]
}

/// GitHub code search URL for a given query.
pub fn github_search_url(query: &str) -> String {
    let encoded = query.replace(' ', "+");
    format!("https://github.com/search?q={}&type=code", encoded)
}

/// GitLab snippet search URL for a domain.
pub fn gitlab_snippet_search_url(domain: &str) -> String {
    let encoded = domain.replace(' ', "+");
    format!(
        "https://gitlab.com/search?search={}&scope=snippet_titles",
        encoded
    )
}

/// npm registry search URL for packages related to a domain.
pub fn npm_search_url(domain: &str) -> String {
    format!("https://www.npmjs.com/search?q={}", domain)
}

/// Docker Hub search URL for images related to a domain/org.
pub fn dockerhub_search_url(org_name: &str) -> String {
    format!(
        "https://hub.docker.com/v2/repositories/{}/?page_size=100",
        org_name
    )
}

/// Postman public workspace search URL.
pub fn postman_search_url(domain: &str) -> String {
    format!(
        "https://www.postman.com/search?q={}&type=workspaces&queryIndices=runtime_combined",
        domain
    )
}

/// Common Swagger/OpenAPI UI endpoints to check for embedded tokens.
pub const SWAGGER_ENDPOINTS: &[&str] = &[
    "/swagger-ui.html",
    "/swagger-ui/index.html",
    "/api-docs",
    "/api/docs",
    "/swagger.json",
    "/swagger.yaml",
    "/openapi.json",
    "/openapi.yaml",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api/swagger.json",
    "/docs",
    "/redoc",
];

/// Docker image layer commands that commonly leak secrets.
pub const DOCKER_LEAK_PATTERNS: &[&str] = &[
    "ENV AWS_ACCESS_KEY_ID",
    "ENV AWS_SECRET_ACCESS_KEY",
    "ENV DATABASE_URL",
    "ENV API_KEY",
    "ENV SECRET_KEY",
    "ENV PRIVATE_KEY",
    "COPY .env",
    "COPY credentials",
    "COPY id_rsa",
    "COPY .aws",
    "ADD .env",
    "ADD credentials",
    "ADD id_rsa",
];

/// A finding from the API secret exposure scan.
#[derive(Debug, Clone, PartialEq)]
pub struct SecretExposureFinding {
    pub source: ExposureSource,
    pub secret_type: SecretType,
    pub severity: SecretSeverity,
    pub location: String,
    pub detail: String,
    pub matched_text: Option<String>,
}

/// Build a finding from a secret match and its source context.
pub fn finding_from_match(
    source: ExposureSource,
    secret_match: &SecretMatch,
    location: &str,
) -> SecretExposureFinding {
    SecretExposureFinding {
        source,
        secret_type: secret_match.secret_type,
        severity: severity_for_secret(secret_match.secret_type),
        location: location.to_string(),
        detail: format!(
            "{} found via {}: {}",
            secret_match.secret_type, source, secret_match.description
        ),
        matched_text: Some(secret_match.matched_text.clone()),
    }
}

/// Check text content from a Swagger/OpenAPI endpoint for embedded secrets.
pub fn check_swagger_content(content: &str) -> Vec<SecretMatch> {
    scan_text_for_secrets(content)
}

/// Check Docker image layer history for leaked secrets.
pub fn check_docker_layer_history(layer_commands: &[&str]) -> Vec<String> {
    let mut leaked = Vec::new();
    for cmd in layer_commands {
        for pattern in DOCKER_LEAK_PATTERNS {
            if cmd.contains(pattern) {
                leaked.push(format!(
                    "Docker layer leaks secret: {} in '{}'",
                    pattern, cmd
                ));
            }
        }
    }
    leaked
}

/// Scanner combining all sources for a target domain.
pub struct ApiSecretExposureScanner {
    pub domain: String,
    pub sources: Vec<ExposureSource>,
}

impl ApiSecretExposureScanner {
    pub fn new(domain: &str) -> Self {
        Self {
            domain: domain.to_string(),
            sources: ExposureSource::all().to_vec(),
        }
    }

    pub fn with_sources(mut self, sources: Vec<ExposureSource>) -> Self {
        self.sources = sources;
        self
    }

    /// Generate all GitHub search queries for this domain.
    pub fn github_queries(&self) -> Vec<String> {
        github_search_queries(&self.domain)
    }

    /// Generate all search URLs for the configured sources.
    pub fn search_urls(&self) -> Vec<(ExposureSource, String)> {
        let mut urls = Vec::new();
        for source in &self.sources {
            match source {
                ExposureSource::GitHubCodeSearch => {
                    for q in github_search_queries(&self.domain) {
                        urls.push((*source, github_search_url(&q)));
                    }
                }
                ExposureSource::GitLabSnippets => {
                    urls.push((*source, gitlab_snippet_search_url(&self.domain)));
                }
                ExposureSource::NpmPackageContents => {
                    urls.push((*source, npm_search_url(&self.domain)));
                }
                ExposureSource::DockerHubImageLayers => {
                    urls.push((*source, dockerhub_search_url(&self.domain)));
                }
                ExposureSource::PostmanPublicWorkspaces => {
                    urls.push((*source, postman_search_url(&self.domain)));
                }
                ExposureSource::SwaggerUiEmbeddedTokens => {
                    for endpoint in SWAGGER_ENDPOINTS {
                        urls.push((*source, format!("https://{}{}", self.domain, endpoint)));
                    }
                }
            }
        }
        urls
    }

    /// Generate Swagger endpoints to check.
    pub fn swagger_urls(&self) -> Vec<String> {
        SWAGGER_ENDPOINTS
            .iter()
            .map(|e| format!("https://{}{}", self.domain, e))
            .collect()
    }
}
