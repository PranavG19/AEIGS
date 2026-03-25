use aegis_protocol::finding::VulnerabilityClass;
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize)]
pub struct AttackMapping {
    pub vulnerability_class: String,
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
    pub procedure_description: String,
    pub detection_recommendations: Vec<String>,
    pub severity: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AttackTechnique {
    pub id: String,
    pub name: String,
    pub tactic: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct NavigatorLayer {
    pub name: String,
    pub versions: NavigatorVersions,
    pub domain: String,
    pub description: String,
    pub techniques: Vec<NavigatorTechnique>,
    pub gradient: NavigatorGradient,
}

#[derive(Debug, Clone, Serialize)]
pub struct NavigatorVersions {
    pub attack: String,
    pub navigator: String,
    pub layer: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct NavigatorTechnique {
    #[serde(rename = "techniqueID")]
    pub technique_id: String,
    pub tactic: String,
    pub score: u32,
    pub color: String,
    pub comment: String,
    pub enabled: bool,
    #[serde(rename = "showSubtechniques")]
    pub show_subtechniques: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct NavigatorGradient {
    pub colors: Vec<String>,
    #[serde(rename = "minValue")]
    pub min_value: u32,
    #[serde(rename = "maxValue")]
    pub max_value: u32,
}

/// Returns the ATT&CK technique metadata for a vulnerability class.
pub fn technique_for(class: &VulnerabilityClass) -> AttackTechnique {
    let (id, name, tactic) = match class {
        VulnerabilityClass::SqlInjection => (
            "T1190",
            "Exploit Public-Facing Application",
            "initial-access",
        ),
        VulnerabilityClass::CrossSiteScripting => {
            ("T1189", "Drive-by Compromise", "initial-access")
        }
        VulnerabilityClass::CommandInjection => {
            ("T1059", "Command and Scripting Interpreter", "execution")
        }
        VulnerabilityClass::PathTraversal => ("T1083", "File and Directory Discovery", "discovery"),
        VulnerabilityClass::ServerSideRequestForgery => ("T1090", "Proxy", "command-and-control"),
        VulnerabilityClass::InsecureDeserialization => (
            "T1190",
            "Exploit Public-Facing Application",
            "initial-access",
        ),
        VulnerabilityClass::BrokenAuthentication => ("T1078", "Valid Accounts", "defense-evasion"),
        VulnerabilityClass::BrokenAuthorization => (
            "T1548",
            "Abuse Elevation Control Mechanism",
            "privilege-escalation",
        ),
        VulnerabilityClass::SecurityMisconfiguration => {
            ("T1574", "Hijack Execution Flow", "persistence")
        }
        VulnerabilityClass::SensitiveDataExposure => {
            ("T1005", "Data from Local System", "collection")
        }
        VulnerabilityClass::ServerSideTemplateInjection => {
            ("T1221", "Template Injection", "defense-evasion")
        }
        VulnerabilityClass::HeaderInjection => {
            ("T1071", "Application Layer Protocol", "command-and-control")
        }
        VulnerabilityClass::OpenRedirect => ("T1204", "User Execution", "execution"),
        VulnerabilityClass::CrlfInjection => {
            ("T1071", "Application Layer Protocol", "command-and-control")
        }
        VulnerabilityClass::KnownVulnerableDependency => {
            ("T1195", "Supply Chain Compromise", "initial-access")
        }
        VulnerabilityClass::InsufficientInputValidation => (
            "T1190",
            "Exploit Public-Facing Application",
            "initial-access",
        ),
        VulnerabilityClass::NoSqlInjection => (
            "T1190",
            "Exploit Public-Facing Application",
            "initial-access",
        ),
        VulnerabilityClass::XmlExternalEntity => (
            "T1190",
            "Exploit Public-Facing Application",
            "initial-access",
        ),
        VulnerabilityClass::CrossOriginMisconfiguration => {
            ("T1189", "Drive-by Compromise", "initial-access")
        }
        VulnerabilityClass::MissingSecurityHeader => {
            ("T1574", "Hijack Execution Flow", "persistence")
        }
        VulnerabilityClass::JwtVulnerability => ("T1078", "Valid Accounts", "defense-evasion"),
        VulnerabilityClass::HttpRequestSmuggling => {
            ("T1071", "Application Layer Protocol", "command-and-control")
        }
        VulnerabilityClass::RaceCondition => (
            "T1190",
            "Exploit Public-Facing Application",
            "initial-access",
        ),
        VulnerabilityClass::SubdomainTakeover => {
            ("T1584", "Compromise Infrastructure", "resource-development")
        }
        VulnerabilityClass::PrototypePollution => (
            "T1190",
            "Exploit Public-Facing Application",
            "initial-access",
        ),
        VulnerabilityClass::GraphQlAbuse => (
            "T1190",
            "Exploit Public-Facing Application",
            "initial-access",
        ),
        VulnerabilityClass::CloudMisconfiguration => {
            ("T1574", "Hijack Execution Flow", "persistence")
        }
        VulnerabilityClass::Clickjacking => ("T1189", "Drive-by Compromise", "initial-access"),
        VulnerabilityClass::CachePoisoning => {
            ("T1557", "Adversary-in-the-Middle", "credential-access")
        }
        VulnerabilityClass::HostHeaderInjection => {
            ("T1071", "Application Layer Protocol", "command-and-control")
        }
        VulnerabilityClass::InsecureDirectObjectReference => (
            "T1548",
            "Abuse Elevation Control Mechanism",
            "privilege-escalation",
        ),
        VulnerabilityClass::InformationDisclosure => {
            ("T1005", "Data from Local System", "collection")
        }
        VulnerabilityClass::WeakCryptography => ("T1600", "Weaken Encryption", "defense-evasion"),
        VulnerabilityClass::MassAssignment => (
            "T1190",
            "Exploit Public-Facing Application",
            "initial-access",
        ),
    };
    AttackTechnique {
        id: id.to_string(),
        name: name.to_string(),
        tactic: tactic.to_string(),
    }
}

fn procedure_description_for(class: &VulnerabilityClass) -> String {
    match class {
        VulnerabilityClass::SqlInjection => {
            "Attacker injects malicious SQL statements through user-controllable input to manipulate backend database queries. \
             This enables unauthorized data extraction, modification, or deletion from the application's data store."
        }
        VulnerabilityClass::CrossSiteScripting => {
            "Attacker injects client-side scripts into web pages viewed by other users, hijacking sessions or defacing content. \
             Reflected and stored variants enable credential theft and phishing through the trusted application domain."
        }
        VulnerabilityClass::CommandInjection => {
            "Attacker injects operating system commands through application input fields that pass data to a shell interpreter. \
             Successful exploitation grants arbitrary command execution with the privileges of the web server process."
        }
        VulnerabilityClass::PathTraversal => {
            "Attacker manipulates file path parameters to traverse directory boundaries and access files outside the intended scope. \
             This reveals sensitive configuration files, source code, and system credentials stored on the server filesystem."
        }
        VulnerabilityClass::ServerSideRequestForgery => {
            "Attacker coerces the server into making HTTP requests to internal services or cloud metadata endpoints. \
             SSRF bypasses network segmentation, enabling access to internal APIs, databases, and cloud instance credentials."
        }
        VulnerabilityClass::InsecureDeserialization => {
            "Attacker supplies crafted serialized objects that execute arbitrary code during the deserialization process. \
             Gadget chains in the application's classpath transform data parsing into remote code execution."
        }
        VulnerabilityClass::BrokenAuthentication => {
            "Attacker exploits weak authentication mechanisms to impersonate legitimate users without valid credentials. \
             Flaws include credential stuffing, session fixation, and missing brute-force protections on login endpoints."
        }
        VulnerabilityClass::BrokenAuthorization => {
            "Attacker escalates privileges by accessing resources or functions beyond their authorized scope. \
             Horizontal and vertical privilege escalation occurs when authorization checks are missing or client-side only."
        }
        VulnerabilityClass::SecurityMisconfiguration => {
            "Attacker exploits default configurations, unnecessary services, or overly permissive settings in the application stack. \
             Exposed debug endpoints, default credentials, and verbose error messages reveal attack surface details."
        }
        VulnerabilityClass::SensitiveDataExposure => {
            "Application transmits or stores sensitive data without adequate protection such as encryption or access controls. \
             Exposed API keys, credentials, PII, or session tokens in responses enable downstream account compromise."
        }
        VulnerabilityClass::ServerSideTemplateInjection => {
            "Attacker injects template directives into server-side template engines that evaluate user input as code. \
             Successful injection achieves remote code execution through the template engine's expression language."
        }
        VulnerabilityClass::HeaderInjection => {
            "Attacker injects crafted values into HTTP response headers through unsanitized input reflected in header fields. \
             This enables response splitting, cache poisoning, and cross-site scripting via manipulated response headers."
        }
        VulnerabilityClass::OpenRedirect => {
            "Application redirects users to attacker-controlled URLs based on unvalidated input parameters. \
             Phishing campaigns leverage the trusted domain to redirect victims to credential harvesting pages."
        }
        VulnerabilityClass::CrlfInjection => {
            "Attacker injects carriage return and line feed characters to split HTTP responses or manipulate log entries. \
             Response splitting enables cache poisoning and session fixation through injected headers."
        }
        VulnerabilityClass::KnownVulnerableDependency => {
            "Application includes third-party libraries with publicly disclosed vulnerabilities and available exploits. \
             Attackers target known CVEs in outdated dependencies as a reliable initial access vector."
        }
        VulnerabilityClass::InsufficientInputValidation => {
            "Application fails to validate, sanitize, or constrain user-supplied input before processing. \
             Missing validation enables injection attacks, buffer overflows, and logic manipulation across multiple input vectors."
        }
        VulnerabilityClass::NoSqlInjection => {
            "Attacker injects NoSQL query operators through input fields to manipulate document database queries. \
             Operator injection in MongoDB or similar databases bypasses authentication and extracts unauthorized data."
        }
        VulnerabilityClass::XmlExternalEntity => {
            "Attacker submits XML documents referencing external entities that the parser resolves during processing. \
             XXE enables server-side file reading, SSRF to internal services, and denial of service via entity expansion."
        }
        VulnerabilityClass::CrossOriginMisconfiguration => {
            "Application sets overly permissive CORS headers allowing untrusted origins to read authenticated responses. \
             Attackers host malicious pages that silently exfiltrate data from the misconfigured API endpoints."
        }
        VulnerabilityClass::MissingSecurityHeader => {
            "Application omits defensive HTTP headers that instruct browsers to enforce security policies. \
             Missing Content-Security-Policy, X-Frame-Options, or HSTS headers leave users vulnerable to client-side attacks."
        }
        VulnerabilityClass::JwtVulnerability => {
            "Application accepts JWTs with weak signing algorithms, missing signature verification, or predictable secrets. \
             Attackers forge tokens with escalated claims to impersonate administrators or bypass authorization."
        }
        VulnerabilityClass::HttpRequestSmuggling => {
            "Attacker exploits discrepancies between front-end and back-end HTTP parsers to smuggle hidden requests. \
             Desynchronized request boundaries enable cache poisoning, credential hijacking, and access control bypass."
        }
        VulnerabilityClass::RaceCondition => {
            "Attacker sends concurrent requests to exploit time-of-check-to-time-of-use gaps in transaction logic. \
             Race windows in balance checks, coupon redemption, or vote tallying enable duplication of limited resources."
        }
        VulnerabilityClass::SubdomainTakeover => {
            "Attacker claims an unclaimed cloud resource pointed to by a dangling DNS record on a target subdomain. \
             Hosting content on the hijacked subdomain enables phishing, cookie theft, and trust exploitation."
        }
        VulnerabilityClass::PrototypePollution => {
            "Attacker modifies the prototype chain of JavaScript objects through recursive merge or deep-copy operations. \
             Polluted prototypes propagate attacker-controlled properties to all objects, enabling XSS or RCE."
        }
        VulnerabilityClass::GraphQlAbuse => {
            "Attacker exploits GraphQL introspection, deeply nested queries, or missing authorization on resolvers. \
             Unrestricted query depth enables denial of service while exposed schemas reveal internal data models."
        }
        VulnerabilityClass::CloudMisconfiguration => {
            "Cloud resources are deployed with overly permissive IAM policies, public storage buckets, or exposed metadata. \
             Misconfigured cloud services grant unauthorized access to production data and infrastructure credentials."
        }
        VulnerabilityClass::Clickjacking => {
            "Attacker frames the target application in a transparent iframe to trick users into clicking hidden UI elements. \
             Victims unknowingly perform state-changing actions like transferring funds or modifying account settings."
        }
        VulnerabilityClass::CachePoisoning => {
            "Attacker manipulates caching mechanisms to serve malicious content to other users through poisoned cache entries. \
             Unkeyed headers or parameters injected into cached responses persist the attack across subsequent visitors."
        }
        VulnerabilityClass::HostHeaderInjection => {
            "Attacker manipulates the Host header to poison password reset links, web cache entries, or SSRF vectors. \
             Applications that trust the Host header for URL generation redirect sensitive flows to attacker domains."
        }
        VulnerabilityClass::InsecureDirectObjectReference => {
            "Attacker modifies direct references to internal objects like database keys or file paths to access other users' data. \
             Sequential or predictable identifiers without authorization checks enable horizontal privilege escalation."
        }
        VulnerabilityClass::InformationDisclosure => {
            "Application reveals internal implementation details, stack traces, or sensitive data in error responses. \
             Disclosed information aids reconnaissance by exposing framework versions, database schemas, and file paths."
        }
        VulnerabilityClass::WeakCryptography => {
            "Application uses deprecated cryptographic algorithms or insufficient key lengths for data protection. \
             Weak ciphers like DES, MD5, or short RSA keys permit offline brute-force recovery of protected secrets."
        }
        VulnerabilityClass::MassAssignment => {
            "Attacker submits additional object properties that the application blindly binds to internal data models. \
             Unprotected model binding enables privilege escalation by setting admin flags or modifying protected fields."
        }
    }.to_string()
}

fn detection_recommendations_for(class: &VulnerabilityClass) -> Vec<String> {
    match class {
        VulnerabilityClass::SqlInjection => vec![
            "Monitor database query logs for anomalous syntax patterns and union-based injection signatures.".to_string(),
            "Deploy a WAF rule set tuned for SQL injection payloads including time-based and error-based variants.".to_string(),
            "Alert on application errors containing database engine syntax in HTTP responses.".to_string(),
        ],
        VulnerabilityClass::CrossSiteScripting => vec![
            "Implement Content-Security-Policy headers with strict script-src directives and nonce-based allowlisting.".to_string(),
            "Monitor DOM mutation events and script injection patterns in client-side telemetry.".to_string(),
            "Scan outbound responses for reflected input containing HTML or JavaScript syntax.".to_string(),
        ],
        VulnerabilityClass::CommandInjection => vec![
            "Audit application logs for process execution calls with shell metacharacters in arguments.".to_string(),
            "Monitor child process creation events for unexpected command interpreters spawned by the web server.".to_string(),
            "Restrict the application's system call surface with seccomp or AppArmor profiles.".to_string(),
        ],
        VulnerabilityClass::PathTraversal => vec![
            "Monitor file access logs for path sequences containing dot-dot-slash traversal patterns.".to_string(),
            "Alert on application attempts to read files outside the designated web root or data directories.".to_string(),
            "Enforce chroot or filesystem namespace isolation for the application process.".to_string(),
        ],
        VulnerabilityClass::ServerSideRequestForgery => vec![
            "Monitor outbound network connections from the application server for requests to internal IP ranges.".to_string(),
            "Block requests to cloud metadata endpoints (169.254.169.254) at the network level.".to_string(),
            "Log and alert on DNS resolution of internal hostnames initiated by user-facing request handlers.".to_string(),
        ],
        VulnerabilityClass::InsecureDeserialization => vec![
            "Monitor application logs for deserialization exceptions or unexpected object type instantiation.".to_string(),
            "Deploy runtime application self-protection to detect gadget chain execution patterns.".to_string(),
            "Restrict deserialization to an explicit allowlist of expected types.".to_string(),
        ],
        VulnerabilityClass::BrokenAuthentication => vec![
            "Monitor for credential stuffing patterns: high-volume login attempts from distributed IP addresses.".to_string(),
            "Alert on session token reuse across different client fingerprints or IP addresses.".to_string(),
            "Track failed authentication rates per account and enforce progressive lockout thresholds.".to_string(),
        ],
        VulnerabilityClass::BrokenAuthorization => vec![
            "Log all authorization decisions including denied access attempts with full request context.".to_string(),
            "Alert on users accessing resources outside their organizational unit or role scope.".to_string(),
            "Implement anomaly detection for unusual access patterns compared to peer group baselines.".to_string(),
        ],
        VulnerabilityClass::SecurityMisconfiguration => vec![
            "Scan deployed configurations against CIS benchmarks and alert on deviations.".to_string(),
            "Monitor for exposed administrative interfaces, debug endpoints, and default credential usage.".to_string(),
            "Alert on verbose error responses that expose stack traces or internal paths to external clients.".to_string(),
        ],
        VulnerabilityClass::SensitiveDataExposure => vec![
            "Scan outbound HTTP responses for patterns matching API keys, tokens, and PII formats.".to_string(),
            "Monitor for unencrypted transmission of sensitive data on non-TLS connections.".to_string(),
            "Alert on responses containing credentials, SSNs, or credit card numbers in plaintext.".to_string(),
        ],
        VulnerabilityClass::ServerSideTemplateInjection => vec![
            "Monitor template rendering logs for expression evaluation errors caused by injected syntax.".to_string(),
            "Deploy sandbox restrictions on template engine expression evaluation capabilities.".to_string(),
            "Alert on template rendering durations that exceed normal bounds, indicating injected computation.".to_string(),
        ],
        VulnerabilityClass::HeaderInjection => vec![
            "Validate all user input reflected in HTTP response headers for CRLF and control characters.".to_string(),
            "Monitor for responses containing unexpected Set-Cookie or Location headers not set by application logic.".to_string(),
            "Alert on HTTP responses with duplicate or malformed headers originating from dynamic content.".to_string(),
        ],
        VulnerabilityClass::OpenRedirect => vec![
            "Monitor redirect targets for domains outside an explicit allowlist of trusted destinations.".to_string(),
            "Alert on URL parameters containing full URLs or protocol-relative paths used in Location headers.".to_string(),
            "Track redirect chain length and alert on redirects that terminate at external domains.".to_string(),
        ],
        VulnerabilityClass::CrlfInjection => vec![
            "Scan input parameters for encoded carriage return and line feed sequences before header inclusion.".to_string(),
            "Monitor HTTP response streams for injected headers not generated by application code.".to_string(),
            "Alert on log entries containing line breaks that could indicate log injection attempts.".to_string(),
        ],
        VulnerabilityClass::KnownVulnerableDependency => vec![
            "Run continuous dependency scanning against the NVD and OSV databases in the CI pipeline.".to_string(),
            "Alert on newly published CVEs affecting dependencies in the production bill of materials.".to_string(),
            "Monitor for exploitation attempts targeting known CVEs in deployed library versions.".to_string(),
        ],
        VulnerabilityClass::InsufficientInputValidation => vec![
            "Implement schema validation at API boundaries and log payloads that fail validation.".to_string(),
            "Monitor for requests with payloads exceeding expected size or complexity bounds.".to_string(),
            "Alert on input containing encoding sequences commonly used to bypass validation filters.".to_string(),
        ],
        VulnerabilityClass::NoSqlInjection => vec![
            "Monitor database query logs for operator injection patterns like $gt, $ne, and $regex in user input.".to_string(),
            "Alert on queries containing unexpected JavaScript expressions or aggregation pipeline operators.".to_string(),
            "Enforce strict type checking on all parameters passed to NoSQL query constructors.".to_string(),
        ],
        VulnerabilityClass::XmlExternalEntity => vec![
            "Disable external entity resolution and DTD processing in all XML parser configurations.".to_string(),
            "Monitor for XML payloads containing DOCTYPE declarations or ENTITY definitions.".to_string(),
            "Alert on outbound network requests initiated during XML parsing operations.".to_string(),
        ],
        VulnerabilityClass::CrossOriginMisconfiguration => vec![
            "Audit CORS configurations for wildcard origins and reflected Origin header values.".to_string(),
            "Monitor for cross-origin requests from unexpected domains accessing authenticated endpoints.".to_string(),
            "Alert on Access-Control-Allow-Origin headers that echo the request Origin without validation.".to_string(),
        ],
        VulnerabilityClass::MissingSecurityHeader => vec![
            "Scan all HTTP responses for the presence of required security headers in the deployment pipeline.".to_string(),
            "Monitor for responses missing Content-Security-Policy, X-Frame-Options, or Strict-Transport-Security.".to_string(),
            "Alert on configuration changes that remove or weaken previously deployed security headers.".to_string(),
        ],
        VulnerabilityClass::JwtVulnerability => vec![
            "Monitor for JWT tokens using the 'none' algorithm or HMAC with asymmetric key confusion.".to_string(),
            "Alert on tokens with anomalous claims such as elevated roles or extended expiration times.".to_string(),
            "Log all token validation failures and track rejection rates per signing algorithm.".to_string(),
        ],
        VulnerabilityClass::HttpRequestSmuggling => vec![
            "Monitor for discrepancies between Content-Length and Transfer-Encoding headers in requests.".to_string(),
            "Alert on HTTP parsing errors at reverse proxy boundaries that indicate desynchronization.".to_string(),
            "Deploy identical HTTP parsing libraries across all tiers of the request processing pipeline.".to_string(),
        ],
        VulnerabilityClass::RaceCondition => vec![
            "Monitor for bursts of identical requests arriving within sub-millisecond windows.".to_string(),
            "Alert on transaction anomalies such as duplicate resource consumption or negative balances.".to_string(),
            "Instrument critical sections with timing telemetry to detect concurrent access violations.".to_string(),
        ],
        VulnerabilityClass::SubdomainTakeover => vec![
            "Monitor DNS records for CNAME entries pointing to unclaimed cloud service endpoints.".to_string(),
            "Alert on subdomains returning provider-specific error pages indicating unconfigured resources.".to_string(),
            "Audit DNS zone files after cloud resource deprovisioning to remove dangling records.".to_string(),
        ],
        VulnerabilityClass::PrototypePollution => vec![
            "Monitor for requests containing __proto__, constructor, or prototype property names in JSON payloads.".to_string(),
            "Alert on unexpected property additions to Object.prototype detected by runtime integrity checks.".to_string(),
            "Enforce Object.freeze on critical prototype chains in the application initialization path.".to_string(),
        ],
        VulnerabilityClass::GraphQlAbuse => vec![
            "Disable introspection queries in production and monitor for schema discovery attempts.".to_string(),
            "Enforce query depth and complexity limits and alert on queries exceeding thresholds.".to_string(),
            "Monitor for batch queries and alias-based amplification targeting rate-limited resolvers.".to_string(),
        ],
        VulnerabilityClass::CloudMisconfiguration => vec![
            "Run continuous cloud security posture management scans against organizational policy baselines.".to_string(),
            "Alert on public exposure of storage buckets, databases, or compute instances.".to_string(),
            "Monitor IAM policy changes and flag overly permissive role assignments or wildcard permissions.".to_string(),
        ],
        VulnerabilityClass::Clickjacking => vec![
            "Deploy X-Frame-Options DENY or SAMEORIGIN headers on all state-changing endpoints.".to_string(),
            "Implement frame-ancestors directive in Content-Security-Policy to restrict framing origins.".to_string(),
            "Monitor for iframe embedding of the application from unauthorized third-party domains.".to_string(),
        ],
        VulnerabilityClass::CachePoisoning => vec![
            "Audit cache key configurations to ensure all client-controllable inputs are included in the key.".to_string(),
            "Monitor cache hit rates for anomalous spikes that could indicate poisoned entries being served.".to_string(),
            "Alert on responses where unkeyed headers or cookies influence the response body content.".to_string(),
        ],
        VulnerabilityClass::HostHeaderInjection => vec![
            "Validate the Host header against an allowlist of expected virtual host names.".to_string(),
            "Monitor for password reset or account verification emails containing unexpected domain names.".to_string(),
            "Alert on requests with Host header values that differ from the expected server names.".to_string(),
        ],
        VulnerabilityClass::InsecureDirectObjectReference => vec![
            "Log all resource access with the authenticated user context and the requested object identifier.".to_string(),
            "Alert on sequential enumeration patterns accessing object IDs outside the user's ownership scope.".to_string(),
            "Implement object-level authorization checks that verify ownership before returning resource data.".to_string(),
        ],
        VulnerabilityClass::InformationDisclosure => vec![
            "Scan HTTP responses for stack traces, internal IP addresses, and framework version strings.".to_string(),
            "Monitor error handling paths to ensure generic error messages are returned to external clients.".to_string(),
            "Alert on responses larger than expected for the endpoint, indicating unintended data leakage.".to_string(),
        ],
        VulnerabilityClass::WeakCryptography => vec![
            "Audit TLS configurations for deprecated cipher suites and protocol versions below TLS 1.2.".to_string(),
            "Monitor for certificate warnings and alert on connections negotiating weak key exchange parameters.".to_string(),
            "Scan application code for usage of MD5, SHA1, DES, or RSA keys shorter than 2048 bits.".to_string(),
        ],
        VulnerabilityClass::MassAssignment => vec![
            "Monitor for API requests containing properties not defined in the endpoint's expected schema.".to_string(),
            "Alert on modifications to protected fields such as role, isAdmin, or accountBalance.".to_string(),
            "Log all model binding operations and flag when unexpected fields are applied to the data model.".to_string(),
        ],
    }
}

/// Maps a single vulnerability finding to its MITRE ATT&CK technique with full details.
pub fn map_finding(class: VulnerabilityClass, severity: f64) -> AttackMapping {
    let technique = technique_for(&class);
    let procedure_description = procedure_description_for(&class);
    let detection_recommendations = detection_recommendations_for(&class);

    AttackMapping {
        vulnerability_class: class.to_string(),
        technique_id: technique.id,
        technique_name: technique.name,
        tactic: technique.tactic,
        procedure_description,
        detection_recommendations,
        severity,
    }
}

/// Maps multiple findings, deduplicating by technique_id and keeping the highest severity.
pub fn map_findings(findings: &[(VulnerabilityClass, f64)]) -> Vec<AttackMapping> {
    let mut best_by_technique: HashMap<String, AttackMapping> = HashMap::new();

    for (class, severity) in findings {
        let mapping = map_finding(*class, *severity);
        let existing = best_by_technique.get(&mapping.technique_id);
        let dominated = match existing {
            Some(prev) => prev.severity < mapping.severity,
            None => true,
        };
        if dominated {
            best_by_technique.insert(mapping.technique_id.clone(), mapping);
        }
    }

    let mut results: Vec<AttackMapping> = best_by_technique.into_values().collect();
    results.sort_by(|a, b| a.technique_id.cmp(&b.technique_id));
    results
}

fn severity_to_color(severity: f64) -> String {
    if severity >= 7.0 {
        "#ff4444".to_string()
    } else if severity >= 4.0 {
        "#ff8c00".to_string()
    } else if severity >= 2.0 {
        "#ffd700".to_string()
    } else {
        "#44ff44".to_string()
    }
}

/// Generates an ATT&CK Navigator layer from a set of attack mappings.
pub fn generate_navigator_layer(mappings: &[AttackMapping], layer_name: &str) -> NavigatorLayer {
    let techniques: Vec<NavigatorTechnique> = mappings
        .iter()
        .map(|m| {
            let raw_score = (m.severity * 10.0) as u32;
            let score = raw_score.min(100);

            NavigatorTechnique {
                technique_id: m.technique_id.clone(),
                tactic: m.tactic.clone(),
                score,
                color: severity_to_color(m.severity),
                comment: m.procedure_description.clone(),
                enabled: true,
                show_subtechniques: false,
            }
        })
        .collect();

    NavigatorLayer {
        name: layer_name.to_string(),
        versions: NavigatorVersions {
            attack: "15.1".to_string(),
            navigator: "5.0.0".to_string(),
            layer: "4.5".to_string(),
        },
        domain: "enterprise-attack".to_string(),
        description: format!(
            "AEGIS scan findings mapped to MITRE ATT&CK techniques ({} techniques)",
            techniques.len()
        ),
        techniques,
        gradient: NavigatorGradient {
            colors: vec!["#ffffff".to_string(), "#ff6666".to_string()],
            min_value: 0,
            max_value: 100,
        },
    }
}

/// Serializes a NavigatorLayer to ATT&CK Navigator JSON format.
pub fn to_navigator_json(layer: &NavigatorLayer) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(layer)
}
