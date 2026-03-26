use std::collections::HashMap;
use std::fmt;

use regex::Regex;

/// Broad technology category for classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TechCategory {
    Language,
    Framework,
    CloudProvider,
    Database,
    CiCd,
    SecurityTool,
    Monitoring,
    Container,
    MessageQueue,
    Other,
}

impl fmt::Display for TechCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Language => write!(f, "Language"),
            Self::Framework => write!(f, "Framework"),
            Self::CloudProvider => write!(f, "Cloud Provider"),
            Self::Database => write!(f, "Database"),
            Self::CiCd => write!(f, "CI/CD"),
            Self::SecurityTool => write!(f, "Security Tool"),
            Self::Monitoring => write!(f, "Monitoring"),
            Self::Container => write!(f, "Container"),
            Self::MessageQueue => write!(f, "Message Queue"),
            Self::Other => write!(f, "Other"),
        }
    }
}

/// A technology detected from job posting text.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectedTech {
    pub name: String,
    pub category: TechCategory,
    pub confidence: f64,
    pub context_snippet: Option<String>,
}

impl fmt::Display for DetectedTech {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [{}] ({:.0}%)",
            self.name,
            self.category,
            self.confidence * 100.0
        )
    }
}

/// Maturity level of the target organization's security posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecurityMaturityLevel {
    Minimal,
    Basic,
    Intermediate,
    Advanced,
    Mature,
}

impl fmt::Display for SecurityMaturityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Minimal => write!(f, "Minimal"),
            Self::Basic => write!(f, "Basic"),
            Self::Intermediate => write!(f, "Intermediate"),
            Self::Advanced => write!(f, "Advanced"),
            Self::Mature => write!(f, "Mature"),
        }
    }
}

/// An indicator contributing to the security maturity score.
#[derive(Debug, Clone, PartialEq)]
pub struct SecurityIndicator {
    pub category: String,
    pub detail: String,
    pub weight: f64,
}

impl fmt::Display for SecurityIndicator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} (weight {:.1})",
            self.category, self.detail, self.weight
        )
    }
}

/// Parsed job posting with extracted metadata.
#[derive(Debug, Clone, PartialEq)]
pub struct JobPosting {
    pub title: String,
    pub company: String,
    pub location: String,
    pub description: String,
    pub requirements: Vec<String>,
    pub source_url: Option<String>,
    pub posted_date: Option<String>,
}

impl fmt::Display for JobPosting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at {} ({})", self.title, self.company, self.location)
    }
}

/// Signals about organizational changes detected from job postings.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum OrgSignal {
    HeadcountGrowth {
        department: String,
        open_roles: usize,
    },
    RestructuringIndicator {
        detail: String,
    },
    AcquisitionHint {
        detail: String,
    },
    NewTeamFormation {
        team_name: String,
    },
    LeadershipChange {
        detail: String,
    },
    OffshoreExpansion {
        region: String,
    },
    SecurityTeamBuild {
        detail: String,
    },
    TechStackMigration {
        from_hint: String,
        to_hint: String,
    },
}

impl fmt::Display for OrgSignal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeadcountGrowth {
                department,
                open_roles,
            } => {
                write!(
                    f,
                    "Headcount growth in {} ({} open roles)",
                    department, open_roles
                )
            }
            Self::RestructuringIndicator { detail } => write!(f, "Restructuring: {}", detail),
            Self::AcquisitionHint { detail } => write!(f, "Acquisition hint: {}", detail),
            Self::NewTeamFormation { team_name } => write!(f, "New team forming: {}", team_name),
            Self::LeadershipChange { detail } => write!(f, "Leadership change: {}", detail),
            Self::OffshoreExpansion { region } => write!(f, "Offshore expansion: {}", region),
            Self::SecurityTeamBuild { detail } => write!(f, "Security team build: {}", detail),
            Self::TechStackMigration { from_hint, to_hint } => {
                write!(f, "Tech migration: {} -> {}", from_hint, to_hint)
            }
        }
    }
}

/// Risk classification derived from tech stack and security posture.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IntelRisk {
    OutdatedTechnology { tech: String, detail: String },
    MissingSecurityLayer { layer: String },
    OverRelianceOnSingleVendor { vendor: String },
    RapidGrowthWithoutSecurity,
    NoComplianceMentioned,
    WeakAuthenticationSignals,
    NoIncidentResponseIndicated,
    LegacyMigrationRisk { detail: String },
}

impl fmt::Display for IntelRisk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutdatedTechnology { tech, detail } => {
                write!(f, "Outdated tech: {} ({})", tech, detail)
            }
            Self::MissingSecurityLayer { layer } => write!(f, "Missing security layer: {}", layer),
            Self::OverRelianceOnSingleVendor { vendor } => {
                write!(f, "Over-reliance on single vendor: {}", vendor)
            }
            Self::RapidGrowthWithoutSecurity => write!(f, "Rapid growth without security hiring"),
            Self::NoComplianceMentioned => write!(f, "No compliance frameworks mentioned"),
            Self::WeakAuthenticationSignals => write!(f, "Weak authentication signals"),
            Self::NoIncidentResponseIndicated => {
                write!(f, "No incident response program indicated")
            }
            Self::LegacyMigrationRisk { detail } => write!(f, "Legacy migration risk: {}", detail),
        }
    }
}

/// Full intelligence report built from one or more job postings.
#[derive(Debug, Clone)]
pub struct JobIntelReport {
    pub postings_analyzed: usize,
    pub detected_technologies: Vec<DetectedTech>,
    pub security_maturity: SecurityMaturityLevel,
    pub security_indicators: Vec<SecurityIndicator>,
    pub org_signals: Vec<OrgSignal>,
    pub risks: Vec<IntelRisk>,
    pub tech_category_counts: HashMap<TechCategory, usize>,
    pub compliance_frameworks: Vec<String>,
    pub summary: String,
}

impl fmt::Display for JobIntelReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Job Intel Report: {} postings, {} technologies, security maturity: {}, {} risks",
            self.postings_analyzed,
            self.detected_technologies.len(),
            self.security_maturity,
            self.risks.len(),
        )
    }
}

struct TechPattern {
    pattern: &'static str,
    canonical_name: &'static str,
    category: TechCategory,
}

fn tech_patterns() -> Vec<TechPattern> {
    vec![
        // --- Languages (20) ---
        TechPattern {
            pattern: r"\brust\b",
            canonical_name: "Rust",
            category: TechCategory::Language,
        },
        TechPattern {
            pattern: r"\bpython\b",
            canonical_name: "Python",
            category: TechCategory::Language,
        },
        TechPattern {
            pattern: r"\bjava\b",
            canonical_name: "Java",
            category: TechCategory::Language,
        },
        TechPattern {
            pattern: r"\bgolang\b|\bgo\s+lang",
            canonical_name: "Go",
            category: TechCategory::Language,
        },
        TechPattern {
            pattern: r"\btypescript\b",
            canonical_name: "TypeScript",
            category: TechCategory::Language,
        },
        TechPattern {
            pattern: r"\bjavascript\b",
            canonical_name: "JavaScript",
            category: TechCategory::Language,
        },
        TechPattern {
            pattern: r"\bc\+\+\b|\bcpp\b",
            canonical_name: "C++",
            category: TechCategory::Language,
        },
        TechPattern {
            pattern: r"\bc#\b|\.net\b|dotnet\b",
            canonical_name: "C#/.NET",
            category: TechCategory::Language,
        },
        TechPattern {
            pattern: r"\bruby\b",
            canonical_name: "Ruby",
            category: TechCategory::Language,
        },
        TechPattern {
            pattern: r"\bkotlin\b",
            canonical_name: "Kotlin",
            category: TechCategory::Language,
        },
        TechPattern {
            pattern: r"\bswift\b",
            canonical_name: "Swift",
            category: TechCategory::Language,
        },
        TechPattern {
            pattern: r"\bscala\b",
            canonical_name: "Scala",
            category: TechCategory::Language,
        },
        TechPattern {
            pattern: r"\bphp\b",
            canonical_name: "PHP",
            category: TechCategory::Language,
        },
        TechPattern {
            pattern: r"\belixir\b",
            canonical_name: "Elixir",
            category: TechCategory::Language,
        },
        TechPattern {
            pattern: r"\berlang\b",
            canonical_name: "Erlang",
            category: TechCategory::Language,
        },
        TechPattern {
            pattern: r"\bhaskell\b",
            canonical_name: "Haskell",
            category: TechCategory::Language,
        },
        TechPattern {
            pattern: r"\bclojure\b",
            canonical_name: "Clojure",
            category: TechCategory::Language,
        },
        TechPattern {
            pattern: r"\blua\b",
            canonical_name: "Lua",
            category: TechCategory::Language,
        },
        TechPattern {
            pattern: r"\br\b(?:\s+programming|\s+language)",
            canonical_name: "R",
            category: TechCategory::Language,
        },
        TechPattern {
            pattern: r"\bzig\b",
            canonical_name: "Zig",
            category: TechCategory::Language,
        },
        // --- Frameworks (15) ---
        TechPattern {
            pattern: r"\breact\b",
            canonical_name: "React",
            category: TechCategory::Framework,
        },
        TechPattern {
            pattern: r"\bangular\b",
            canonical_name: "Angular",
            category: TechCategory::Framework,
        },
        TechPattern {
            pattern: r"\bvue\.?js\b|\bvuejs\b",
            canonical_name: "Vue.js",
            category: TechCategory::Framework,
        },
        TechPattern {
            pattern: r"\bdjango\b",
            canonical_name: "Django",
            category: TechCategory::Framework,
        },
        TechPattern {
            pattern: r"\bflask\b",
            canonical_name: "Flask",
            category: TechCategory::Framework,
        },
        TechPattern {
            pattern: r"\bspring\s*(boot)?\b",
            canonical_name: "Spring",
            category: TechCategory::Framework,
        },
        TechPattern {
            pattern: r"\bexpress\.?js\b|\bexpressjs\b",
            canonical_name: "Express.js",
            category: TechCategory::Framework,
        },
        TechPattern {
            pattern: r"\brails\b|\bruby on rails\b",
            canonical_name: "Ruby on Rails",
            category: TechCategory::Framework,
        },
        TechPattern {
            pattern: r"\bnext\.?js\b|\bnextjs\b",
            canonical_name: "Next.js",
            category: TechCategory::Framework,
        },
        TechPattern {
            pattern: r"\bfastapi\b",
            canonical_name: "FastAPI",
            category: TechCategory::Framework,
        },
        TechPattern {
            pattern: r"\blaravel\b",
            canonical_name: "Laravel",
            category: TechCategory::Framework,
        },
        TechPattern {
            pattern: r"\bsvelte\b",
            canonical_name: "Svelte",
            category: TechCategory::Framework,
        },
        TechPattern {
            pattern: r"\breact\s+native\b",
            canonical_name: "React Native",
            category: TechCategory::Framework,
        },
        TechPattern {
            pattern: r"\bflutter\b",
            canonical_name: "Flutter",
            category: TechCategory::Framework,
        },
        TechPattern {
            pattern: r"\bactix\b|\btokio\b|\baxum\b",
            canonical_name: "Rust async (actix/tokio/axum)",
            category: TechCategory::Framework,
        },
        // --- Cloud Providers (8) ---
        TechPattern {
            pattern: r"\baws\b|\bamazon web services\b",
            canonical_name: "AWS",
            category: TechCategory::CloudProvider,
        },
        TechPattern {
            pattern: r"\bgcp\b|\bgoogle cloud\b",
            canonical_name: "GCP",
            category: TechCategory::CloudProvider,
        },
        TechPattern {
            pattern: r"\bazure\b",
            canonical_name: "Azure",
            category: TechCategory::CloudProvider,
        },
        TechPattern {
            pattern: r"\bcloudflare\b",
            canonical_name: "Cloudflare",
            category: TechCategory::CloudProvider,
        },
        TechPattern {
            pattern: r"\bdigitalocean\b",
            canonical_name: "DigitalOcean",
            category: TechCategory::CloudProvider,
        },
        TechPattern {
            pattern: r"\bheroku\b",
            canonical_name: "Heroku",
            category: TechCategory::CloudProvider,
        },
        TechPattern {
            pattern: r"\bvercel\b",
            canonical_name: "Vercel",
            category: TechCategory::CloudProvider,
        },
        TechPattern {
            pattern: r"\blinode\b|\bakamai\b",
            canonical_name: "Linode/Akamai",
            category: TechCategory::CloudProvider,
        },
        // --- Databases (12) ---
        TechPattern {
            pattern: r"\bpostgres(?:ql)?\b",
            canonical_name: "PostgreSQL",
            category: TechCategory::Database,
        },
        TechPattern {
            pattern: r"\bmysql\b",
            canonical_name: "MySQL",
            category: TechCategory::Database,
        },
        TechPattern {
            pattern: r"\bmongodb\b|\bmongo\b",
            canonical_name: "MongoDB",
            category: TechCategory::Database,
        },
        TechPattern {
            pattern: r"\bredis\b",
            canonical_name: "Redis",
            category: TechCategory::Database,
        },
        TechPattern {
            pattern: r"\belasticsearch\b|\belastic\b",
            canonical_name: "Elasticsearch",
            category: TechCategory::Database,
        },
        TechPattern {
            pattern: r"\bdynamodb\b",
            canonical_name: "DynamoDB",
            category: TechCategory::Database,
        },
        TechPattern {
            pattern: r"\bcassandra\b",
            canonical_name: "Cassandra",
            category: TechCategory::Database,
        },
        TechPattern {
            pattern: r"\bsqlite\b",
            canonical_name: "SQLite",
            category: TechCategory::Database,
        },
        TechPattern {
            pattern: r"\bcockroachdb\b",
            canonical_name: "CockroachDB",
            category: TechCategory::Database,
        },
        TechPattern {
            pattern: r"\bneo4j\b",
            canonical_name: "Neo4j",
            category: TechCategory::Database,
        },
        TechPattern {
            pattern: r"\bsnowflake\b",
            canonical_name: "Snowflake",
            category: TechCategory::Database,
        },
        TechPattern {
            pattern: r"\bclickhouse\b",
            canonical_name: "ClickHouse",
            category: TechCategory::Database,
        },
        // --- CI/CD (10) ---
        TechPattern {
            pattern: r"\bjenkins\b",
            canonical_name: "Jenkins",
            category: TechCategory::CiCd,
        },
        TechPattern {
            pattern: r"\bgithub\s*actions\b",
            canonical_name: "GitHub Actions",
            category: TechCategory::CiCd,
        },
        TechPattern {
            pattern: r"\bgitlab\s*ci\b",
            canonical_name: "GitLab CI",
            category: TechCategory::CiCd,
        },
        TechPattern {
            pattern: r"\bcircle\s*ci\b",
            canonical_name: "CircleCI",
            category: TechCategory::CiCd,
        },
        TechPattern {
            pattern: r"\bterraform\b",
            canonical_name: "Terraform",
            category: TechCategory::CiCd,
        },
        TechPattern {
            pattern: r"\bansible\b",
            canonical_name: "Ansible",
            category: TechCategory::CiCd,
        },
        TechPattern {
            pattern: r"\bargo\s*cd\b|\bargocd\b",
            canonical_name: "ArgoCD",
            category: TechCategory::CiCd,
        },
        TechPattern {
            pattern: r"\bpulumi\b",
            canonical_name: "Pulumi",
            category: TechCategory::CiCd,
        },
        TechPattern {
            pattern: r"\bspinnaker\b",
            canonical_name: "Spinnaker",
            category: TechCategory::CiCd,
        },
        TechPattern {
            pattern: r"\bhelm\b",
            canonical_name: "Helm",
            category: TechCategory::CiCd,
        },
        // --- Security Tools (10) ---
        TechPattern {
            pattern: r"\bburp\s*suite\b|\bburp\b",
            canonical_name: "Burp Suite",
            category: TechCategory::SecurityTool,
        },
        TechPattern {
            pattern: r"\bnmap\b",
            canonical_name: "Nmap",
            category: TechCategory::SecurityTool,
        },
        TechPattern {
            pattern: r"\bmetasploit\b",
            canonical_name: "Metasploit",
            category: TechCategory::SecurityTool,
        },
        TechPattern {
            pattern: r"\bwireshark\b",
            canonical_name: "Wireshark",
            category: TechCategory::SecurityTool,
        },
        TechPattern {
            pattern: r"\bsnyk\b",
            canonical_name: "Snyk",
            category: TechCategory::SecurityTool,
        },
        TechPattern {
            pattern: r"\bsonarqube\b|\bsonar\b",
            canonical_name: "SonarQube",
            category: TechCategory::SecurityTool,
        },
        TechPattern {
            pattern: r"\bvault\b|\bhashicorp\s+vault\b",
            canonical_name: "HashiCorp Vault",
            category: TechCategory::SecurityTool,
        },
        TechPattern {
            pattern: r"\bsplunk\b",
            canonical_name: "Splunk",
            category: TechCategory::SecurityTool,
        },
        TechPattern {
            pattern: r"\bcrowdstrike\b",
            canonical_name: "CrowdStrike",
            category: TechCategory::SecurityTool,
        },
        TechPattern {
            pattern: r"\bsentinelone\b",
            canonical_name: "SentinelOne",
            category: TechCategory::SecurityTool,
        },
        // --- Monitoring (6) ---
        TechPattern {
            pattern: r"\bdatadog\b",
            canonical_name: "Datadog",
            category: TechCategory::Monitoring,
        },
        TechPattern {
            pattern: r"\bgrafana\b",
            canonical_name: "Grafana",
            category: TechCategory::Monitoring,
        },
        TechPattern {
            pattern: r"\bprometheus\b",
            canonical_name: "Prometheus",
            category: TechCategory::Monitoring,
        },
        TechPattern {
            pattern: r"\bnew\s*relic\b",
            canonical_name: "New Relic",
            category: TechCategory::Monitoring,
        },
        TechPattern {
            pattern: r"\bpagerduty\b",
            canonical_name: "PagerDuty",
            category: TechCategory::Monitoring,
        },
        TechPattern {
            pattern: r"\bsentry\b",
            canonical_name: "Sentry",
            category: TechCategory::Monitoring,
        },
        // --- Containers (5) ---
        TechPattern {
            pattern: r"\bdocker\b",
            canonical_name: "Docker",
            category: TechCategory::Container,
        },
        TechPattern {
            pattern: r"\bkubernetes\b|\bk8s\b",
            canonical_name: "Kubernetes",
            category: TechCategory::Container,
        },
        TechPattern {
            pattern: r"\bpodman\b",
            canonical_name: "Podman",
            category: TechCategory::Container,
        },
        TechPattern {
            pattern: r"\bistio\b",
            canonical_name: "Istio",
            category: TechCategory::Container,
        },
        TechPattern {
            pattern: r"\benvoy\b",
            canonical_name: "Envoy",
            category: TechCategory::Container,
        },
        // --- Message Queues (5) ---
        TechPattern {
            pattern: r"\bkafka\b",
            canonical_name: "Kafka",
            category: TechCategory::MessageQueue,
        },
        TechPattern {
            pattern: r"\brabbitmq\b",
            canonical_name: "RabbitMQ",
            category: TechCategory::MessageQueue,
        },
        TechPattern {
            pattern: r"\bsqs\b",
            canonical_name: "SQS",
            category: TechCategory::MessageQueue,
        },
        TechPattern {
            pattern: r"\bnats\b",
            canonical_name: "NATS",
            category: TechCategory::MessageQueue,
        },
        TechPattern {
            pattern: r"\bpulsar\b",
            canonical_name: "Pulsar",
            category: TechCategory::MessageQueue,
        },
    ]
}

/// Extract technology stack from free-text job description content.
///
/// Scans the input against 90+ technology patterns across all `TechCategory` variants
/// and returns deduplicated matches with confidence scores derived from match context.
pub fn extract_tech_stack(text: &str) -> Vec<DetectedTech> {
    let lower = text.to_lowercase();
    let patterns = tech_patterns();
    let mut seen: HashMap<String, DetectedTech> = HashMap::new();

    for tp in &patterns {
        let re = match Regex::new(&format!("(?i){}", tp.pattern)) {
            Ok(r) => r,
            Err(_) => continue,
        };

        for mat in re.find_iter(&lower) {
            let key = tp.canonical_name.to_string();
            if seen.contains_key(&key) {
                continue;
            }

            let start = mat.start().saturating_sub(30);
            let end = (mat.end() + 30).min(text.len());
            let snippet = text[start..end].to_string();

            let confidence = compute_tech_confidence(&lower, tp.canonical_name, mat.start());
            seen.insert(
                key,
                DetectedTech {
                    name: tp.canonical_name.to_string(),
                    category: tp.category,
                    confidence,
                    context_snippet: Some(snippet),
                },
            );
        }
    }

    let mut results: Vec<DetectedTech> = seen.into_values().collect();
    results.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    results
}

fn compute_tech_confidence(text: &str, tech_name: &str, match_pos: usize) -> f64 {
    let mut score: f64 = 0.5;
    let context_start = match_pos.saturating_sub(80);
    let context_end = (match_pos + 80).min(text.len());
    let context = &text[context_start..context_end];

    let requirement_signals = [
        "require",
        "must have",
        "experience with",
        "proficiency",
        "expertise",
        "strong",
        "deep knowledge",
        "hands-on",
        "mandatory",
        "essential",
    ];
    let nice_to_have = [
        "nice to have",
        "preferred",
        "bonus",
        "plus",
        "desired",
        "optional",
    ];

    if requirement_signals.iter().any(|s| context.contains(s)) {
        score += 0.3;
    }
    if nice_to_have.iter().any(|s| context.contains(s)) {
        score += 0.1;
    }

    let mention_count = text.matches(&tech_name.to_lowercase()).count();
    if mention_count >= 3 {
        score += 0.15;
    } else if mention_count >= 2 {
        score += 0.05;
    }

    score.min(1.0)
}

struct CompliancePattern {
    pattern: &'static str,
    framework: &'static str,
    weight: f64,
}

fn compliance_patterns() -> Vec<CompliancePattern> {
    vec![
        CompliancePattern {
            pattern: r"\bsoc\s*2\b|\bsoc2\b|\bsoc\s+type\s+(ii|2)\b",
            framework: "SOC 2",
            weight: 3.0,
        },
        CompliancePattern {
            pattern: r"\biso\s*27001\b",
            framework: "ISO 27001",
            weight: 3.0,
        },
        CompliancePattern {
            pattern: r"\bpci[\s\-]*dss\b",
            framework: "PCI-DSS",
            weight: 3.5,
        },
        CompliancePattern {
            pattern: r"\bhipaa\b",
            framework: "HIPAA",
            weight: 3.0,
        },
        CompliancePattern {
            pattern: r"\bgdpr\b",
            framework: "GDPR",
            weight: 2.5,
        },
        CompliancePattern {
            pattern: r"\bfedramp\b",
            framework: "FedRAMP",
            weight: 3.5,
        },
        CompliancePattern {
            pattern: r"\bnist\b",
            framework: "NIST",
            weight: 2.5,
        },
        CompliancePattern {
            pattern: r"\bccpa\b",
            framework: "CCPA",
            weight: 2.0,
        },
        CompliancePattern {
            pattern: r"\biso\s*27701\b",
            framework: "ISO 27701",
            weight: 2.5,
        },
        CompliancePattern {
            pattern: r"\bcsa\s+star\b",
            framework: "CSA STAR",
            weight: 2.0,
        },
    ]
}

/// Infer security maturity from combined text of one or more job postings.
///
/// Examines compliance frameworks, security tooling references, dedicated team signals,
/// vulnerability management terms, and incident response language to produce a maturity
/// level and the individual indicators that contributed to the score.
pub fn infer_security_maturity(text: &str) -> (SecurityMaturityLevel, Vec<SecurityIndicator>) {
    let lower = text.to_lowercase();
    let mut indicators: Vec<SecurityIndicator> = Vec::new();
    let mut total_weight: f64 = 0.0;

    for cp in compliance_patterns() {
        let re = match Regex::new(&format!("(?i){}", cp.pattern)) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if re.is_match(&lower) {
            indicators.push(SecurityIndicator {
                category: "Compliance".to_string(),
                detail: format!("{} mentioned", cp.framework),
                weight: cp.weight,
            });
            total_weight += cp.weight;
        }
    }

    let security_team_signals: Vec<(&str, f64)> = vec![
        ("security team", 2.0),
        ("security engineer", 2.5),
        ("appsec", 2.5),
        ("application security", 2.5),
        ("penetration test", 2.0),
        ("red team", 3.0),
        ("blue team", 3.0),
        ("purple team", 3.5),
        ("security operations center", 3.0),
        ("ciso", 3.0),
        ("chief information security", 3.0),
        ("devsecops", 2.5),
        ("security architect", 2.5),
        ("threat model", 2.5),
        ("bug bounty", 2.0),
    ];

    for (signal, weight) in &security_team_signals {
        if lower.contains(signal) {
            indicators.push(SecurityIndicator {
                category: "Security Team".to_string(),
                detail: format!("Reference to '{}'", signal),
                weight: *weight,
            });
            total_weight += weight;
        }
    }

    let security_tool_signals: Vec<(&str, f64)> = vec![
        ("siem", 2.0),
        ("waf", 1.5),
        ("ids", 1.0),
        ("ips", 1.0),
        ("edr", 2.0),
        ("xdr", 2.5),
        ("soar", 2.5),
        ("vulnerability scan", 2.0),
        ("sast", 2.0),
        ("dast", 2.0),
        ("iast", 2.0),
        ("rasp", 2.0),
        ("secret management", 1.5),
        ("zero trust", 2.5),
        ("mfa", 1.5),
        ("multi-factor", 1.5),
        ("sso", 1.0),
        ("oauth", 1.0),
        ("saml", 1.0),
        ("code review", 1.5),
    ];

    for (signal, weight) in &security_tool_signals {
        if lower.contains(signal) {
            indicators.push(SecurityIndicator {
                category: "Security Tooling".to_string(),
                detail: format!("'{}' referenced", signal),
                weight: *weight,
            });
            total_weight += weight;
        }
    }

    let vuln_mgmt_signals: Vec<(&str, f64)> = vec![
        ("vulnerability management", 2.5),
        ("patch management", 2.0),
        ("cve", 1.5),
        ("cwe", 1.5),
        ("owasp", 2.0),
        ("secure sdlc", 2.5),
        ("security review", 2.0),
        ("incident response", 2.5),
        ("security incident", 2.0),
        ("forensic", 2.0),
        ("threat intelligence", 2.5),
        ("risk assessment", 2.0),
        ("security audit", 2.0),
        ("compliance audit", 2.0),
        ("security awareness", 1.5),
    ];

    for (signal, weight) in &vuln_mgmt_signals {
        if lower.contains(signal) {
            indicators.push(SecurityIndicator {
                category: "Vulnerability Management".to_string(),
                detail: format!("'{}' mentioned", signal),
                weight: *weight,
            });
            total_weight += weight;
        }
    }

    let level = if total_weight >= 25.0 {
        SecurityMaturityLevel::Mature
    } else if total_weight >= 15.0 {
        SecurityMaturityLevel::Advanced
    } else if total_weight >= 8.0 {
        SecurityMaturityLevel::Intermediate
    } else if total_weight >= 3.0 {
        SecurityMaturityLevel::Basic
    } else {
        SecurityMaturityLevel::Minimal
    };

    (level, indicators)
}

/// Parse a JSON-encoded job posting into a `JobPosting` struct.
///
/// Expected JSON fields: `title`, `company`, `location`, `description`, `requirements`
/// (array of strings), plus optional `source_url` and `posted_date`.
pub fn parse_job_posting_json(json_str: &str) -> Result<JobPosting, String> {
    let value: serde_json::Value =
        serde_json::from_str(json_str).map_err(|e| format!("JSON parse error: {}", e))?;

    let obj = value
        .as_object()
        .ok_or_else(|| "Expected JSON object".to_string())?;

    let title = obj
        .get("title")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing 'title' field".to_string())?
        .to_string();

    let company = obj
        .get("company")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing 'company' field".to_string())?
        .to_string();

    let location = obj
        .get("location")
        .and_then(|v| v.as_str())
        .unwrap_or("Remote")
        .to_string();

    let description = obj
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let requirements = obj
        .get("requirements")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let source_url = obj
        .get("source_url")
        .and_then(|v| v.as_str())
        .map(String::from);
    let posted_date = obj
        .get("posted_date")
        .and_then(|v| v.as_str())
        .map(String::from);

    Ok(JobPosting {
        title,
        company,
        location,
        description,
        requirements,
        source_url,
        posted_date,
    })
}

/// Detect organizational signals from a collection of job postings.
///
/// Looks for headcount surges per department, restructuring language, acquisition
/// terminology, new-team formation patterns, leadership hires, offshore expansion,
/// security team build-outs, and technology migration hints.
pub fn detect_org_signals(postings: &[JobPosting]) -> Vec<OrgSignal> {
    let mut signals: Vec<OrgSignal> = Vec::new();

    let mut dept_counts: HashMap<String, usize> = HashMap::new();
    for posting in postings {
        let dept = infer_department(&posting.title);
        *dept_counts.entry(dept).or_default() += 1;
    }
    for (dept, count) in &dept_counts {
        if *count >= 3 {
            signals.push(OrgSignal::HeadcountGrowth {
                department: dept.clone(),
                open_roles: *count,
            });
        }
    }

    let all_text: String = postings
        .iter()
        .map(|p| format!("{} {} {}", p.title, p.description, p.requirements.join(" ")))
        .collect::<Vec<_>>()
        .join(" ");
    let lower = all_text.to_lowercase();

    let restructuring_kw = [
        "reorg",
        "reorganiz",
        "restructur",
        "transformation",
        "new direction",
        "strategic shift",
        "realign",
    ];
    for kw in &restructuring_kw {
        if lower.contains(kw) {
            signals.push(OrgSignal::RestructuringIndicator {
                detail: format!("'{}' found in posting text", kw),
            });
            break;
        }
    }

    let acquisition_kw = [
        "acquisition",
        "merger",
        "m&a",
        "integration",
        "acquired company",
        "post-merger",
        "newly acquired",
    ];
    for kw in &acquisition_kw {
        if lower.contains(kw) {
            signals.push(OrgSignal::AcquisitionHint {
                detail: format!("'{}' found in posting text", kw),
            });
            break;
        }
    }

    let new_team_re = Regex::new(r"(?i)build(?:ing)?\s+(?:a\s+)?(?:new\s+)?(\w+)\s+team").ok();
    if let Some(re) = new_team_re {
        for cap in re.captures_iter(&all_text) {
            if let Some(team) = cap.get(1) {
                signals.push(OrgSignal::NewTeamFormation {
                    team_name: team.as_str().to_string(),
                });
            }
        }
    }

    let leadership_titles = [
        "vp",
        "vice president",
        "cto",
        "ciso",
        "ceo",
        "cfo",
        "head of",
        "director",
    ];
    for posting in postings {
        let title_lower = posting.title.to_lowercase();
        for lt in &leadership_titles {
            if title_lower.contains(lt) {
                signals.push(OrgSignal::LeadershipChange {
                    detail: format!("Hiring for: {}", posting.title),
                });
                break;
            }
        }
    }

    let offshore_regions = [
        ("india", "India"),
        ("bangalore", "India"),
        ("hyderabad", "India"),
        ("pune", "India"),
        ("poland", "Poland"),
        ("romania", "Romania"),
        ("ukraine", "Ukraine"),
        ("philippines", "Philippines"),
        ("vietnam", "Vietnam"),
        ("latam", "Latin America"),
        ("costa rica", "Costa Rica"),
    ];
    for (kw, region) in &offshore_regions {
        if lower.contains(kw) {
            signals.push(OrgSignal::OffshoreExpansion {
                region: region.to_string(),
            });
            break;
        }
    }

    let security_build_signals = [
        "first security",
        "founding security",
        "build security",
        "stand up security",
        "establish security",
        "grow our security",
    ];
    for kw in &security_build_signals {
        if lower.contains(kw) {
            signals.push(OrgSignal::SecurityTeamBuild {
                detail: format!("'{}' found in posting text", kw),
            });
            break;
        }
    }

    let migration_pairs: Vec<(&str, &str)> = vec![
        ("monolith", "microservice"),
        ("on-prem", "cloud"),
        ("legacy", "modern"),
        ("migrate from", "migrate to"),
        ("java", "golang"),
        ("python 2", "python 3"),
        ("mysql", "postgres"),
    ];
    for (from_kw, to_kw) in &migration_pairs {
        if lower.contains(from_kw) && lower.contains(to_kw) {
            signals.push(OrgSignal::TechStackMigration {
                from_hint: from_kw.to_string(),
                to_hint: to_kw.to_string(),
            });
        }
    }

    signals
}

fn infer_department(title: &str) -> String {
    let lower = title.to_lowercase();
    if lower.contains("security") || lower.contains("appsec") || lower.contains("ciso") {
        "Security".to_string()
    } else if lower.contains("devops")
        || lower.contains("sre")
        || lower.contains("infrastructure")
        || lower.contains("platform")
    {
        "Infrastructure".to_string()
    } else if lower.contains("frontend")
        || lower.contains("ui")
        || lower.contains("ux")
        || lower.contains("design")
    {
        "Frontend/Design".to_string()
    } else if lower.contains("backend") || lower.contains("api") || lower.contains("server") {
        "Backend".to_string()
    } else if lower.contains("data")
        || lower.contains("machine learning")
        || lower.contains("ml ")
        || lower.contains("ai ")
    {
        "Data/ML".to_string()
    } else if lower.contains("mobile") || lower.contains("ios") || lower.contains("android") {
        "Mobile".to_string()
    } else if lower.contains("qa") || lower.contains("test") || lower.contains("quality") {
        "QA".to_string()
    } else if lower.contains("product") || lower.contains("pm ") {
        "Product".to_string()
    } else if lower.contains("sales") || lower.contains("account executive") {
        "Sales".to_string()
    } else if lower.contains("marketing") || lower.contains("growth") {
        "Marketing".to_string()
    } else {
        "Engineering".to_string()
    }
}

/// Build a comprehensive intelligence report from one or more parsed job postings.
///
/// Aggregates tech extraction, security maturity inference, org signals, and risk
/// classification into a single `JobIntelReport`.
pub fn build_job_intel_report(postings: &[JobPosting]) -> JobIntelReport {
    let combined_text: String = postings
        .iter()
        .map(|p| {
            format!(
                "{}\n{}\n{}",
                p.title,
                p.description,
                p.requirements.join("\n"),
            )
        })
        .collect::<Vec<_>>()
        .join("\n\n");

    let detected_technologies = extract_tech_stack(&combined_text);
    let (security_maturity, security_indicators) = infer_security_maturity(&combined_text);
    let org_signals = detect_org_signals(postings);

    let mut tech_category_counts: HashMap<TechCategory, usize> = HashMap::new();
    for tech in &detected_technologies {
        *tech_category_counts.entry(tech.category).or_default() += 1;
    }

    let compliance_frameworks = extract_compliance_frameworks(&combined_text);
    let risks = classify_tech_risk(&detected_technologies, &security_indicators, &org_signals);

    let summary = format!(
        "Analyzed {} posting(s): {} technologies detected across {} categories, \
         security maturity {}, {} org signals, {} compliance frameworks, {} risks identified",
        postings.len(),
        detected_technologies.len(),
        tech_category_counts.len(),
        security_maturity,
        org_signals.len(),
        compliance_frameworks.len(),
        risks.len(),
    );

    JobIntelReport {
        postings_analyzed: postings.len(),
        detected_technologies,
        security_maturity,
        security_indicators,
        org_signals,
        risks,
        tech_category_counts,
        compliance_frameworks,
        summary,
    }
}

fn extract_compliance_frameworks(text: &str) -> Vec<String> {
    let mut frameworks: Vec<String> = Vec::new();
    for cp in compliance_patterns() {
        let re = match Regex::new(&format!("(?i){}", cp.pattern)) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if re.is_match(text) {
            frameworks.push(cp.framework.to_string());
        }
    }
    frameworks.sort();
    frameworks.dedup();
    frameworks
}

/// Classify risks based on detected technology, security indicators, and org signals.
///
/// Produces a list of `IntelRisk` findings capturing outdated tech, missing security
/// layers, vendor concentration, rapid growth without security investment, and more.
pub fn classify_tech_risk(
    technologies: &[DetectedTech],
    security_indicators: &[SecurityIndicator],
    org_signals: &[OrgSignal],
) -> Vec<IntelRisk> {
    let mut risks: Vec<IntelRisk> = Vec::new();

    let outdated_techs: Vec<(&str, &str)> = vec![
        ("PHP", "Legacy language with historically weak type safety"),
        ("jQuery", "Legacy frontend library suggesting old codebase"),
        ("ColdFusion", "End-of-mainstream-support platform"),
        ("Perl", "Declining ecosystem with security implications"),
    ];
    for (tech_name, detail) in &outdated_techs {
        if technologies
            .iter()
            .any(|t| t.name.eq_ignore_ascii_case(tech_name))
        {
            risks.push(IntelRisk::OutdatedTechnology {
                tech: tech_name.to_string(),
                detail: detail.to_string(),
            });
        }
    }

    let has_security_tool_indicator = security_indicators
        .iter()
        .any(|si| si.category == "Security Tooling");
    let has_vuln_mgmt = security_indicators
        .iter()
        .any(|si| si.category == "Vulnerability Management");
    let has_compliance = security_indicators
        .iter()
        .any(|si| si.category == "Compliance");

    if !has_security_tool_indicator {
        risks.push(IntelRisk::MissingSecurityLayer {
            layer: "No security tooling mentioned (SAST/DAST/SIEM/WAF)".to_string(),
        });
    }
    if !has_vuln_mgmt {
        risks.push(IntelRisk::MissingSecurityLayer {
            layer: "No vulnerability management program indicated".to_string(),
        });
    }
    if !has_compliance {
        risks.push(IntelRisk::NoComplianceMentioned);
    }

    let cloud_techs: Vec<String> = technologies
        .iter()
        .filter(|t| t.category == TechCategory::CloudProvider)
        .map(|t| t.name.clone())
        .collect();
    if cloud_techs.len() == 1 {
        risks.push(IntelRisk::OverRelianceOnSingleVendor {
            vendor: cloud_techs[0].clone(),
        });
    }

    let has_growth = org_signals
        .iter()
        .any(|s| matches!(s, OrgSignal::HeadcountGrowth { .. }));
    let has_security_hire = org_signals
        .iter()
        .any(|s| matches!(s, OrgSignal::SecurityTeamBuild { .. }));
    let security_tech_count = technologies
        .iter()
        .filter(|t| t.category == TechCategory::SecurityTool)
        .count();
    if has_growth && !has_security_hire && security_tech_count == 0 {
        risks.push(IntelRisk::RapidGrowthWithoutSecurity);
    }

    let auth_signals = ["oauth", "saml", "mfa", "multi-factor", "sso"];
    let has_auth = security_indicators.iter().any(|si| {
        auth_signals
            .iter()
            .any(|kw| si.detail.to_lowercase().contains(kw))
    });
    if !has_auth {
        risks.push(IntelRisk::WeakAuthenticationSignals);
    }

    let has_ir = security_indicators
        .iter()
        .any(|si| si.detail.to_lowercase().contains("incident response"));
    if !has_ir {
        risks.push(IntelRisk::NoIncidentResponseIndicated);
    }

    let has_migration = org_signals
        .iter()
        .any(|s| matches!(s, OrgSignal::TechStackMigration { .. }));
    if has_migration {
        risks.push(IntelRisk::LegacyMigrationRisk {
            detail: "Active migration detected — transitional architecture may have gaps"
                .to_string(),
        });
    }

    risks
}
