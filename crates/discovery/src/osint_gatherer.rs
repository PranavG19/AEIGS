use std::collections::HashMap;

/// Raw breach entry: (source_name, date, records_count, data_types).
pub type BreachEntry<'a> = (&'a str, Option<&'a str>, Option<u64>, &'a [&'a str]);

/// Raw repository entry: (platform, org, repo_name, is_public, language, last_updated).
pub type RepoEntry<'a> = (
    &'a str,
    &'a str,
    &'a str,
    bool,
    Option<&'a str>,
    Option<&'a str>,
);

/// Raw social profile entry: (platform, url, username, verified, followers).
pub type SocialEntry<'a> = (&'a str, &'a str, Option<&'a str>, bool, Option<u64>);

/// Raw employee entry: (name, role, department, source_str).
pub type EmployeeEntry<'a> = (&'a str, Option<&'a str>, Option<&'a str>, &'a str);

/// Origin of OSINT data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OsintSource {
    LinkedIn,
    GitHub,
    GitLab,
    JobPosting,
    BreachDatabase,
    SocialMedia,
    PublicRecords,
    CodeRepository,
    WebArchive,
    Pastebin,
}

impl std::fmt::Display for OsintSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LinkedIn => write!(f, "LinkedIn"),
            Self::GitHub => write!(f, "GitHub"),
            Self::GitLab => write!(f, "GitLab"),
            Self::JobPosting => write!(f, "Job Posting"),
            Self::BreachDatabase => write!(f, "Breach Database"),
            Self::SocialMedia => write!(f, "Social Media"),
            Self::PublicRecords => write!(f, "Public Records"),
            Self::CodeRepository => write!(f, "Code Repository"),
            Self::WebArchive => write!(f, "Web Archive"),
            Self::Pastebin => write!(f, "Pastebin"),
        }
    }
}

/// Technology classification for OSINT stack items.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OsintTechCategory {
    Language,
    Framework,
    Database,
    CloudProvider,
    Cdn,
    Ci,
    VersionControl,
    Monitoring,
    Security,
    Other,
}

impl std::fmt::Display for OsintTechCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Language => write!(f, "Language"),
            Self::Framework => write!(f, "Framework"),
            Self::Database => write!(f, "Database"),
            Self::CloudProvider => write!(f, "Cloud Provider"),
            Self::Cdn => write!(f, "CDN"),
            Self::Ci => write!(f, "CI/CD"),
            Self::VersionControl => write!(f, "Version Control"),
            Self::Monitoring => write!(f, "Monitoring"),
            Self::Security => write!(f, "Security"),
            Self::Other => write!(f, "Other"),
        }
    }
}

/// Estimated organization size bracket with headcount.
#[derive(Debug, Clone, PartialEq)]
pub enum OrgSize {
    Startup(usize),
    Small(usize),
    Medium(usize),
    Large(usize),
    Enterprise(usize),
}

impl OrgSize {
    fn from_headcount(count: usize) -> Self {
        match count {
            0..=10 => Self::Startup(count),
            11..=50 => Self::Small(count),
            51..=250 => Self::Medium(count),
            251..=1000 => Self::Large(count),
            _ => Self::Enterprise(count),
        }
    }
}

/// Data types exposed in a breach.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BreachDataType {
    Email,
    Password,
    PasswordHash,
    Name,
    Phone,
    Address,
    Ssn,
    CreditCard,
    IpAddress,
    Other(String),
}

impl BreachDataType {
    fn from_str_lossy(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "email" | "emails" => Self::Email,
            "password" | "passwords" => Self::Password,
            "password_hash" | "passwordhash" | "hashed_password" => Self::PasswordHash,
            "name" | "names" | "full_name" => Self::Name,
            "phone" | "phones" | "phone_number" => Self::Phone,
            "address" | "addresses" => Self::Address,
            "ssn" | "social_security" => Self::Ssn,
            "credit_card" | "creditcard" | "cc" => Self::CreditCard,
            "ip" | "ip_address" | "ipaddress" => Self::IpAddress,
            other => Self::Other(other.to_string()),
        }
    }
}

/// Information about a discovered employee.
#[derive(Debug, Clone, PartialEq)]
pub struct EmployeeInfo {
    pub name: String,
    pub role: Option<String>,
    pub department: Option<String>,
    pub email_pattern: Option<String>,
    pub source: OsintSource,
    pub confidence: f64,
}

/// Detected email naming pattern for a domain.
#[derive(Debug, Clone, PartialEq)]
pub struct EmailPattern {
    pub pattern: String,
    pub examples: Vec<String>,
    pub confidence: f64,
    pub description: String,
}

/// A technology detected in the target's stack.
#[derive(Debug, Clone, PartialEq)]
pub struct TechStackItem {
    pub technology: String,
    pub category: OsintTechCategory,
    pub version: Option<String>,
    pub source: OsintSource,
    pub confidence: f64,
}

/// A department within the organization.
#[derive(Debug, Clone, PartialEq)]
pub struct Department {
    pub name: String,
    pub estimated_headcount: usize,
    pub technologies: Vec<String>,
}

/// Inferred organizational structure.
#[derive(Debug, Clone, PartialEq)]
pub struct OrgStructure {
    pub departments: Vec<Department>,
    pub estimated_size: OrgSize,
    pub leadership: Vec<EmployeeInfo>,
}

/// A breach record associated with the target domain.
#[derive(Debug, Clone, PartialEq)]
pub struct BreachRecord {
    pub source_name: String,
    pub date: Option<String>,
    pub records_exposed: Option<u64>,
    pub data_types: Vec<BreachDataType>,
    pub email_domain_match: bool,
}

/// Social media presence for the organization.
#[derive(Debug, Clone, PartialEq)]
pub struct SocialMediaPresence {
    pub platform: String,
    pub url: String,
    pub username: Option<String>,
    pub verified: bool,
    pub follower_count: Option<u64>,
}

/// A discovered code repository.
#[derive(Debug, Clone, PartialEq)]
pub struct CodeRepository {
    pub platform: String,
    pub org_name: String,
    pub repo_name: String,
    pub url: String,
    pub is_public: bool,
    pub language: Option<String>,
    pub last_updated: Option<String>,
}

/// Full OSINT report for a target domain.
#[derive(Debug, Clone, PartialEq)]
pub struct OsintReport {
    pub domain: String,
    pub employees: Vec<EmployeeInfo>,
    pub email_patterns: Vec<EmailPattern>,
    pub tech_stack: Vec<TechStackItem>,
    pub org_structure: Option<OrgStructure>,
    pub breaches: Vec<BreachRecord>,
    pub social_media: Vec<SocialMediaPresence>,
    pub repositories: Vec<CodeRepository>,
    pub risk_score: f64,
}

/// Analyze known email addresses to detect naming patterns for a domain.
pub fn infer_email_patterns(known_emails: &[&str], domain: &str) -> Vec<EmailPattern> {
    let domain_lower = domain.to_lowercase();
    let matching: Vec<String> = known_emails
        .iter()
        .map(|e| e.to_lowercase())
        .filter(|e| e.ends_with(&format!("@{domain_lower}")))
        .collect();

    if matching.is_empty() {
        return Vec::new();
    }

    let mut pattern_counts: HashMap<&str, Vec<String>> = HashMap::new();

    for email in &matching {
        let local = match email.split('@').next() {
            Some(l) => l,
            None => continue,
        };
        let detected = classify_local_part(local);
        pattern_counts
            .entry(detected)
            .or_default()
            .push(email.clone());
    }

    let total = matching.len() as f64;
    let mut patterns = Vec::new();

    for (pattern_key, examples) in &pattern_counts {
        let confidence = examples.len() as f64 / total;
        let (pattern_str, description) = pattern_description(pattern_key);
        patterns.push(EmailPattern {
            pattern: pattern_str.to_string(),
            examples: examples.clone(),
            confidence,
            description: description.to_string(),
        });
    }

    patterns.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
    patterns
}

fn classify_local_part(local: &str) -> &'static str {
    if local.contains('.') {
        let parts: Vec<&str> = local.split('.').collect();
        if parts.len() == 2 && parts[0].len() > 1 && parts[1].len() > 1 {
            return "first.last";
        }
        if parts.len() == 2 && parts[0].len() == 1 && parts[1].len() > 1 {
            return "flast";
        }
        if parts.len() == 2 && parts[0].len() > 1 && parts[1].len() == 1 {
            return "firstl";
        }
    }

    if local.len() > 1 && local.chars().all(|c| c.is_ascii_alphabetic()) {
        let has_upper_boundary = local
            .chars()
            .zip(local.chars().skip(1))
            .any(|(a, b)| a.is_lowercase() && b.is_uppercase());
        if has_upper_boundary {
            return "firstLast";
        }
        if local.len() <= 8 {
            return "first";
        }
        return "firstlast";
    }

    if local.contains('_') {
        let parts: Vec<&str> = local.split('_').collect();
        if parts.len() == 2 && parts[0].len() > 1 && parts[1].len() > 1 {
            return "first_last";
        }
    }

    if local.contains('-') {
        let parts: Vec<&str> = local.split('-').collect();
        if parts.len() == 2 && parts[0].len() > 1 && parts[1].len() > 1 {
            return "first-last";
        }
    }

    "unknown"
}

fn pattern_description(key: &str) -> (&str, &str) {
    match key {
        "first.last" => ("first.last@domain", "First name dot last name"),
        "flast" => ("flast@domain", "First initial dot last name"),
        "firstl" => ("firstl@domain", "First name dot last initial"),
        "first_last" => ("first_last@domain", "First name underscore last name"),
        "first-last" => ("first-last@domain", "First name hyphen last name"),
        "firstLast" => ("firstLast@domain", "Camel-cased first and last name"),
        "firstlast" => ("firstlast@domain", "Concatenated first and last name"),
        "first" => ("first@domain", "First name only"),
        _ => ("unknown@domain", "Unrecognized pattern"),
    }
}

struct TechKeyword {
    keyword: &'static str,
    canonical: &'static str,
    category: OsintTechCategory,
}

const TECH_KEYWORDS: &[TechKeyword] = &[
    TechKeyword {
        keyword: "python",
        canonical: "Python",
        category: OsintTechCategory::Language,
    },
    TechKeyword {
        keyword: "java ",
        canonical: "Java",
        category: OsintTechCategory::Language,
    },
    TechKeyword {
        keyword: "javascript",
        canonical: "JavaScript",
        category: OsintTechCategory::Language,
    },
    TechKeyword {
        keyword: "typescript",
        canonical: "TypeScript",
        category: OsintTechCategory::Language,
    },
    TechKeyword {
        keyword: "golang",
        canonical: "Go",
        category: OsintTechCategory::Language,
    },
    TechKeyword {
        keyword: " go ",
        canonical: "Go",
        category: OsintTechCategory::Language,
    },
    TechKeyword {
        keyword: "rust",
        canonical: "Rust",
        category: OsintTechCategory::Language,
    },
    TechKeyword {
        keyword: "c++",
        canonical: "C++",
        category: OsintTechCategory::Language,
    },
    TechKeyword {
        keyword: "ruby",
        canonical: "Ruby",
        category: OsintTechCategory::Language,
    },
    TechKeyword {
        keyword: "scala",
        canonical: "Scala",
        category: OsintTechCategory::Language,
    },
    TechKeyword {
        keyword: "kotlin",
        canonical: "Kotlin",
        category: OsintTechCategory::Language,
    },
    TechKeyword {
        keyword: "swift",
        canonical: "Swift",
        category: OsintTechCategory::Language,
    },
    TechKeyword {
        keyword: "react",
        canonical: "React",
        category: OsintTechCategory::Framework,
    },
    TechKeyword {
        keyword: "angular",
        canonical: "Angular",
        category: OsintTechCategory::Framework,
    },
    TechKeyword {
        keyword: "vue",
        canonical: "Vue",
        category: OsintTechCategory::Framework,
    },
    TechKeyword {
        keyword: "node.js",
        canonical: "Node.js",
        category: OsintTechCategory::Framework,
    },
    TechKeyword {
        keyword: "nodejs",
        canonical: "Node.js",
        category: OsintTechCategory::Framework,
    },
    TechKeyword {
        keyword: "django",
        canonical: "Django",
        category: OsintTechCategory::Framework,
    },
    TechKeyword {
        keyword: "flask",
        canonical: "Flask",
        category: OsintTechCategory::Framework,
    },
    TechKeyword {
        keyword: "spring",
        canonical: "Spring",
        category: OsintTechCategory::Framework,
    },
    TechKeyword {
        keyword: "rails",
        canonical: "Ruby on Rails",
        category: OsintTechCategory::Framework,
    },
    TechKeyword {
        keyword: "next.js",
        canonical: "Next.js",
        category: OsintTechCategory::Framework,
    },
    TechKeyword {
        keyword: "nextjs",
        canonical: "Next.js",
        category: OsintTechCategory::Framework,
    },
    TechKeyword {
        keyword: "express",
        canonical: "Express",
        category: OsintTechCategory::Framework,
    },
    TechKeyword {
        keyword: "fastapi",
        canonical: "FastAPI",
        category: OsintTechCategory::Framework,
    },
    TechKeyword {
        keyword: "laravel",
        canonical: "Laravel",
        category: OsintTechCategory::Framework,
    },
    TechKeyword {
        keyword: "postgresql",
        canonical: "PostgreSQL",
        category: OsintTechCategory::Database,
    },
    TechKeyword {
        keyword: "postgres",
        canonical: "PostgreSQL",
        category: OsintTechCategory::Database,
    },
    TechKeyword {
        keyword: "mysql",
        canonical: "MySQL",
        category: OsintTechCategory::Database,
    },
    TechKeyword {
        keyword: "mongodb",
        canonical: "MongoDB",
        category: OsintTechCategory::Database,
    },
    TechKeyword {
        keyword: "redis",
        canonical: "Redis",
        category: OsintTechCategory::Database,
    },
    TechKeyword {
        keyword: "elasticsearch",
        canonical: "Elasticsearch",
        category: OsintTechCategory::Database,
    },
    TechKeyword {
        keyword: "dynamodb",
        canonical: "DynamoDB",
        category: OsintTechCategory::Database,
    },
    TechKeyword {
        keyword: "cassandra",
        canonical: "Cassandra",
        category: OsintTechCategory::Database,
    },
    TechKeyword {
        keyword: "kafka",
        canonical: "Kafka",
        category: OsintTechCategory::Database,
    },
    TechKeyword {
        keyword: "rabbitmq",
        canonical: "RabbitMQ",
        category: OsintTechCategory::Database,
    },
    TechKeyword {
        keyword: "aws",
        canonical: "AWS",
        category: OsintTechCategory::CloudProvider,
    },
    TechKeyword {
        keyword: "amazon web services",
        canonical: "AWS",
        category: OsintTechCategory::CloudProvider,
    },
    TechKeyword {
        keyword: "azure",
        canonical: "Azure",
        category: OsintTechCategory::CloudProvider,
    },
    TechKeyword {
        keyword: "gcp",
        canonical: "GCP",
        category: OsintTechCategory::CloudProvider,
    },
    TechKeyword {
        keyword: "google cloud",
        canonical: "GCP",
        category: OsintTechCategory::CloudProvider,
    },
    TechKeyword {
        keyword: "docker",
        canonical: "Docker",
        category: OsintTechCategory::Other,
    },
    TechKeyword {
        keyword: "kubernetes",
        canonical: "Kubernetes",
        category: OsintTechCategory::Other,
    },
    TechKeyword {
        keyword: "k8s",
        canonical: "Kubernetes",
        category: OsintTechCategory::Other,
    },
    TechKeyword {
        keyword: "terraform",
        canonical: "Terraform",
        category: OsintTechCategory::Other,
    },
    TechKeyword {
        keyword: "ansible",
        canonical: "Ansible",
        category: OsintTechCategory::Other,
    },
    TechKeyword {
        keyword: "cloudflare",
        canonical: "Cloudflare",
        category: OsintTechCategory::Cdn,
    },
    TechKeyword {
        keyword: "fastly",
        canonical: "Fastly",
        category: OsintTechCategory::Cdn,
    },
    TechKeyword {
        keyword: "akamai",
        canonical: "Akamai",
        category: OsintTechCategory::Cdn,
    },
    TechKeyword {
        keyword: "jenkins",
        canonical: "Jenkins",
        category: OsintTechCategory::Ci,
    },
    TechKeyword {
        keyword: "github actions",
        canonical: "GitHub Actions",
        category: OsintTechCategory::Ci,
    },
    TechKeyword {
        keyword: "circleci",
        canonical: "CircleCI",
        category: OsintTechCategory::Ci,
    },
    TechKeyword {
        keyword: "gitlab ci",
        canonical: "GitLab CI",
        category: OsintTechCategory::Ci,
    },
    TechKeyword {
        keyword: "travis",
        canonical: "Travis CI",
        category: OsintTechCategory::Ci,
    },
    TechKeyword {
        keyword: "datadog",
        canonical: "Datadog",
        category: OsintTechCategory::Monitoring,
    },
    TechKeyword {
        keyword: "splunk",
        canonical: "Splunk",
        category: OsintTechCategory::Monitoring,
    },
    TechKeyword {
        keyword: "grafana",
        canonical: "Grafana",
        category: OsintTechCategory::Monitoring,
    },
    TechKeyword {
        keyword: "prometheus",
        canonical: "Prometheus",
        category: OsintTechCategory::Monitoring,
    },
    TechKeyword {
        keyword: "new relic",
        canonical: "New Relic",
        category: OsintTechCategory::Monitoring,
    },
    TechKeyword {
        keyword: "pagerduty",
        canonical: "PagerDuty",
        category: OsintTechCategory::Monitoring,
    },
    TechKeyword {
        keyword: "git",
        canonical: "Git",
        category: OsintTechCategory::VersionControl,
    },
    TechKeyword {
        keyword: "github",
        canonical: "GitHub",
        category: OsintTechCategory::VersionControl,
    },
    TechKeyword {
        keyword: "gitlab",
        canonical: "GitLab",
        category: OsintTechCategory::VersionControl,
    },
    TechKeyword {
        keyword: "bitbucket",
        canonical: "Bitbucket",
        category: OsintTechCategory::VersionControl,
    },
    TechKeyword {
        keyword: "vault",
        canonical: "HashiCorp Vault",
        category: OsintTechCategory::Security,
    },
    TechKeyword {
        keyword: "okta",
        canonical: "Okta",
        category: OsintTechCategory::Security,
    },
    TechKeyword {
        keyword: "auth0",
        canonical: "Auth0",
        category: OsintTechCategory::Security,
    },
    TechKeyword {
        keyword: "crowdstrike",
        canonical: "CrowdStrike",
        category: OsintTechCategory::Security,
    },
    TechKeyword {
        keyword: "snyk",
        canonical: "Snyk",
        category: OsintTechCategory::Security,
    },
];

/// Extract technology mentions from job posting text.
pub fn extract_tech_from_job_postings(postings: &[&str]) -> Vec<TechStackItem> {
    let mut seen: HashMap<String, TechStackItem> = HashMap::new();

    for posting in postings {
        let lower = posting.to_lowercase();
        for tk in TECH_KEYWORDS {
            if lower.contains(tk.keyword) {
                let key = tk.canonical.to_lowercase();
                seen.entry(key)
                    .and_modify(|existing| {
                        existing.confidence = (existing.confidence + 0.1).min(1.0);
                    })
                    .or_insert_with(|| TechStackItem {
                        technology: tk.canonical.to_string(),
                        category: tk.category,
                        version: None,
                        source: OsintSource::JobPosting,
                        confidence: 0.6,
                    });
            }
        }
    }

    let mut results: Vec<TechStackItem> = seen.into_values().collect();
    results.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap()
            .then_with(|| a.technology.cmp(&b.technology))
    });
    results
}

/// Process breach database entries and correlate with the target domain.
pub fn correlate_breaches(domain: &str, breach_entries: &[BreachEntry<'_>]) -> Vec<BreachRecord> {
    let domain_lower = domain.to_lowercase();

    breach_entries
        .iter()
        .map(|(source_name, date, records_count, data_types)| {
            let source_lower = source_name.to_lowercase();
            let email_domain_match =
                source_lower.contains(&domain_lower) || domain_lower.contains(&source_lower);

            BreachRecord {
                source_name: source_name.to_string(),
                date: date.map(|d| d.to_string()),
                records_exposed: *records_count,
                data_types: data_types
                    .iter()
                    .map(|dt| BreachDataType::from_str_lossy(dt))
                    .collect(),
                email_domain_match,
            }
        })
        .collect()
}

/// Process raw repository metadata into typed structs.
pub fn enumerate_repositories(repos: &[RepoEntry<'_>]) -> Vec<CodeRepository> {
    repos
        .iter()
        .map(
            |(platform, org, repo_name, is_public, language, last_updated)| {
                let url = format!("https://{}/{}/{}", platform.to_lowercase(), org, repo_name);
                CodeRepository {
                    platform: platform.to_string(),
                    org_name: org.to_string(),
                    repo_name: repo_name.to_string(),
                    url,
                    is_public: *is_public,
                    language: language.map(|l| l.to_string()),
                    last_updated: last_updated.map(|u| u.to_string()),
                }
            },
        )
        .collect()
}

/// Infer organizational structure from employee data and tech stack.
pub fn build_org_structure(
    employees: &[EmployeeInfo],
    tech_stack: &[TechStackItem],
) -> OrgStructure {
    let mut dept_members: HashMap<String, Vec<&EmployeeInfo>> = HashMap::new();

    for emp in employees {
        let dept_name = emp
            .department
            .clone()
            .unwrap_or_else(|| "Unknown".to_string());
        dept_members.entry(dept_name).or_default().push(emp);
    }

    let tech_names: Vec<String> = tech_stack.iter().map(|t| t.technology.clone()).collect();
    let departments = build_departments(&dept_members, &tech_names);
    let leadership = identify_leadership(employees);
    let total_headcount = employees.len().max(1);
    let estimated_size = OrgSize::from_headcount(total_headcount);

    OrgStructure {
        departments,
        estimated_size,
        leadership,
    }
}

fn build_departments(
    dept_members: &HashMap<String, Vec<&EmployeeInfo>>,
    tech_names: &[String],
) -> Vec<Department> {
    let engineering_keywords = ["engineer", "developer", "devops", "sre", "architect", "qa"];

    let mut departments: Vec<Department> = dept_members
        .iter()
        .map(|(name, members)| {
            let is_engineering = members.iter().any(|m| {
                m.role
                    .as_deref()
                    .map(|r| {
                        let lower = r.to_lowercase();
                        engineering_keywords.iter().any(|kw| lower.contains(kw))
                    })
                    .unwrap_or(false)
            }) || name.to_lowercase().contains("engineer")
                || name.to_lowercase().contains("tech");

            let technologies = if is_engineering {
                tech_names.to_vec()
            } else {
                Vec::new()
            };

            Department {
                name: name.clone(),
                estimated_headcount: members.len(),
                technologies,
            }
        })
        .collect();

    departments.sort_by(|a, b| b.estimated_headcount.cmp(&a.estimated_headcount));
    departments
}

const LEADERSHIP_TITLES: &[&str] = &[
    "ceo",
    "cto",
    "cfo",
    "coo",
    "ciso",
    "vp",
    "vice president",
    "director",
    "head of",
    "chief",
    "partner",
    "founder",
    "president",
    "svp",
    "evp",
];

fn identify_leadership(employees: &[EmployeeInfo]) -> Vec<EmployeeInfo> {
    employees
        .iter()
        .filter(|emp| {
            emp.role
                .as_deref()
                .map(|r| {
                    let lower = r.to_lowercase();
                    LEADERSHIP_TITLES.iter().any(|title| lower.contains(title))
                })
                .unwrap_or(false)
        })
        .cloned()
        .collect()
}

/// Calculate overall OSINT exposure risk score from 0.0 to 1.0.
pub fn calculate_osint_risk(report: &OsintReport) -> f64 {
    let employee_risk = normalize_count(report.employees.len(), 50);
    let email_risk = report
        .email_patterns
        .iter()
        .map(|p| p.confidence)
        .max_by(|a, b| a.partial_cmp(b).unwrap())
        .unwrap_or(0.0);
    let breach_risk = calculate_breach_risk(&report.breaches);
    let repo_risk = calculate_repo_risk(&report.repositories);
    let social_risk = normalize_count(report.social_media.len(), 10);

    let weighted = employee_risk * 0.2
        + email_risk * 0.2
        + breach_risk * 0.3
        + repo_risk * 0.15
        + social_risk * 0.15;

    weighted.min(1.0)
}

fn normalize_count(count: usize, saturation: usize) -> f64 {
    (count as f64 / saturation as f64).min(1.0)
}

fn calculate_breach_risk(breaches: &[BreachRecord]) -> f64 {
    if breaches.is_empty() {
        return 0.0;
    }

    let domain_matches = breaches.iter().filter(|b| b.email_domain_match).count();
    let match_ratio = domain_matches as f64 / breaches.len() as f64;

    let has_passwords = breaches.iter().any(|b| {
        b.data_types
            .iter()
            .any(|dt| matches!(dt, BreachDataType::Password | BreachDataType::PasswordHash))
    });

    let has_sensitive = breaches.iter().any(|b| {
        b.data_types
            .iter()
            .any(|dt| matches!(dt, BreachDataType::Ssn | BreachDataType::CreditCard))
    });

    let base = normalize_count(breaches.len(), 5);
    let severity_bump =
        if has_passwords { 0.15 } else { 0.0 } + if has_sensitive { 0.2 } else { 0.0 };

    ((base + severity_bump) * (0.5 + 0.5 * match_ratio)).min(1.0)
}

fn calculate_repo_risk(repos: &[CodeRepository]) -> f64 {
    let public_count = repos.iter().filter(|r| r.is_public).count();
    normalize_count(public_count, 20)
}

/// Map raw social profile tuples to typed structs.
pub fn map_social_profiles(profiles: &[SocialEntry<'_>]) -> Vec<SocialMediaPresence> {
    profiles
        .iter()
        .map(
            |(platform, url, username, verified, followers)| SocialMediaPresence {
                platform: platform.to_string(),
                url: url.to_string(),
                username: username.map(|u| u.to_string()),
                verified: *verified,
                follower_count: *followers,
            },
        )
        .collect()
}

fn parse_osint_source(s: &str) -> OsintSource {
    match s.to_lowercase().as_str() {
        "linkedin" => OsintSource::LinkedIn,
        "github" => OsintSource::GitHub,
        "gitlab" => OsintSource::GitLab,
        "job_posting" | "jobposting" | "job posting" => OsintSource::JobPosting,
        "breach" | "breach_database" | "breachdatabase" => OsintSource::BreachDatabase,
        "social" | "social_media" | "socialmedia" => OsintSource::SocialMedia,
        "public_records" | "publicrecords" => OsintSource::PublicRecords,
        "code_repository" | "coderepository" | "repo" => OsintSource::CodeRepository,
        "web_archive" | "webarchive" | "archive" => OsintSource::WebArchive,
        "pastebin" | "paste" => OsintSource::Pastebin,
        _ => OsintSource::PublicRecords,
    }
}

fn build_employees(
    employee_data: &[EmployeeEntry<'_>],
    email_patterns: &[EmailPattern],
    domain: &str,
) -> Vec<EmployeeInfo> {
    employee_data
        .iter()
        .map(|(name, role, department, source_str)| {
            let pattern = infer_email_for_employee(name, email_patterns, domain);
            EmployeeInfo {
                name: name.to_string(),
                role: role.map(|r| r.to_string()),
                department: department.map(|d| d.to_string()),
                email_pattern: pattern,
                source: parse_osint_source(source_str),
                confidence: 0.7,
            }
        })
        .collect()
}

fn infer_email_for_employee(name: &str, patterns: &[EmailPattern], domain: &str) -> Option<String> {
    let best = patterns
        .iter()
        .max_by(|a, b| a.confidence.partial_cmp(&b.confidence).unwrap())?;

    let parts: Vec<&str> = name.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }

    let first = parts[0].to_lowercase();
    let last = parts.last().unwrap().to_lowercase();

    let local = match best.pattern.as_str() {
        "first.last@domain" => format!("{first}.{last}"),
        "flast@domain" => format!("{}.{last}", first.chars().next().unwrap_or('x')),
        "firstl@domain" => format!("{first}.{}", last.chars().next().unwrap_or('x')),
        "first_last@domain" => format!("{first}_{last}"),
        "first-last@domain" => format!("{first}-{last}"),
        "firstlast@domain" => format!("{first}{last}"),
        "first@domain" => first.to_string(),
        _ => return None,
    };

    Some(format!("{local}@{domain}"))
}

/// Main entry point: combine all OSINT analysis into a unified report.
#[allow(clippy::too_many_arguments)]
pub fn gather_osint(
    domain: &str,
    known_emails: &[&str],
    job_postings: &[&str],
    breach_data: &[BreachEntry<'_>],
    repo_data: &[RepoEntry<'_>],
    social_profiles: &[SocialEntry<'_>],
    employee_data: &[EmployeeEntry<'_>],
) -> OsintReport {
    let email_patterns = infer_email_patterns(known_emails, domain);
    let tech_stack = extract_tech_from_job_postings(job_postings);
    let breaches = correlate_breaches(domain, breach_data);
    let repositories = enumerate_repositories(repo_data);
    let social_media = map_social_profiles(social_profiles);
    let employees = build_employees(employee_data, &email_patterns, domain);
    let org_structure = if employees.is_empty() {
        None
    } else {
        Some(build_org_structure(&employees, &tech_stack))
    };

    let mut report = OsintReport {
        domain: domain.to_string(),
        employees,
        email_patterns,
        tech_stack,
        org_structure,
        breaches,
        social_media,
        repositories,
        risk_score: 0.0,
    };

    report.risk_score = calculate_osint_risk(&report);
    report
}
