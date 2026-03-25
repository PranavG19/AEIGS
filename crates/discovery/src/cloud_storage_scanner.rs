/// Cloud storage misconfiguration scanner.
///
/// Detects misconfigured S3 buckets, Azure Blob containers, GCP buckets,
/// and DigitalOcean Spaces. Generates candidate bucket names from a
/// discovered domain and checks each permission level (read, write, list).
/// Supported cloud storage providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CloudStorageProvider {
    AwsS3,
    AzureBlob,
    GcpStorage,
    DigitalOceanSpaces,
}

impl std::fmt::Display for CloudStorageProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AwsS3 => write!(f, "AWS S3"),
            Self::AzureBlob => write!(f, "Azure Blob Storage"),
            Self::GcpStorage => write!(f, "GCP Cloud Storage"),
            Self::DigitalOceanSpaces => write!(f, "DigitalOcean Spaces"),
        }
    }
}

impl CloudStorageProvider {
    /// All supported providers.
    pub fn all() -> &'static [CloudStorageProvider] {
        &[
            Self::AwsS3,
            Self::AzureBlob,
            Self::GcpStorage,
            Self::DigitalOceanSpaces,
        ]
    }

    /// URL template for testing bucket existence / listing.
    pub fn bucket_url(&self, bucket_name: &str) -> String {
        match self {
            Self::AwsS3 => format!("https://{}.s3.amazonaws.com/", bucket_name),
            Self::AzureBlob => format!("https://{}.blob.core.windows.net/?comp=list", bucket_name),
            Self::GcpStorage => {
                format!("https://storage.googleapis.com/{}/", bucket_name)
            }
            Self::DigitalOceanSpaces => {
                format!("https://{}.nyc3.digitaloceanspaces.com/", bucket_name)
            }
        }
    }

    /// URL template for testing a specific permission action.
    pub fn permission_test_url(&self, bucket_name: &str, action: BucketPermission) -> String {
        match (self, action) {
            (Self::AwsS3, BucketPermission::Read) => {
                format!("https://{}.s3.amazonaws.com/", bucket_name)
            }
            (Self::AwsS3, BucketPermission::Write) => {
                format!("https://{}.s3.amazonaws.com/__test_write__", bucket_name)
            }
            (Self::AwsS3, BucketPermission::List) => {
                format!("https://{}.s3.amazonaws.com/?list-type=2", bucket_name)
            }
            (Self::AzureBlob, BucketPermission::Read) => {
                format!("https://{}.blob.core.windows.net/", bucket_name)
            }
            (Self::AzureBlob, BucketPermission::Write) => {
                format!(
                    "https://{}.blob.core.windows.net/__test_write__",
                    bucket_name
                )
            }
            (Self::AzureBlob, BucketPermission::List) => {
                format!(
                    "https://{}.blob.core.windows.net/?comp=list&restype=container",
                    bucket_name
                )
            }
            (Self::GcpStorage, BucketPermission::Read) => {
                format!("https://storage.googleapis.com/{}/", bucket_name)
            }
            (Self::GcpStorage, BucketPermission::Write) => {
                format!(
                    "https://storage.googleapis.com/upload/storage/v1/b/{}/o?uploadType=media",
                    bucket_name
                )
            }
            (Self::GcpStorage, BucketPermission::List) => {
                format!(
                    "https://storage.googleapis.com/storage/v1/b/{}/o",
                    bucket_name
                )
            }
            (Self::DigitalOceanSpaces, BucketPermission::Read) => {
                format!("https://{}.nyc3.digitaloceanspaces.com/", bucket_name)
            }
            (Self::DigitalOceanSpaces, BucketPermission::Write) => {
                format!(
                    "https://{}.nyc3.digitaloceanspaces.com/__test_write__",
                    bucket_name
                )
            }
            (Self::DigitalOceanSpaces, BucketPermission::List) => {
                format!(
                    "https://{}.nyc3.digitaloceanspaces.com/?list-type=2",
                    bucket_name
                )
            }
        }
    }
}

/// The permission level being tested on a storage bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BucketPermission {
    Read,
    Write,
    List,
}

impl BucketPermission {
    pub fn all() -> &'static [BucketPermission] {
        &[Self::Read, Self::Write, Self::List]
    }
}

impl std::fmt::Display for BucketPermission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read => write!(f, "Read"),
            Self::Write => write!(f, "Write"),
            Self::List => write!(f, "List"),
        }
    }
}

/// Severity of a misconfigured bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BucketSeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl BucketSeverity {
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

/// Determines severity based on which permissions are open.
pub fn severity_for_permissions(permissions: &[BucketPermission]) -> BucketSeverity {
    let has_write = permissions.contains(&BucketPermission::Write);
    let has_list = permissions.contains(&BucketPermission::List);
    let has_read = permissions.contains(&BucketPermission::Read);

    if has_write {
        BucketSeverity::Critical
    } else if has_list {
        BucketSeverity::High
    } else if has_read {
        BucketSeverity::Medium
    } else {
        BucketSeverity::Informational
    }
}

/// Common suffixes appended to domain-derived bucket names.
pub const BUCKET_NAME_SUFFIXES: &[&str] = &[
    "",
    "-backup",
    "-backups",
    "-dev",
    "-development",
    "-staging",
    "-stage",
    "-stg",
    "-prod",
    "-production",
    "-test",
    "-testing",
    "-qa",
    "-uat",
    "-data",
    "-assets",
    "-static",
    "-media",
    "-uploads",
    "-images",
    "-files",
    "-docs",
    "-documents",
    "-logs",
    "-archive",
    "-public",
    "-private",
    "-internal",
    "-cdn",
    "-web",
    "-api",
    "-app",
    "-config",
    "-db",
    "-database",
    "-dump",
    "-export",
    "-import",
    "-temp",
    "-tmp",
];

/// Generate candidate bucket names from a domain.
///
/// Given `example.com`, produces `example`, `example-com`, `example.com`,
/// `examplecom`, plus each with every suffix from `BUCKET_NAME_SUFFIXES`.
pub fn generate_bucket_names(domain: &str) -> Vec<String> {
    let stripped = domain
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/');

    let parts: Vec<&str> = stripped.split('.').collect();

    let mut bases = Vec::new();
    if let Some(first) = parts.first() {
        bases.push(first.to_string());
    }
    if parts.len() >= 2 {
        bases.push(format!("{}-{}", parts[0], parts[1]));
        bases.push(stripped.to_string());
        bases.push(parts.join(""));
    }

    let mut names = Vec::new();
    for base in &bases {
        for suffix in BUCKET_NAME_SUFFIXES {
            names.push(format!("{}{}", base, suffix));
        }
    }
    names.sort();
    names.dedup();
    names
}

/// A candidate bucket to check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketCandidate {
    pub provider: CloudStorageProvider,
    pub bucket_name: String,
    pub base_url: String,
}

/// Generate bucket candidates for all providers from a domain.
pub fn candidates_for_domain(domain: &str) -> Vec<BucketCandidate> {
    let names = generate_bucket_names(domain);
    let mut candidates = Vec::new();
    for provider in CloudStorageProvider::all() {
        for name in &names {
            candidates.push(BucketCandidate {
                provider: *provider,
                bucket_name: name.clone(),
                base_url: provider.bucket_url(name),
            });
        }
    }
    candidates
}

/// A confirmed misconfiguration finding for a cloud storage bucket.
#[derive(Debug, Clone, PartialEq)]
pub struct CloudStorageFinding {
    pub provider: CloudStorageProvider,
    pub bucket_name: String,
    pub open_permissions: Vec<BucketPermission>,
    pub severity: BucketSeverity,
    pub detail: String,
    pub test_urls: Vec<String>,
}

/// Build a finding from a bucket candidate and the permissions confirmed open.
pub fn finding_from_candidate(
    candidate: &BucketCandidate,
    open_permissions: Vec<BucketPermission>,
) -> CloudStorageFinding {
    let severity = severity_for_permissions(&open_permissions);
    let test_urls: Vec<String> = open_permissions
        .iter()
        .map(|p| {
            candidate
                .provider
                .permission_test_url(&candidate.bucket_name, *p)
        })
        .collect();
    let perm_labels: Vec<String> = open_permissions.iter().map(|p| p.to_string()).collect();
    CloudStorageFinding {
        provider: candidate.provider,
        bucket_name: candidate.bucket_name.clone(),
        open_permissions,
        severity,
        detail: format!(
            "{} bucket '{}' allows anonymous {} access",
            candidate.provider,
            candidate.bucket_name,
            perm_labels.join(", ")
        ),
        test_urls,
    }
}

/// Probe specification for checking a single bucket across all permission levels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketProbe {
    pub provider: CloudStorageProvider,
    pub bucket_name: String,
    pub check_urls: Vec<(BucketPermission, String)>,
}

/// Build a probe for a candidate bucket that tests all permission levels.
pub fn build_bucket_probe(candidate: &BucketCandidate) -> BucketProbe {
    let check_urls = BucketPermission::all()
        .iter()
        .map(|p| {
            (
                *p,
                candidate
                    .provider
                    .permission_test_url(&candidate.bucket_name, *p),
            )
        })
        .collect();
    BucketProbe {
        provider: candidate.provider,
        bucket_name: candidate.bucket_name.clone(),
        check_urls,
    }
}

/// Policy analysis patterns for S3 bucket policies.
pub const S3_DANGEROUS_ACTIONS: &[&str] = &[
    "s3:GetObject",
    "s3:PutObject",
    "s3:DeleteObject",
    "s3:ListBucket",
    "s3:GetBucketAcl",
    "s3:PutBucketAcl",
    "s3:*",
];

/// Principal values that indicate public access in S3 policies.
pub const S3_PUBLIC_PRINCIPALS: &[&str] = &["*", "arn:aws:iam::*"];

/// Classify an S3 policy statement as dangerous based on principal and action.
pub fn is_dangerous_s3_statement(principal: &str, actions: &[&str]) -> bool {
    let is_public_principal = S3_PUBLIC_PRINCIPALS.iter().any(|p| principal.contains(p));
    let has_dangerous_action = actions
        .iter()
        .any(|a| S3_DANGEROUS_ACTIONS.iter().any(|d| a.contains(d)));
    is_public_principal && has_dangerous_action
}

/// Scanner struct wrapping domain-based bucket enumeration.
pub struct CloudStorageScanner {
    pub domain: String,
    pub providers: Vec<CloudStorageProvider>,
}

impl CloudStorageScanner {
    pub fn new(domain: &str) -> Self {
        Self {
            domain: domain.to_string(),
            providers: CloudStorageProvider::all().to_vec(),
        }
    }

    pub fn with_providers(mut self, providers: Vec<CloudStorageProvider>) -> Self {
        self.providers = providers;
        self
    }

    /// Generate all candidates for the configured providers.
    pub fn candidates(&self) -> Vec<BucketCandidate> {
        let names = generate_bucket_names(&self.domain);
        let mut candidates = Vec::new();
        for provider in &self.providers {
            for name in &names {
                candidates.push(BucketCandidate {
                    provider: *provider,
                    bucket_name: name.clone(),
                    base_url: provider.bucket_url(name),
                });
            }
        }
        candidates
    }

    /// Generate probes for all candidates.
    pub fn probes(&self) -> Vec<BucketProbe> {
        self.candidates().iter().map(build_bucket_probe).collect()
    }
}
