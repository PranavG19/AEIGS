use std::fmt;

use regex::Regex;

const PUBLIC_LISTING_SEVERITY: f64 = 8.0;
const PUBLIC_READ_SEVERITY: f64 = 7.5;
const OPEN_FIREBASE_SEVERITY: f64 = 9.0;

const REQUEST_TIMEOUT_SECS: u64 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CloudResource {
    AwsS3Bucket,
    AzureBlobStorage,
    GcpStorageBucket,
    FirebaseDatabase,
}

impl fmt::Display for CloudResource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::AwsS3Bucket => "aws-s3-bucket",
            Self::AzureBlobStorage => "azure-blob-storage",
            Self::GcpStorageBucket => "gcp-storage-bucket",
            Self::FirebaseDatabase => "firebase-database",
        };
        write!(f, "{label}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CloudIssue {
    PublicListing,
    PublicReadAccess,
    OpenFirebase,
}

impl CloudIssue {
    pub fn severity(self) -> f64 {
        match self {
            Self::PublicListing => PUBLIC_LISTING_SEVERITY,
            Self::PublicReadAccess => PUBLIC_READ_SEVERITY,
            Self::OpenFirebase => OPEN_FIREBASE_SEVERITY,
        }
    }
}

impl fmt::Display for CloudIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::PublicListing => "public-listing",
            Self::PublicReadAccess => "public-read-access",
            Self::OpenFirebase => "open-firebase",
        };
        write!(f, "{label}")
    }
}

#[derive(Debug, Clone)]
pub struct CloudFinding {
    pub resource_type: CloudResource,
    pub resource_url: String,
    pub issue: CloudIssue,
    pub severity: f64,
    pub evidence: String,
}

pub struct CloudDetector {
    client: reqwest::blocking::Client,
}

impl Default for CloudDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl CloudDetector {
    pub fn new() -> Self {
        Self {
            client: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS))
                .build()
                .expect("failed to build HTTP client"),
        }
    }

    pub fn with_client(client: reqwest::blocking::Client) -> Self {
        Self { client }
    }

    pub fn scan_responses(&self, responses: &[(String, String)]) -> Vec<CloudFinding> {
        let mut findings = Vec::new();
        for (_url, body) in responses {
            let references = extract_cloud_references(body);
            for (resource_type, resource_url) in references {
                let result = match resource_type {
                    CloudResource::AwsS3Bucket => self.test_s3_bucket(&resource_url),
                    CloudResource::AzureBlobStorage => self.test_azure_blob(&resource_url),
                    CloudResource::GcpStorageBucket => self.test_gcp_bucket(&resource_url),
                    CloudResource::FirebaseDatabase => self.test_firebase(&resource_url),
                };
                if let Some(finding) = result {
                    findings.push(finding);
                }
            }
        }
        findings
    }

    pub(crate) fn test_s3_bucket(&self, bucket_url: &str) -> Option<CloudFinding> {
        let list_url = format!("{bucket_url}?list-type=2&max-keys=5");
        let resp = self.client.get(&list_url).send().ok()?;

        if resp.status().is_success() {
            let body = resp.text().ok()?;
            if body.contains("<Contents>") {
                return Some(CloudFinding {
                    resource_type: CloudResource::AwsS3Bucket,
                    resource_url: bucket_url.to_string(),
                    issue: CloudIssue::PublicListing,
                    severity: CloudIssue::PublicListing.severity(),
                    evidence: format!("S3 bucket listing enabled at {bucket_url}"),
                });
            }
        }

        None
    }

    pub(crate) fn test_firebase(&self, firebase_url: &str) -> Option<CloudFinding> {
        let json_url = format!("{firebase_url}/.json");
        let resp = self.client.get(&json_url).send().ok()?;

        if resp.status().is_success() {
            let body = resp.text().ok()?;
            if body.trim() != "\"null\"" && body.trim() != "null" {
                return Some(CloudFinding {
                    resource_type: CloudResource::FirebaseDatabase,
                    resource_url: firebase_url.to_string(),
                    issue: CloudIssue::OpenFirebase,
                    severity: CloudIssue::OpenFirebase.severity(),
                    evidence: format!("Firebase database openly readable at {firebase_url}"),
                });
            }
        }

        None
    }

    pub(crate) fn test_azure_blob(&self, container_url: &str) -> Option<CloudFinding> {
        let list_url = format!("{container_url}?restype=container&comp=list");
        let resp = self.client.get(&list_url).send().ok()?;

        if resp.status().is_success() {
            let body = resp.text().ok()?;
            if body.contains("<Blob>") {
                return Some(CloudFinding {
                    resource_type: CloudResource::AzureBlobStorage,
                    resource_url: container_url.to_string(),
                    issue: CloudIssue::PublicListing,
                    severity: CloudIssue::PublicListing.severity(),
                    evidence: format!("Azure blob container listing enabled at {container_url}"),
                });
            }
        }

        None
    }

    fn test_gcp_bucket(&self, bucket_url: &str) -> Option<CloudFinding> {
        let list_url = format!("{bucket_url}?list-type=2&max-keys=5");
        let resp = self.client.get(&list_url).send().ok()?;

        if resp.status().is_success() {
            let body = resp.text().ok()?;
            if body.contains("<Contents>") {
                return Some(CloudFinding {
                    resource_type: CloudResource::GcpStorageBucket,
                    resource_url: bucket_url.to_string(),
                    issue: CloudIssue::PublicListing,
                    severity: CloudIssue::PublicListing.severity(),
                    evidence: format!("GCP storage bucket listing enabled at {bucket_url}"),
                });
            }
        }

        None
    }
}

pub fn extract_cloud_references(response_body: &str) -> Vec<(CloudResource, String)> {
    let mut references = Vec::new();

    let s3_subdomain =
        Regex::new(r"([\w.-]+)\.s3\.amazonaws\.com").expect("invalid S3 subdomain regex");
    let s3_path = Regex::new(r"://s3\.amazonaws\.com/([\w.-]+)").expect("invalid S3 path regex");
    let azure_blob =
        Regex::new(r"([\w.-]+)\.blob\.core\.windows\.net").expect("invalid Azure blob regex");
    let gcp_storage =
        Regex::new(r"storage\.googleapis\.com/([\w.-]+)").expect("invalid GCP storage regex");
    let firebase = Regex::new(r"([\w-]+)\.firebaseio\.com").expect("invalid Firebase regex");

    for cap in s3_subdomain.captures_iter(response_body) {
        let bucket = &cap[1];
        let url = format!("https://{bucket}.s3.amazonaws.com");
        references.push((CloudResource::AwsS3Bucket, url));
    }

    for cap in s3_path.captures_iter(response_body) {
        let bucket = &cap[1];
        let url = format!("https://s3.amazonaws.com/{bucket}");
        references.push((CloudResource::AwsS3Bucket, url));
    }

    for cap in azure_blob.captures_iter(response_body) {
        let account = &cap[1];
        let url = format!("https://{account}.blob.core.windows.net");
        references.push((CloudResource::AzureBlobStorage, url));
    }

    for cap in gcp_storage.captures_iter(response_body) {
        let bucket = &cap[1];
        let url = format!("https://storage.googleapis.com/{bucket}");
        references.push((CloudResource::GcpStorageBucket, url));
    }

    for cap in firebase.captures_iter(response_body) {
        let project = &cap[1];
        let url = format!("https://{project}.firebaseio.com");
        references.push((CloudResource::FirebaseDatabase, url));
    }

    references
}

#[cfg(test)]
#[path = "cloud_detector_test.rs"]
mod cloud_detector_test;
