use aegis_protocol::finding::VulnerabilityClass;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Severity level aligned with CVSS qualitative ratings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GroundTruthSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl GroundTruthSeverity {
    /// Returns a numeric weight for sorting and scoring.
    pub fn weight(&self) -> f64 {
        match self {
            GroundTruthSeverity::Critical => 10.0,
            GroundTruthSeverity::High => 8.0,
            GroundTruthSeverity::Medium => 5.0,
            GroundTruthSeverity::Low => 2.0,
            GroundTruthSeverity::Info => 0.5,
        }
    }
}

/// HTTP method for the annotated endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Options,
    Head,
}

/// A single ground truth annotation for one finding at one endpoint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GroundTruthAnnotation {
    /// The endpoint path (e.g. "/api/users").
    pub endpoint: String,
    /// HTTP method.
    pub method: HttpMethod,
    /// Expected vulnerability class.
    pub vulnerability_class: VulnerabilityClass,
    /// Severity rating.
    pub severity: GroundTruthSeverity,
    /// CWE identifier (e.g. "CWE-89").
    pub cwe_id: String,
    /// CVSS 3.1 base score (0.0 - 10.0).
    pub cvss_score: Option<f64>,
    /// Vulnerable parameter name, if applicable.
    pub parameter: Option<String>,
    /// Human-readable description of the vulnerability.
    pub description: String,
    /// Whether this is a true positive (expected to be found).
    pub expected_detected: bool,
}

/// Complete ground truth manifest for a test fixture.
///
/// Maps endpoints to their expected vulnerability findings. Supports
/// JSON serialization for persistence and comparison against scan results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundTruthManifest {
    /// Schema version for forward compatibility.
    pub version: u32,
    /// Name of the fixture this manifest describes.
    pub fixture_name: String,
    /// All annotations.
    pub annotations: Vec<GroundTruthAnnotation>,
}

impl GroundTruthManifest {
    /// Creates a new empty manifest for the given fixture.
    pub fn new(fixture_name: &str) -> Self {
        Self {
            version: 2,
            fixture_name: fixture_name.to_string(),
            annotations: Vec::new(),
        }
    }

    /// Adds an annotation to the manifest. Returns `&mut Self` for chaining.
    pub fn add(&mut self, annotation: GroundTruthAnnotation) -> &mut Self {
        self.annotations.push(annotation);
        self
    }

    /// Returns annotations for a specific endpoint path.
    pub fn for_endpoint(&self, endpoint: &str) -> Vec<&GroundTruthAnnotation> {
        self.annotations
            .iter()
            .filter(|a| a.endpoint == endpoint)
            .collect()
    }

    /// Returns annotations for a specific vulnerability class.
    pub fn for_class(&self, class: VulnerabilityClass) -> Vec<&GroundTruthAnnotation> {
        self.annotations
            .iter()
            .filter(|a| a.vulnerability_class == class)
            .collect()
    }

    /// Returns annotations at a given severity level.
    pub fn for_severity(&self, severity: GroundTruthSeverity) -> Vec<&GroundTruthAnnotation> {
        self.annotations
            .iter()
            .filter(|a| a.severity == severity)
            .collect()
    }

    /// Returns the total number of annotations.
    pub fn count(&self) -> usize {
        self.annotations.len()
    }

    /// Returns unique endpoints.
    pub fn endpoints(&self) -> Vec<String> {
        let mut eps: Vec<String> = self
            .annotations
            .iter()
            .map(|a| a.endpoint.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        eps.sort();
        eps
    }

    /// Returns unique vulnerability classes present in the manifest.
    pub fn vulnerability_classes(&self) -> Vec<VulnerabilityClass> {
        let mut classes: Vec<VulnerabilityClass> = self
            .annotations
            .iter()
            .map(|a| a.vulnerability_class)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        classes.sort_by_key(|c| format!("{c:?}"));
        classes
    }

    /// Returns a severity distribution as a count map.
    pub fn severity_distribution(&self) -> HashMap<GroundTruthSeverity, usize> {
        let mut map = HashMap::new();
        for ann in &self.annotations {
            *map.entry(ann.severity).or_insert(0) += 1;
        }
        map
    }

    /// Returns the total weighted severity score (sum of severity weights).
    pub fn total_severity_score(&self) -> f64 {
        self.annotations.iter().map(|a| a.severity.weight()).sum()
    }

    /// Serializes to pretty JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserializes from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Compares scanner findings against ground truth and returns metrics.
    ///
    /// `findings` is a list of `(endpoint, vulnerability_class)` tuples
    /// representing what the scanner actually found.
    pub fn evaluate(&self, findings: &[(String, VulnerabilityClass)]) -> GroundTruthEvaluation {
        let expected: std::collections::HashSet<(String, VulnerabilityClass)> = self
            .annotations
            .iter()
            .filter(|a| a.expected_detected)
            .map(|a| (a.endpoint.clone(), a.vulnerability_class))
            .collect();

        let found: std::collections::HashSet<(String, VulnerabilityClass)> =
            findings.iter().cloned().collect();

        let true_positives: Vec<(String, VulnerabilityClass)> =
            expected.intersection(&found).cloned().collect();
        let false_negatives: Vec<(String, VulnerabilityClass)> =
            expected.difference(&found).cloned().collect();
        let false_positives: Vec<(String, VulnerabilityClass)> =
            found.difference(&expected).cloned().collect();

        let tp = true_positives.len() as f64;
        let fp = false_positives.len() as f64;
        let fn_ = false_negatives.len() as f64;

        let precision = if tp + fp > 0.0 { tp / (tp + fp) } else { 0.0 };
        let recall = if tp + fn_ > 0.0 { tp / (tp + fn_) } else { 0.0 };
        let f1 = if precision + recall > 0.0 {
            2.0 * precision * recall / (precision + recall)
        } else {
            0.0
        };

        GroundTruthEvaluation {
            true_positives,
            false_positives,
            false_negatives,
            precision,
            recall,
            f1,
        }
    }
}

/// Evaluation result comparing scanner findings to ground truth.
#[derive(Debug, Clone)]
pub struct GroundTruthEvaluation {
    pub true_positives: Vec<(String, VulnerabilityClass)>,
    pub false_positives: Vec<(String, VulnerabilityClass)>,
    pub false_negatives: Vec<(String, VulnerabilityClass)>,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
}

/// Builder for constructing individual annotations fluently.
pub struct AnnotationBuilder {
    endpoint: String,
    method: HttpMethod,
    vulnerability_class: VulnerabilityClass,
    severity: GroundTruthSeverity,
    cwe_id: String,
    cvss_score: Option<f64>,
    parameter: Option<String>,
    description: String,
    expected_detected: bool,
}

impl AnnotationBuilder {
    pub fn new(endpoint: &str, class: VulnerabilityClass) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            method: HttpMethod::Get,
            vulnerability_class: class,
            severity: GroundTruthSeverity::Medium,
            cwe_id: String::new(),
            cvss_score: None,
            parameter: None,
            description: String::new(),
            expected_detected: true,
        }
    }

    pub fn method(mut self, method: HttpMethod) -> Self {
        self.method = method;
        self
    }

    pub fn severity(mut self, severity: GroundTruthSeverity) -> Self {
        self.severity = severity;
        self
    }

    pub fn cwe(mut self, cwe: &str) -> Self {
        self.cwe_id = cwe.to_string();
        self
    }

    pub fn cvss(mut self, score: f64) -> Self {
        self.cvss_score = Some(score);
        self
    }

    pub fn parameter(mut self, param: &str) -> Self {
        self.parameter = Some(param.to_string());
        self
    }

    pub fn description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    pub fn expected_detected(mut self, detected: bool) -> Self {
        self.expected_detected = detected;
        self
    }

    pub fn build(self) -> GroundTruthAnnotation {
        GroundTruthAnnotation {
            endpoint: self.endpoint,
            method: self.method,
            vulnerability_class: self.vulnerability_class,
            severity: self.severity,
            cwe_id: self.cwe_id,
            cvss_score: self.cvss_score,
            parameter: self.parameter,
            description: self.description,
            expected_detected: self.expected_detected,
        }
    }
}

/// Creates a pre-populated ground truth manifest for the Express vulnerable
/// app (defense-stacks/express-vuln-app).
pub fn express_ground_truth() -> GroundTruthManifest {
    let mut m = GroundTruthManifest::new("express-vuln-app");

    m.add(
        AnnotationBuilder::new("/api/search", VulnerabilityClass::SqlInjection)
            .severity(GroundTruthSeverity::Critical)
            .cwe("CWE-89")
            .cvss(9.8)
            .parameter("q")
            .description("SQL injection via string concatenation in search query")
            .build(),
    );
    m.add(
        AnnotationBuilder::new("/api/render", VulnerabilityClass::CrossSiteScripting)
            .severity(GroundTruthSeverity::High)
            .cwe("CWE-79")
            .cvss(6.1)
            .parameter("name")
            .description("Reflected XSS via unescaped template parameter")
            .build(),
    );
    m.add(
        AnnotationBuilder::new("/api/exec", VulnerabilityClass::CommandInjection)
            .severity(GroundTruthSeverity::Critical)
            .cwe("CWE-78")
            .cvss(9.8)
            .parameter("cmd")
            .description("OS command injection via shell exec")
            .build(),
    );
    m.add(
        AnnotationBuilder::new("/api/files", VulnerabilityClass::PathTraversal)
            .severity(GroundTruthSeverity::High)
            .cwe("CWE-22")
            .cvss(7.5)
            .parameter("path")
            .description("Path traversal via unvalidated file path parameter")
            .build(),
    );
    m.add(
        AnnotationBuilder::new("/api/ssrf", VulnerabilityClass::ServerSideRequestForgery)
            .severity(GroundTruthSeverity::High)
            .cwe("CWE-918")
            .cvss(7.5)
            .parameter("url")
            .description("SSRF via user-supplied URL parameter")
            .build(),
    );
    m.add(
        AnnotationBuilder::new(
            "/api/template",
            VulnerabilityClass::ServerSideTemplateInjection,
        )
        .severity(GroundTruthSeverity::High)
        .cwe("CWE-1336")
        .cvss(7.5)
        .parameter("expr")
        .description("SSTI via unvalidated template expression")
        .build(),
    );
    m.add(
        AnnotationBuilder::new("/api/admin", VulnerabilityClass::BrokenAuthentication)
            .severity(GroundTruthSeverity::Critical)
            .cwe("CWE-306")
            .cvss(9.1)
            .description("Admin endpoint accessible without authentication")
            .build(),
    );
    m.add(
        AnnotationBuilder::new("/api/user", VulnerabilityClass::BrokenAuthorization)
            .severity(GroundTruthSeverity::High)
            .cwe("CWE-639")
            .cvss(7.5)
            .parameter("id")
            .description("IDOR via sequential user ID parameter")
            .build(),
    );
    m.add(
        AnnotationBuilder::new("/api/redirect", VulnerabilityClass::OpenRedirect)
            .severity(GroundTruthSeverity::Medium)
            .cwe("CWE-601")
            .cvss(4.7)
            .parameter("url")
            .description("Open redirect via unvalidated URL parameter")
            .build(),
    );
    m.add(
        AnnotationBuilder::new("/api/debug", VulnerabilityClass::SecurityMisconfiguration)
            .severity(GroundTruthSeverity::Medium)
            .cwe("CWE-215")
            .cvss(5.3)
            .description("Debug endpoint exposing stack traces and environment")
            .build(),
    );
    m.add(
        AnnotationBuilder::new("/api/data", VulnerabilityClass::SensitiveDataExposure)
            .severity(GroundTruthSeverity::High)
            .cwe("CWE-312")
            .cvss(7.5)
            .description("API keys and credentials in plaintext response")
            .build(),
    );
    m.add(
        AnnotationBuilder::new(
            "/api/deserialize",
            VulnerabilityClass::InsecureDeserialization,
        )
        .method(HttpMethod::Post)
        .severity(GroundTruthSeverity::Critical)
        .cwe("CWE-502")
        .cvss(9.8)
        .parameter("data")
        .description("Unsafe deserialization of user-controlled input")
        .build(),
    );

    m
}

/// Creates a pre-populated ground truth manifest for the Flask vulnerable
/// app (defense-stacks/flask-vuln-app).
pub fn flask_ground_truth() -> GroundTruthManifest {
    let mut m = GroundTruthManifest::new("flask-vuln-app");

    m.add(
        AnnotationBuilder::new("/search", VulnerabilityClass::SqlInjection)
            .severity(GroundTruthSeverity::Critical)
            .cwe("CWE-89")
            .cvss(9.8)
            .parameter("q")
            .description("SQL injection in search endpoint")
            .build(),
    );
    m.add(
        AnnotationBuilder::new("/render", VulnerabilityClass::CrossSiteScripting)
            .severity(GroundTruthSeverity::High)
            .cwe("CWE-79")
            .cvss(6.1)
            .parameter("name")
            .description("Reflected XSS via Jinja2 safe filter misuse")
            .build(),
    );
    m.add(
        AnnotationBuilder::new("/exec", VulnerabilityClass::CommandInjection)
            .severity(GroundTruthSeverity::Critical)
            .cwe("CWE-78")
            .cvss(9.8)
            .parameter("cmd")
            .description("OS command injection via subprocess")
            .build(),
    );
    m.add(
        AnnotationBuilder::new("/files", VulnerabilityClass::PathTraversal)
            .severity(GroundTruthSeverity::High)
            .cwe("CWE-22")
            .cvss(7.5)
            .parameter("path")
            .description("Path traversal via send_file")
            .build(),
    );
    m.add(
        AnnotationBuilder::new("/template", VulnerabilityClass::ServerSideTemplateInjection)
            .severity(GroundTruthSeverity::High)
            .cwe("CWE-1336")
            .cvss(7.5)
            .parameter("expr")
            .description("SSTI via Jinja2 template rendering")
            .build(),
    );
    m.add(
        AnnotationBuilder::new("/debug", VulnerabilityClass::SecurityMisconfiguration)
            .severity(GroundTruthSeverity::Medium)
            .cwe("CWE-215")
            .cvss(5.3)
            .description("Debug mode enabled in production")
            .build(),
    );
    m.add(
        AnnotationBuilder::new("/redirect", VulnerabilityClass::OpenRedirect)
            .severity(GroundTruthSeverity::Medium)
            .cwe("CWE-601")
            .cvss(4.7)
            .parameter("url")
            .description("Open redirect via flask.redirect")
            .build(),
    );
    m.add(
        AnnotationBuilder::new("/data", VulnerabilityClass::SensitiveDataExposure)
            .severity(GroundTruthSeverity::High)
            .cwe("CWE-312")
            .cvss(7.5)
            .description("Credentials in JSON response body")
            .build(),
    );

    m
}

#[cfg(test)]
#[path = "ground_truth_v2_test.rs"]
mod tests;
