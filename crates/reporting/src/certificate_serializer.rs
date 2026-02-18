use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CertificateType {
    Fuzzing,
    Taint,
    Chain,
    Config,
    Dependency,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzingCertificate {
    pub request_method: String,
    pub request_url: String,
    pub request_headers: Vec<(String, String)>,
    pub request_body: Vec<u8>,
    pub response_status: u16,
    pub response_body: Vec<u8>,
    pub anomaly_type: String,
    pub statistical_significance: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintCertificate {
    pub source_location: SourceSinkLocation,
    pub sink_location: SourceSinkLocation,
    pub path_steps: Vec<TaintPathStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceSinkLocation {
    pub file: String,
    pub line: u32,
    pub function: String,
    pub variable: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintPathStep {
    pub file: String,
    pub line: u32,
    pub function: String,
    pub variable: String,
    pub operation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainCertificate {
    pub steps: Vec<ChainStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStep {
    pub vulnerability_id: u64,
    pub description: String,
    pub transition_condition: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigCertificate {
    pub config_key: String,
    pub current_value: String,
    pub expected_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyCertificate {
    pub package_name: String,
    pub installed_version: String,
    pub vulnerable_range: String,
    pub cve_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Certificate {
    Fuzzing(FuzzingCertificate),
    Taint(TaintCertificate),
    Chain(ChainCertificate),
    Config(ConfigCertificate),
    Dependency(DependencyCertificate),
}

pub fn serialize_certificate(
    cert: &Certificate,
) -> Result<Vec<u8>, ciborium::ser::Error<std::io::Error>> {
    let mut buf = Vec::new();
    ciborium::into_writer(cert, &mut buf)?;
    Ok(buf)
}

pub fn deserialize_certificate(
    data: &[u8],
) -> Result<Certificate, ciborium::de::Error<std::io::Error>> {
    ciborium::from_reader(data)
}

pub fn certificate_hash(data: &[u8]) -> [u8; 32] {
    use sha3::Digest;
    let mut hasher = sha3::Sha3_256::new();
    hasher.update(data);
    hasher.finalize().into()
}
