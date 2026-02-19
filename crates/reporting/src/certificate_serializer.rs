use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CertificateEnvelope {
    version: u16,
    payload: Vec<u8>,
}

#[derive(Debug)]
pub enum CertificateError {
    SerializeError(String),
    DeserializeError(String),
    UnsupportedVersion(u16),
}

impl std::fmt::Display for CertificateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SerializeError(msg) => write!(f, "serialize error: {msg}"),
            Self::DeserializeError(msg) => write!(f, "deserialize error: {msg}"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported certificate version: {v}"),
        }
    }
}

impl std::error::Error for CertificateError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CertificateType {
    Fuzzing,
    Taint,
    Chain,
    Config,
    Dependency,
    Evasion,
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
pub struct EvasionCertificate {
    pub original_payload: String,
    pub evasion_payload: String,
    pub defense_vendor: String,
    pub evasion_technique: String,
    pub block_response_status: u16,
    pub bypass_response_status: u16,
    pub anomaly_detected: bool,
}

const CURRENT_VERSION: u16 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Certificate {
    Fuzzing(FuzzingCertificate),
    Taint(TaintCertificate),
    Chain(ChainCertificate),
    Config(ConfigCertificate),
    Dependency(DependencyCertificate),
    Evasion(EvasionCertificate),
}

pub fn serialize_certificate(cert: &Certificate) -> Result<Vec<u8>, CertificateError> {
    let mut inner_buf = Vec::new();
    ciborium::into_writer(cert, &mut inner_buf)
        .map_err(|e| CertificateError::SerializeError(e.to_string()))?;
    let envelope = CertificateEnvelope {
        version: CURRENT_VERSION,
        payload: inner_buf,
    };
    let mut buf = Vec::new();
    ciborium::into_writer(&envelope, &mut buf)
        .map_err(|e| CertificateError::SerializeError(e.to_string()))?;
    Ok(buf)
}

pub fn deserialize_certificate(data: &[u8]) -> Result<Certificate, CertificateError> {
    let envelope: CertificateEnvelope = ciborium::from_reader(data)
        .map_err(|e| CertificateError::DeserializeError(e.to_string()))?;
    if envelope.version == 0 || envelope.version > CURRENT_VERSION {
        return Err(CertificateError::UnsupportedVersion(envelope.version));
    }
    ciborium::from_reader(envelope.payload.as_slice())
        .map_err(|e| CertificateError::DeserializeError(e.to_string()))
}

pub fn certificate_hash(data: &[u8]) -> [u8; 32] {
    use sha3::Digest;
    let mut hasher = sha3::Sha3_256::new();
    hasher.update(data);
    hasher.finalize().into()
}
