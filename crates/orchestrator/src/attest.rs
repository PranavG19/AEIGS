use aegis_protocol::scope_attestation::{
    days_to_ymd, sign_scope_document, ScopeDocument, SignedScopeAttestation,
};
use ed25519_dalek::SigningKey;
use std::path::{Path, PathBuf};

const DEFAULT_OUTPUT: &str = "scope-attestation.json";

/// CLI arguments for the `attest` subcommand that generates Ed25519-signed
/// scope attestation files for authorized remote scanning.
#[derive(Debug)]
pub struct AttestArgs {
    pub target: String,
    pub authorized_by: String,
    pub valid_days: u64,
    pub key_path: PathBuf,
    pub output_path: PathBuf,
}

/// Errors from the `attest` subcommand.
#[derive(Debug)]
pub enum AttestError {
    MissingArg(String),
    InvalidDays(String),
    KeyIo(String),
    KeyFormat(String),
    OutputIo(String),
}

impl std::fmt::Display for AttestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingArg(name) => write!(f, "missing required argument: --{name}"),
            Self::InvalidDays(val) => write!(f, "invalid --valid-days value: {val}"),
            Self::KeyIo(msg) => write!(f, "key file I/O error: {msg}"),
            Self::KeyFormat(msg) => write!(f, "key file format error: {msg}"),
            Self::OutputIo(msg) => write!(f, "output file I/O error: {msg}"),
        }
    }
}

impl std::error::Error for AttestError {}

pub fn parse_attest_args(args: &[String]) -> Result<AttestArgs, AttestError> {
    let target = find_flag(args, "target").ok_or(AttestError::MissingArg("target".to_string()))?;
    let authorized_by = find_flag(args, "authorized-by")
        .ok_or(AttestError::MissingArg("authorized-by".to_string()))?;
    let valid_days_str =
        find_flag(args, "valid-days").ok_or(AttestError::MissingArg("valid-days".to_string()))?;
    let valid_days: u64 = valid_days_str
        .parse()
        .map_err(|_| AttestError::InvalidDays(valid_days_str.clone()))?;
    if valid_days == 0 {
        return Err(AttestError::InvalidDays(valid_days_str));
    }
    let key_path_str = find_flag(args, "key").ok_or(AttestError::MissingArg("key".to_string()))?;
    let output_path_str = find_flag(args, "output").unwrap_or(DEFAULT_OUTPUT.to_string());

    Ok(AttestArgs {
        target,
        authorized_by,
        valid_days,
        key_path: PathBuf::from(key_path_str),
        output_path: PathBuf::from(output_path_str),
    })
}

pub fn run_attest(args: &AttestArgs) -> Result<PathBuf, AttestError> {
    let signing_key = load_or_generate_key(&args.key_path)?;
    let valid_until = compute_valid_until(args.valid_days);
    let scope_id = generate_scope_id();

    let document = ScopeDocument {
        target: args.target.clone(),
        authorized_by: args.authorized_by.clone(),
        valid_until,
        scope_id,
    };

    let attestation = sign_scope_document(&document, &signing_key);
    write_attestation(&attestation, &args.output_path)?;

    println!("Attestation written to: {}", args.output_path.display());
    println!("Public key (hex): {}", attestation.public_key_hex);

    Ok(args.output_path.clone())
}

fn load_or_generate_key(path: &Path) -> Result<SigningKey, AttestError> {
    if !path.exists() {
        let secret: [u8; 32] = rand::random();
        write_key_file(path, &secret)?;
        println!("Generated new Ed25519 signing key: {}", path.display());
    }

    let bytes = std::fs::read(path).map_err(|e| AttestError::KeyIo(e.to_string()))?;
    let len = bytes.len();
    let secret: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AttestError::KeyFormat(format!("expected 32 bytes, got {len}")))?;
    Ok(SigningKey::from_bytes(&secret))
}

fn write_attestation(attestation: &SignedScopeAttestation, path: &Path) -> Result<(), AttestError> {
    let json = serde_json::to_string_pretty(attestation)
        .map_err(|e| AttestError::OutputIo(e.to_string()))?;
    std::fs::write(path, json).map_err(|e| AttestError::OutputIo(e.to_string()))
}

fn compute_valid_until(valid_days: u64) -> String {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let future_secs = now_secs.saturating_add(valid_days.saturating_mul(86400));
    let days_since_epoch = future_secs / 86400;
    let (y, m, d) = days_to_ymd(days_since_epoch);
    format!("{y:04}-{m:02}-{d:02}")
}

fn generate_scope_id() -> String {
    let bytes: [u8; 16] = rand::random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Writes raw key bytes to a file with restrictive permissions (0600 on Unix).
fn write_key_file(path: &Path, secret: &[u8; 32]) -> Result<(), AttestError> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| AttestError::KeyIo(e.to_string()))?;
        file.write_all(secret)
            .map_err(|e| AttestError::KeyIo(e.to_string()))
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, secret).map_err(|e| AttestError::KeyIo(e.to_string()))
    }
}

fn find_flag(args: &[String], name: &str) -> Option<String> {
    let flag = format!("--{name}");
    args.windows(2).find(|w| w[0] == flag).map(|w| w[1].clone())
}

#[cfg(test)]
#[path = "attest_test.rs"]
mod attest_test;
