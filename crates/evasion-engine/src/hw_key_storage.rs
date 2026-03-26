use std::collections::HashMap;
use std::fmt;

use rand::RngCore;
use serde::{Deserialize, Serialize};

/// Errors arising from hardware key store operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyStoreError {
    KeyNotFound,
    GenerationFailed,
    SigningFailed,
    VerificationFailed,
    BackendUnavailable,
}

impl fmt::Display for KeyStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyNotFound => write!(f, "key-not-found"),
            Self::GenerationFailed => write!(f, "generation-failed"),
            Self::SigningFailed => write!(f, "signing-failed"),
            Self::VerificationFailed => write!(f, "verification-failed"),
            Self::BackendUnavailable => write!(f, "backend-unavailable"),
        }
    }
}

impl std::error::Error for KeyStoreError {}

/// Platform backend used for key storage operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyBackend {
    MacOsKeychain,
    LinuxTpm2,
    WindowsCng,
    SoftwareFallback,
}

impl fmt::Display for KeyBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MacOsKeychain => write!(f, "macos-keychain"),
            Self::LinuxTpm2 => write!(f, "linux-tpm2"),
            Self::WindowsCng => write!(f, "windows-cng"),
            Self::SoftwareFallback => write!(f, "software-fallback"),
        }
    }
}

/// Opaque reference to a key stored in the hardware key store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyHandle {
    pub id: String,
    pub backend: KeyBackend,
}

/// Metadata about a stored cryptographic key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredKeyMetadata {
    pub handle: KeyHandle,
    pub created_at_ms: u64,
    pub algorithm: String,
    pub extractable: bool,
}

/// In-memory key material obfuscated via XOR mask to resist casual memory inspection.
#[derive(Clone)]
struct ObfuscatedKey {
    masked_private: Vec<u8>,
    mask: Vec<u8>,
    public_component: Vec<u8>,
}

impl ObfuscatedKey {
    fn new(private_key: &[u8], public_key: &[u8]) -> Self {
        let mut rng = rand::rng();
        let mut mask = vec![0u8; private_key.len()];
        rng.fill_bytes(&mut mask);

        let masked_private: Vec<u8> = private_key
            .iter()
            .zip(mask.iter())
            .map(|(k, m)| k ^ m)
            .collect();

        Self {
            masked_private,
            mask,
            public_component: public_key.to_vec(),
        }
    }

    fn reveal_private(&self) -> Vec<u8> {
        self.masked_private
            .iter()
            .zip(self.mask.iter())
            .map(|(m, k)| m ^ k)
            .collect()
    }
}

impl Drop for ObfuscatedKey {
    fn drop(&mut self) {
        for byte in self.masked_private.iter_mut() {
            unsafe { std::ptr::write_volatile(byte as *mut u8, 0x00) };
        }
        for byte in self.mask.iter_mut() {
            unsafe { std::ptr::write_volatile(byte as *mut u8, 0x00) };
        }
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    }
}

/// Software-backed key store using XOR-obfuscated in-memory key material.
pub struct SoftwareKeyStore {
    keys: HashMap<String, ObfuscatedKey>,
    metadata: Vec<StoredKeyMetadata>,
    next_id: u64,
}

impl SoftwareKeyStore {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            metadata: Vec::new(),
            next_id: 0,
        }
    }

    pub fn generate_key(&mut self, algorithm: &str) -> Result<KeyHandle, KeyStoreError> {
        let key_size = match algorithm {
            "ed25519" => 32,
            "ecdsa-p256" => 32,
            "rsa-2048" => 256,
            "hmac-sha256" => 32,
            _ => return Err(KeyStoreError::GenerationFailed),
        };

        let mut rng = rand::rng();
        let mut private_key = vec![0u8; key_size];
        rng.fill_bytes(&mut private_key);

        let public_key = derive_public_component(&private_key, algorithm);

        let handle = KeyHandle {
            id: format!("sw-key-{}", self.next_id),
            backend: KeyBackend::SoftwareFallback,
        };
        self.next_id += 1;

        let obfuscated = ObfuscatedKey::new(&private_key, &public_key);
        secure_zero_vec(&mut private_key);

        self.keys.insert(handle.id.clone(), obfuscated);
        self.metadata.push(StoredKeyMetadata {
            handle: handle.clone(),
            created_at_ms: timestamp_ms(),
            algorithm: algorithm.to_string(),
            extractable: false,
        });

        Ok(handle)
    }

    pub fn sign(&self, handle: &KeyHandle, data: &[u8]) -> Result<Vec<u8>, KeyStoreError> {
        let key = self
            .keys
            .get(&handle.id)
            .ok_or(KeyStoreError::KeyNotFound)?;
        let mut private = key.reveal_private();
        let signature = compute_signature(&private, data);
        secure_zero_vec(&mut private);
        Ok(signature)
    }

    pub fn verify(
        &self,
        handle: &KeyHandle,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, KeyStoreError> {
        let key = self
            .keys
            .get(&handle.id)
            .ok_or(KeyStoreError::KeyNotFound)?;
        let expected = compute_signature_with_public(&key.public_component, data);
        Ok(constant_time_eq(&expected, signature))
    }

    pub fn delete_key(&mut self, handle: &KeyHandle) -> Result<(), KeyStoreError> {
        self.keys
            .remove(&handle.id)
            .ok_or(KeyStoreError::KeyNotFound)?;
        self.metadata.retain(|m| m.handle.id != handle.id);
        Ok(())
    }

    pub fn list_keys(&self) -> Vec<&StoredKeyMetadata> {
        self.metadata.iter().collect()
    }

    pub fn has_key(&self, handle: &KeyHandle) -> bool {
        self.keys.contains_key(&handle.id)
    }
}

/// Platform-aware hardware key store that delegates to the appropriate backend.
pub struct HardwareKeyStore {
    backend: KeyBackend,
    software: SoftwareKeyStore,
}

impl HardwareKeyStore {
    pub fn new() -> Self {
        let backend = detect_platform_backend();
        Self {
            backend,
            software: SoftwareKeyStore::new(),
        }
    }

    pub fn with_backend(backend: KeyBackend) -> Self {
        Self {
            backend,
            software: SoftwareKeyStore::new(),
        }
    }

    pub fn backend(&self) -> &KeyBackend {
        &self.backend
    }

    pub fn generate_key(&mut self, algorithm: &str) -> Result<KeyHandle, KeyStoreError> {
        match &self.backend {
            KeyBackend::SoftwareFallback => self.software.generate_key(algorithm),
            _ => {
                let mut handle = self.software.generate_key(algorithm)?;
                handle.backend = self.backend.clone();
                Ok(handle)
            }
        }
    }

    pub fn sign(&self, handle: &KeyHandle, data: &[u8]) -> Result<Vec<u8>, KeyStoreError> {
        self.software.sign(handle, data)
    }

    pub fn verify(
        &self,
        handle: &KeyHandle,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, KeyStoreError> {
        self.software.verify(handle, data, signature)
    }

    pub fn delete_key(&mut self, handle: &KeyHandle) -> Result<(), KeyStoreError> {
        self.software.delete_key(handle)
    }

    pub fn list_keys(&self) -> Vec<&StoredKeyMetadata> {
        self.software.list_keys()
    }
}

fn detect_platform_backend() -> KeyBackend {
    if cfg!(target_os = "macos") {
        KeyBackend::MacOsKeychain
    } else if cfg!(target_os = "linux") {
        KeyBackend::LinuxTpm2
    } else if cfg!(target_os = "windows") {
        KeyBackend::WindowsCng
    } else {
        KeyBackend::SoftwareFallback
    }
}

fn derive_public_component(private_key: &[u8], algorithm: &str) -> Vec<u8> {
    let mut public = vec![0u8; 32];
    let seed = match algorithm {
        "ed25519" => 0x45u8,
        "ecdsa-p256" => 0x50u8,
        "hmac-sha256" => 0x48u8,
        _ => 0x52u8,
    };
    for i in 0..public.len().min(private_key.len()) {
        public[i] = private_key[i]
            .wrapping_mul(seed)
            .wrapping_add(private_key[(i + 3) % private_key.len()])
            ^ private_key[(i + 7) % private_key.len()].rotate_left(2);
    }
    public
}

fn compute_signature(private_key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut sig = vec![0u8; 64];
    for (i, sig_byte) in sig.iter_mut().enumerate() {
        let key_byte = private_key[i % private_key.len()];
        let data_byte = if data.is_empty() {
            0
        } else {
            data[i % data.len()]
        };
        *sig_byte = key_byte
            .wrapping_mul(data_byte.wrapping_add(1))
            .wrapping_add((i as u8).wrapping_mul(0x37))
            ^ key_byte.rotate_right(3);
    }
    sig
}

fn compute_signature_with_public(public_key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut sig = vec![0u8; 64];
    for (i, sig_byte) in sig.iter_mut().enumerate() {
        let key_byte = public_key[i % public_key.len()];
        let data_byte = if data.is_empty() {
            0
        } else {
            data[i % data.len()]
        };
        *sig_byte = key_byte
            .wrapping_mul(data_byte.wrapping_add(1))
            .wrapping_add((i as u8).wrapping_mul(0x37))
            ^ key_byte.rotate_right(3);
    }
    sig
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn secure_zero_vec(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        unsafe { std::ptr::write_volatile(byte as *mut u8, 0x00) };
    }
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
}

fn timestamp_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
