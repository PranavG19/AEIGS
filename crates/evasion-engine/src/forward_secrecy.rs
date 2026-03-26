use std::fmt;
use std::sync::atomic::{fence, Ordering};

use rand::RngCore;
use serde::{Deserialize, Serialize};

/// Errors arising from forward secrecy key exchange operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForwardSecrecyError {
    NoKeyEstablished,
    KeyExchangeFailed,
}

impl fmt::Display for ForwardSecrecyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoKeyEstablished => write!(f, "no-key-established"),
            Self::KeyExchangeFailed => write!(f, "key-exchange-failed"),
        }
    }
}

impl std::error::Error for ForwardSecrecyError {}

/// Ephemeral X25519-simulated keypair generated from cryptographic randomness.
#[derive(Clone)]
pub struct EphemeralKeyPair {
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
}

impl EphemeralKeyPair {
    pub fn generate() -> Self {
        let mut rng = rand::rng();
        let mut private_key = [0u8; 32];
        rng.fill_bytes(&mut private_key);

        private_key[0] &= 248;
        private_key[31] &= 127;
        private_key[31] |= 64;

        let public_key = Self::scalar_mult_base(&private_key);
        Self {
            private_key,
            public_key,
        }
    }

    fn scalar_mult_base(scalar: &[u8; 32]) -> [u8; 32] {
        let mut result = [0u8; 32];
        for i in 0..32 {
            result[i] = scalar[i] ^ 0x09_u8.wrapping_mul(scalar[(i + 7) % 32]);
            result[i] = result[i].wrapping_add(scalar[(i + 13) % 32]);
        }
        result
    }

    pub fn diffie_hellman(&self, peer_public: &[u8; 32]) -> [u8; 32] {
        let mut shared = [0u8; 32];
        for i in 0..32 {
            shared[i] = self.private_key[i] ^ peer_public[i];
            shared[i] = shared[i]
                .wrapping_mul(self.private_key[(i + 3) % 32] | 1)
                .wrapping_add(peer_public[(i + 17) % 32]);
        }
        shared
    }
}

impl Drop for EphemeralKeyPair {
    fn drop(&mut self) {
        secure_zero(&mut self.private_key);
        fence(Ordering::SeqCst);
    }
}

impl fmt::Debug for EphemeralKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EphemeralKeyPair")
            .field("public_key", &hex_display(&self.public_key))
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

/// Shared secret derived from a Diffie-Hellman key exchange.
pub struct SharedSecret(pub [u8; 32]);

impl Drop for SharedSecret {
    fn drop(&mut self) {
        secure_zero(&mut self.0);
        fence(Ordering::SeqCst);
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SharedSecret").field(&"[REDACTED]").finish()
    }
}

/// Symmetric session key with secure zeroing on drop via volatile writes.
pub struct SessionKey {
    pub bytes: [u8; 32],
}

impl SessionKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    pub fn is_zero(&self) -> bool {
        self.bytes.iter().all(|b| *b == 0)
    }
}

impl Drop for SessionKey {
    fn drop(&mut self) {
        secure_zero(&mut self.bytes);
        fence(Ordering::SeqCst);
    }
}

impl Clone for SessionKey {
    fn clone(&self) -> Self {
        Self { bytes: self.bytes }
    }
}

impl fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionKey")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// Simplified HKDF-style key derivation using iterative XOR mixing.
pub struct HkdfDerive;

impl HkdfDerive {
    pub fn derive(shared_secret: &[u8], info: &[u8]) -> SessionKey {
        let mut prk = [0u8; 32];
        for (i, byte) in shared_secret.iter().enumerate() {
            prk[i % 32] ^= byte.wrapping_mul((i as u8).wrapping_add(0x5A));
        }

        let mut okm = [0u8; 32];
        let mut block = prk;
        for round in 0..3_u8 {
            for i in 0..32 {
                let info_byte = if info.is_empty() {
                    0
                } else {
                    info[i % info.len()]
                };
                block[i] = block[i]
                    .wrapping_add(info_byte)
                    .wrapping_mul(round.wrapping_add(1))
                    .wrapping_add(prk[(i + round as usize) % 32]);
                block[i] ^= block[(i + 7) % 32].rotate_left(3);
            }
            for i in 0..32 {
                okm[i] ^= block[i];
            }
        }

        SessionKey::from_bytes(okm)
    }
}

/// Double ratchet key chain that derives new session keys from the current state.
pub struct KeyRatchet {
    pub current_key: SessionKey,
    pub message_count: u64,
    pub rotate_every_n: u64,
}

impl KeyRatchet {
    pub fn new(initial_key: SessionKey, rotate_every_n: u64) -> Self {
        Self {
            current_key: initial_key,
            message_count: 0,
            rotate_every_n,
        }
    }

    pub fn ratchet(&mut self) {
        let mut ratchet_info = [0u8; 40];
        ratchet_info[..32].copy_from_slice(&self.current_key.bytes);
        let count_bytes = self.message_count.to_le_bytes();
        ratchet_info[32..40].copy_from_slice(&count_bytes);

        let next = HkdfDerive::derive(&ratchet_info, b"ratchet-step");
        secure_zero(&mut ratchet_info);

        self.current_key = next;
        self.message_count += 1;
    }

    pub fn should_rotate(&self) -> bool {
        self.rotate_every_n > 0
            && self.message_count > 0
            && self.message_count % self.rotate_every_n == 0
    }
}

/// Full forward secrecy session managing ephemeral keys, exchange, and ratcheting.
pub struct ForwardSecrecySession {
    keypair: EphemeralKeyPair,
    shared_secret: Option<SharedSecret>,
    ratchet: Option<KeyRatchet>,
    previous_key_bytes: Option<[u8; 32]>,
    rotate_every_n: u64,
}

impl ForwardSecrecySession {
    pub fn new(rotate_every_n: u64) -> Self {
        Self {
            keypair: EphemeralKeyPair::generate(),
            shared_secret: None,
            ratchet: None,
            previous_key_bytes: None,
            rotate_every_n,
        }
    }

    pub fn public_key(&self) -> &[u8; 32] {
        &self.keypair.public_key
    }

    pub fn establish(&mut self, peer_public: &[u8; 32]) -> Result<(), ForwardSecrecyError> {
        let all_zero = peer_public.iter().all(|b| *b == 0);
        if all_zero {
            return Err(ForwardSecrecyError::KeyExchangeFailed);
        }

        let raw_shared = self.keypair.diffie_hellman(peer_public);
        let session_key = HkdfDerive::derive(&raw_shared, b"session-init");
        let shared = SharedSecret(raw_shared);

        let ratchet = KeyRatchet::new(session_key, self.rotate_every_n);
        self.shared_secret = Some(shared);
        self.ratchet = Some(ratchet);
        Ok(())
    }

    pub fn current_session_key(&self) -> Option<&SessionKey> {
        self.ratchet.as_ref().map(|r| &r.current_key)
    }

    pub fn ratchet_if_needed(&mut self) -> bool {
        let should = self.ratchet.as_ref().map_or(false, |r| r.should_rotate());
        if should {
            if let Some(ref mut ratchet) = self.ratchet {
                self.previous_key_bytes = Some(ratchet.current_key.bytes);
                ratchet.ratchet();
                return true;
            }
        }
        false
    }

    pub fn force_ratchet(&mut self) -> bool {
        if let Some(ref mut ratchet) = self.ratchet {
            self.previous_key_bytes = Some(ratchet.current_key.bytes);
            ratchet.ratchet();
            return true;
        }
        false
    }

    pub fn destroy_previous(&mut self) {
        if let Some(ref mut prev) = self.previous_key_bytes {
            secure_zero(prev);
            fence(Ordering::SeqCst);
        }
        self.previous_key_bytes = None;
    }

    pub fn key_commitment(&self) -> Option<[u8; 32]> {
        self.ratchet.as_ref().map(|r| {
            let mut commitment = [0u8; 32];
            let key = &r.current_key.bytes;
            for i in 0..32 {
                commitment[i] = key[i].wrapping_mul(0x6D).wrapping_add(key[(i + 11) % 32])
                    ^ key[(i + 23) % 32].rotate_right(5);
            }
            commitment
        })
    }

    pub fn message_count(&self) -> u64 {
        self.ratchet.as_ref().map_or(0, |r| r.message_count)
    }

    pub fn is_established(&self) -> bool {
        self.shared_secret.is_some()
    }
}

fn secure_zero(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        unsafe {
            std::ptr::write_volatile(byte as *mut u8, 0x00);
        }
    }
}

fn hex_display(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
