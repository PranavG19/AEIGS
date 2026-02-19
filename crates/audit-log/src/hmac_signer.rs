use hmac::{Hmac, Mac};
use sha3::{Digest, Sha3_256};
use std::path::Path;

type HmacSha3_256 = Hmac<Sha3_256>;

pub const MAC_SIZE: usize = 32;
pub type MacBytes = [u8; MAC_SIZE];

pub struct HmacSigner {
    key: Vec<u8>,
}

impl HmacSigner {
    pub fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }

    pub fn with_key_file(path: &Path) -> Result<Self, std::io::Error> {
        let key = std::fs::read(path)?;
        Ok(Self { key })
    }

    pub fn save_key_to_file(&self, path: &Path) -> Result<(), std::io::Error> {
        std::fs::write(path, &self.key)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(path, perms)?;
        }
        Ok(())
    }

    pub fn with_derived_key(passphrase: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(b"aegis-hmac-key-derivation-v1");
        hasher.update(passphrase);
        let key: [u8; 32] = hasher.finalize().into();
        Self { key: key.to_vec() }
    }

    pub fn sign(&self, data: &[u8]) -> MacBytes {
        let mut mac =
            HmacSha3_256::new_from_slice(&self.key).expect("HMAC accepts keys of any size");
        mac.update(data);
        let result = mac.finalize();
        let bytes = result.into_bytes();
        let mut output = [0u8; MAC_SIZE];
        output.copy_from_slice(&bytes);
        output
    }

    pub fn verify(&self, data: &[u8], expected_mac: &MacBytes) -> bool {
        let computed = self.sign(data);
        constant_time_eq(&computed, expected_mac)
    }
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
