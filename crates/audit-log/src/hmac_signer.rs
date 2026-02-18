use hmac::{Hmac, Mac};
use sha3::Sha3_256;

type HmacSha3_256 = Hmac<Sha3_256>;

pub const MAC_SIZE: usize = 32;
pub type MacBytes = [u8; MAC_SIZE];

pub struct HmacSigner {
    key: Vec<u8>,
}

impl HmacSigner {
    pub fn new(key: &[u8]) -> Self {
        Self {
            key: key.to_vec(),
        }
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
