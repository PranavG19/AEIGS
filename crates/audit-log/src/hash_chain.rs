use sha3::{Digest, Sha3_256};

pub const HASH_SIZE: usize = 32;
pub type Hash = [u8; HASH_SIZE];

pub struct HashChain {
    current_hash: Hash,
}

impl HashChain {
    pub fn new() -> Self {
        Self {
            current_hash: genesis_hash(),
        }
    }

    pub fn append(&mut self, data: &[u8]) -> Hash {
        let mut hasher = Sha3_256::new();
        hasher.update(self.current_hash);
        hasher.update(data);
        self.current_hash = hasher.finalize().into();
        self.current_hash
    }

    pub fn current_hash(&self) -> Hash {
        self.current_hash
    }
}

impl Default for HashChain {
    fn default() -> Self {
        Self::new()
    }
}

pub fn genesis_hash() -> Hash {
    let hasher = Sha3_256::new();
    hasher.finalize().into()
}

pub fn compute_next_hash(previous_hash: &Hash, data: &[u8]) -> Hash {
    let mut hasher = Sha3_256::new();
    hasher.update(previous_hash);
    hasher.update(data);
    hasher.finalize().into()
}

pub fn verify_chain(entries: &[(Hash, Vec<u8>)]) -> bool {
    let mut expected_prev = genesis_hash();

    for (recorded_hash, data) in entries {
        let computed = compute_next_hash(&expected_prev, data);
        if computed != *recorded_hash {
            return false;
        }
        expected_prev = *recorded_hash;
    }

    true
}
