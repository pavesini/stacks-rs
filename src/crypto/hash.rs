use sha2::{Digest, Sha256 as ExtSha256, Sha512 as ExtSha512};

pub struct Sha256 {
    hasher: ExtSha256,
}

impl Sha256 {
    pub fn new() -> Self {
        Self { hasher: ExtSha256::new() }
    }

    pub fn hash(mut self, payload: &[u8]) -> Vec<u8> {
        self.hasher.update(payload);
        self.hasher.finalize().to_vec()
    }
}

pub struct Sha512 {
    hasher: ExtSha512,
}

impl Sha512 {
    pub fn new() -> Self {
        Self { hasher: ExtSha512::new() }
    }

    pub fn hash(mut self, payload: &[u8]) -> Vec<u8> {
        self.hasher.update(payload);
        self.hasher.finalize().to_vec()
    }
}