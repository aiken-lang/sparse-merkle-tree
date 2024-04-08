use cryptoxide::{blake2b::Blake2b, digest::Digest};

use crate::{h256::H256, traits::Hasher};

const BLAKE2B_LEN: usize = 32;

pub struct Blake2bHasher(Blake2b);

impl Default for Blake2bHasher {
    fn default() -> Self {
        let blake2b = Blake2b::new(BLAKE2B_LEN);
        Blake2bHasher(blake2b)
    }
}

impl Hasher for Blake2bHasher {
    fn write_h256(&mut self, h: &H256) {
        self.0.input(h.as_slice());
    }
    fn write_byte(&mut self, b: u8) {
        self.0.input(&[b]);
    }
    fn finish(mut self) -> H256 {
        let mut hash = [0u8; 32];
        self.0.result(&mut hash);
        hash.into()
    }
}
