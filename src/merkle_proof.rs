use crate::{h256::H256, merge::MergeValue};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Side {
    Left(MergeValue),
    Right(MergeValue),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    // leaf bitmap, bitmap.get_bit(height) is true means there need a non zero sibling in this height
    leaves_bitmap: Vec<H256>,
    // needed sibling node hash
    merkle_path: Vec<(H256, Vec<Side>)>,
}

impl MerkleProof {
    /// Create MerkleProof
    /// leaves_bitmap: leaf bitmap, bitmap.get_bit(height) is true means there need a non zero sibling in this height
    /// proof: needed sibling node hash
    pub fn new(leaves_bitmap: Vec<H256>, merkle_path: Vec<(H256, Vec<Side>)>) -> Self {
        MerkleProof {
            leaves_bitmap,
            merkle_path,
        }
    }

    /// Destruct the structure, useful for serialization
    pub fn take(self) -> (Vec<H256>, Vec<(H256, Vec<Side>)>) {
        let MerkleProof {
            leaves_bitmap,
            merkle_path,
        } = self;
        (leaves_bitmap, merkle_path)
    }

    /// number of leaves required by this merkle proof
    pub fn leaves_count(&self) -> usize {
        self.leaves_bitmap.len()
    }

    /// return the inner leaves_bitmap vector
    pub fn leaves_bitmap(&self) -> &Vec<H256> {
        &self.leaves_bitmap
    }

    /// return sibling node hashes
    pub fn merkle_path(&self) -> &Vec<(H256, Vec<Side>)> {
        &self.merkle_path
    }
}
