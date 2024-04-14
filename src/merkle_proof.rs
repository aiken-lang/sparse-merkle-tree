use crate::{h256::H256, merge::MergeValue};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Side {
    Left(MergeValue),
    Right(MergeValue),
}

impl Side {
    pub fn is_same_side(&self, other: &Side) -> bool {
        matches!(
            (self, other),
            (Side::Left(_), Side::Left(_)) | (Side::Right(_), Side::Right(_))
        )
    }

    pub fn merge_value(self) -> MergeValue {
        match self {
            Side::Left(v) => v,
            Side::Right(v) => v,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    // needed sibling node hash
    merkle_path: Vec<(H256, Vec<Side>)>,
}

impl MerkleProof {
    /// Create MerkleProof
    /// leaves_bitmap: leaf bitmap, bitmap.get_bit(height) is true means there need a non zero sibling in this height
    /// proof: needed sibling node hash
    pub fn new(merkle_path: Vec<(H256, Vec<Side>)>) -> Self {
        MerkleProof { merkle_path }
    }

    /// Destruct the structure, useful for serialization
    pub fn take(self) -> Vec<(H256, Vec<Side>)> {
        let MerkleProof { merkle_path } = self;
        merkle_path
    }

    /// return sibling node hashes
    pub fn merkle_path(&self) -> &Vec<(H256, Vec<Side>)> {
        &self.merkle_path
    }
}
