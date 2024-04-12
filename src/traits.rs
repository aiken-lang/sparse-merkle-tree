use std::collections::HashMap;

use crate::{
    error::Error,
    h256::{H256, LEAF_BYTE},
    tree::{BranchKey, BranchNode},
};

/// Trait for customize hash function
pub trait Hasher {
    fn write_h256(&mut self, h: &H256);
    fn write_byte(&mut self, b: u8);
    fn finish(self) -> H256;
}

/// Trait for define value structures
pub trait Value {
    fn to_h256<H: Hasher + Default>(&self) -> H256;
    fn zero() -> Self;
    fn max() -> Self;
}

impl Value for H256 {
    fn to_h256<H: Hasher + Default>(&self) -> H256 {
        let mut hasher = H::default();
        hasher.write_byte(LEAF_BYTE);
        hasher.write_h256(self);
        hasher.finish()
    }
    fn zero() -> Self {
        H256::zero()
    }
    fn max() -> Self {
        H256::max()
    }
}

/// Traits for customize backend storage
pub trait StoreReadOps<V> {
    fn get_branch(&self, branch_key: &BranchKey) -> Result<Option<BranchNode>, Error>;
    fn get_leaf(&self, leaf_key: &H256) -> Result<Option<V>, Error>;
    fn branches_map(&self) -> &HashMap<BranchKey, BranchNode>;
    fn leaves_map(&self) -> &HashMap<H256, V>;
}

pub trait StoreWriteOps<V> {
    fn insert_branch(&mut self, node_key: BranchKey, branch: BranchNode) -> Result<(), Error>;
    fn insert_leaf(&mut self, leaf_key: H256, leaf: V) -> Result<(), Error>;
    fn remove_branch(&mut self, node_key: &BranchKey) -> Result<(), Error>;
    fn remove_leaf(&mut self, leaf_key: &H256) -> Result<(), Error>;
}
