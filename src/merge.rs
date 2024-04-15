use crate::h256::H256;
use crate::traits::Hasher;

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct MergeValue {
    hash: H256,
}

impl MergeValue {
    pub fn from_h256(v: H256) -> Self {
        MergeValue { hash: v }
    }

    pub fn zero() -> Self {
        MergeValue::from_h256(H256::zero())
    }

    pub fn is_zero(&self) -> bool {
        self.hash().is_zero()
    }

    #[cfg(feature = "trie")]
    pub fn shortcut_or_value(key: H256, value: H256, height: u8) -> Self {
        if height == 0 || value.is_zero() {
            MergeValue::Value(value)
        } else {
            MergeValue::ShortCut { key, value, height }
        }
    }

    #[cfg(feature = "trie")]
    pub fn is_shortcut(&self) -> bool {
        matches!(self, MergeValue::ShortCut { .. })
    }

    pub fn hash(&self) -> H256 {
        self.hash
    }
}

/// Helper function for Shortcut node
/// Transform it into a MergeValue or MergeWithZero node
#[cfg(feature = "trie")]
pub fn into_merge_value<H: Hasher + Default>(key: H256, value: H256, height: u8) -> MergeValue {
    // try keep hash same with MergeWithZero
    if value.is_zero() || height == 0 {
        MergeValue::from_h256(value)
    } else {
        let base_key = key.parent_path(0);
        let base_node = hash_base_node::<H>(0, &base_key, &value);
        let mut zero_bits = key;
        for i in height..=core::u8::MAX {
            if key.get_bit(i) {
                zero_bits.clear_bit(i);
            }
        }
        MergeValue::MergeWithZero {
            base_node,
            zero_bits,
            zero_count: height,
        }
    }
}

/// Hash base node into a H256
pub fn hash_base_node<H: Hasher + Default>(
    base_height: u8,
    base_key: &H256,
    base_value: &H256,
) -> H256 {
    let mut hasher = H::default();
    hasher.write_byte(base_height);
    hasher.write_h256(base_key);
    hasher.write_h256(base_value);
    hasher.finish()
}

/// Merge two hash with node information
/// this function optimized for ZERO_HASH
/// if lhs and rhs both are ZERO_HASH return ZERO_HASH, otherwise hash all info.
pub fn merge<H: Hasher + Default>(lhs: &MergeValue, rhs: &MergeValue) -> MergeValue {
    if lhs.is_zero() && rhs.is_zero() {
        return MergeValue::zero();
    }
    if lhs.is_zero() {
        return rhs.clone();
    }
    if rhs.is_zero() {
        return lhs.clone();
    }

    let mut hasher = H::default();
    hasher.write_h256(&lhs.hash());
    hasher.write_h256(&rhs.hash());
    MergeValue::from_h256(hasher.finish())
}
