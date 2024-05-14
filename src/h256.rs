use std::{cmp::Ordering, fmt::Debug};

use bitvec::{array::BitArray, order::Msb0, vec::BitVec};

/// Represent 256 bits
#[derive(Eq, PartialEq, Default, Hash, Clone, Copy)]
pub struct H256([u8; 32]);

const ZERO: H256 = H256([0u8; 32]);
const MAX: H256 = H256([255u8; 32]);
const BYTE_SIZE: u8 = 8;
pub const LEAF_BYTE: u8 = 13;

impl Debug for H256 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("H256").field(&hex::encode(self.0)).finish()
    }
}

impl H256 {
    pub const fn zero() -> Self {
        ZERO
    }

    pub const fn max() -> Self {
        MAX
    }

    pub fn is_zero(&self) -> bool {
        self == &ZERO
    }

    #[inline]
    pub fn get_bit(&self, i: u8) -> bool {
        let byte_pos = i / BYTE_SIZE;
        let bit_pos = i % BYTE_SIZE;
        let bit = self.0[31 - byte_pos as usize] >> bit_pos & 1;
        bit != 0
    }

    #[inline]
    pub fn set_bit(&mut self, i: u8) {
        let byte_pos = i / BYTE_SIZE;
        let bit_pos = i % BYTE_SIZE;
        self.0[31 - byte_pos as usize] |= 1 << bit_pos;
    }

    #[inline]
    pub fn clear_bit(&mut self, i: u8) {
        let byte_pos = i / BYTE_SIZE;
        let bit_pos = i % BYTE_SIZE;
        self.0[byte_pos as usize] &= !((1 << bit_pos) as u8);
    }

    #[inline]
    pub fn is_right(&self) -> bool {
        let bit = self.0[31] & 1;
        bit != 0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0[..]
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0[..]
    }

    /// Treat H256 as a path in a tree
    /// fork height is the number of common bits(from heigher to lower: 255..=0) of two H256
    pub fn fork_height(&self, key: &H256) -> u8 {
        for h in (0..=core::u8::MAX).rev() {
            if self.get_bit(h) != key.get_bit(h) {
                return h;
            }
        }
        0
    }

    /// Treat H256 as a path in a tree
    /// return parent_path of self
    pub fn parent_path_by_height(&self, height: u8) -> Self {
        if height == core::u8::MAX {
            H256::zero()
        } else {
            let height = height + 1;
            let mut x = *self;

            let x: &mut BitVec<_, Msb0> = &mut BitVec::from_slice(x.as_mut_slice());

            x.shift_right(height.into());

            let target: BitArray<[u8; 32], _> = x.as_bitslice().try_into().unwrap();

            let y: [u8; 32] = target.data;

            y.into()
        }
    }
}

impl PartialOrd for H256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for H256 {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare bits from heigher to lower (255..0)
        self.0.iter().cmp(other.0.iter())
    }
}

impl From<[u8; 32]> for H256 {
    fn from(v: [u8; 32]) -> H256 {
        H256(v)
    }
}

impl From<H256> for [u8; 32] {
    fn from(h256: H256) -> [u8; 32] {
        h256.0
    }
}
