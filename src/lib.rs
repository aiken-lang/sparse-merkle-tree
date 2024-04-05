pub mod error;
pub mod h256;
pub mod merge;
pub mod merkle_proof;
pub mod traits;
pub mod tree;

/// Expected path size: log2(256) * 2, used for hint vector capacity
pub const EXPECTED_PATH_SIZE: usize = 16;
// Max stack size can be used when verify compiled proof
pub(crate) const MAX_STACK_SIZE: usize = 257;
