use aiken/builtin
use aiken/bytearray.{to_hex}
use aiken/hash.{Blake2b_256, Hash}
use aiken/math
use aiken/sparse_merkle_tree/consts.{merkle_lower_bound, merkle_upper_bound}

pub const hash_length = 32

pub const leaf_byte = #"0deeffaad07783"

pub type Side {
  Left
  Right
}

pub type Byte =
  Int

pub type Height =
  Byte

pub type Root<a> =
  Hash<Blake2b_256, a>

pub opaque type HashedProof<a> {
  inner: Hash<Blake2b_256, a>,
}

pub fn get_starting_side(
  left_leaf: HashedProof<a>,
  right_leaf: HashedProof<a>,
  member_hash: HashedProof<a>,
  intersecting_level: Int,
) -> Side {
  // 0 indexed byte positions as a reminder
  let bit_to_test = 255 - intersecting_level

  let left_leaf = left_leaf.inner

  let right_leaf = right_leaf.inner

  if bit_to_test == 0 {
    fail @"Impossible due to initial construction of the merkle tree"
  } else {
    let previous_bytes = bit_to_test - 1

    let bit_shift = math.pow2(7 - previous_bytes % 8)
    let other_bytes = previous_bytes / 8

    let left_previous_bytes =
      builtin.index_bytearray(left_leaf, other_bytes) / bit_shift * bit_shift
        |> builtin.cons_bytearray(
            builtin.slice_bytearray(0, other_bytes, left_leaf),
          )

    let right_previous_bytes =
      builtin.index_bytearray(right_leaf, other_bytes) / bit_shift * bit_shift
        |> builtin.cons_bytearray(
            builtin.slice_bytearray(0, other_bytes, right_leaf),
          )

    let member_previous_bytes =
      builtin.index_bytearray(member_hash.inner, other_bytes) / bit_shift * bit_shift
        |> builtin.cons_bytearray(
            builtin.slice_bytearray(0, other_bytes, member_hash.inner),
          )

    let test_left_bit = bytearray.test_bit(left_leaf, bit_to_test)

    let test_right_bit = bytearray.test_bit(right_leaf, bit_to_test)

    let test_member_bit = bytearray.test_bit(member_hash.inner, bit_to_test)

    if and {
      test_left_bit != test_member_bit,
      left_previous_bytes == member_previous_bytes,
      right_previous_bytes != member_previous_bytes,
    } {
      Left
    } else if and {
      test_right_bit != test_member_bit,
      right_previous_bytes == member_previous_bytes,
      left_previous_bytes != member_previous_bytes,
    } {
      Right
    } else {
      fail @"Impossible"
    }
  }
}

pub fn lowest_continuing_side_height(
  proof: ContinuingSideProofs<a>,
  starting_side: Side,
) -> Option<Int> {
  if bytearray.length(proof.inner) == 0 {
    None
  } else {
    when starting_side is {
      Left -> Some(builtin.index_bytearray(proof.inner, hash_length))
      Right -> Some(builtin.index_bytearray(proof.inner, 0))
    }
  }
}

fn get_hashed_bytes(p: HashedProof<a>) -> Hash<Blake2b_256, a> {
  p.inner
}

pub fn convert_to_hashed_proof(bytes: ByteArray) -> HashedProof<a> {
  expect bytearray.length(bytes) == hash_length

  HashedProof { inner: bytes }
}

pub fn hash_to_hashed_proof(bytes: ByteArray) -> HashedProof<a> {
  HashedProof { inner: bytes |> hash.blake2b_256 }
}

pub fn to_string(proof: HashedProof<a>) {
  to_hex(proof.inner)
}

pub fn proof_length() -> Int {
  hash_length + 1
}

/// Plus one byte to tell us whether to prepend or append the proof
pub fn remainder_proofs_size() -> Int {
  proof_length() + 1
}

/// The bytearray representation is a byte for the side and then a byte for the height if side is right followed by the hash
/// Or the hash followed by a byte for the height
pub type RemainderProof<side, level, a> =
  Hash<Blake2b_256, a>

/// A series of remainder proofs that are concatenated together with no separator
pub opaque type MerkleRemainderProofs<a> {
  inner: RemainderProof<Side, Height, a>,
}

/// 1 byte for deciding which side the proof is on, 1 byte for the height, and 32 bytes for the proof hash
/// The byte for the height is either in front if it's a right side and at the end if it's a left side
/// This is to reduce the builtins needed before concatenation
pub fn convert_bytes_to_remainder_proofs(
  bytes: ByteArray,
) -> MerkleRemainderProofs<a> {
  expect bytearray.length(bytes) % remainder_proofs_size() == 0

  MerkleRemainderProofs { inner: bytes }
}

/// Verify the remaining merkle proof branches with the current hashed proofs equals the root
pub fn verify_root(
  bounds: MerkleRemainderProofs<a>,
  hashed_proof: HashedProof<a>,
  root: Root<a>,
) -> Bool {
  do_verify_root(hashed_proof.inner, bounds, bytearray.length(bounds.inner), 0) == root
}

pub fn test_add_member(
  bounds: MerkleRemainderProofs<a>,
  hashed_proof: HashedProof<a>,
) -> Root<a> {
  do_verify_root(hashed_proof.inner, bounds, bytearray.length(bounds.inner), 0)
}

fn do_verify_root(
  hashed_proof: ByteArray,
  bounds: MerkleRemainderProofs<a>,
  bounds_length: Int,
  index: Int,
) -> ByteArray {
  if index == bounds_length {
    hashed_proof
  } else {
    // determine which side the proof is on
    if builtin.index_bytearray(bounds.inner, index) == 0 {
      // Sliced bytes are prepended to the proof
      // The byte corresponding to the height is at the end
      builtin.slice_bytearray(index + 1, proof_length(), bounds.inner)
        |> bytearray.concat(hashed_proof)
        |> hash.blake2b_256
        |> do_verify_root(bounds, bounds_length, index + remainder_proofs_size())
    } else {
      // Sliced bytes are appended to the proof
      // The byte corresponding to the height is at the front
      builtin.slice_bytearray(index + 1, proof_length(), bounds.inner)
        |> bytearray.concat(hashed_proof, _)
        |> hash.blake2b_256
        |> do_verify_root(bounds, bounds_length, index + remainder_proofs_size())
    }
  }
}

/// A byte for the height if the starting side is right followed by the hash
/// Or the hash followed by a byte for the height if the starting side is left
pub type ContSideProof<level, a> =
  Hash<Blake2b_256, a>

/// A series of continuing side proofs that are concatenated together with no separator
pub opaque type ContinuingSideProofs<a> {
  inner: ContSideProof<Height, a>,
}

pub fn convert_to_side_proof(bytes: ByteArray) -> ContinuingSideProofs<a> {
  expect bytearray.length(bytes) % proof_length() == 0

  ContinuingSideProofs { inner: bytes }
}

/// Combine the left and right proofs to get the new combined hash
/// Assumes remaining_side_proofs is empty and the rest of the merkle 
/// proof is contained remaining_proofs
pub fn combine_sides(
  hashed_left: HashedProof<a>,
  hashed_right: HashedProof<a>,
  left_right_intersection: Height,
) -> HashedProof<a> {
  hashed_left
    |> get_hashed_bytes
    |> bytearray.concat(
        builtin.cons_bytearray(left_right_intersection, hashed_right.inner),
      )
    |> hash.blake2b_256
    |> HashedProof
}

/// Combine the left and right proofs to get the new combined hash
/// Then repeat with the item to be inserted
pub fn combine_proofs(
  starting_side: Side,
  remaining_side_proofs: ContinuingSideProofs<a>,
  hashed_left: HashedProof<a>,
  hashed_right: HashedProof<a>,
  account_hash: HashedProof<a>,
  left_right_intersection: Height,
  intersecting_level: Height,
  callback,
) {
  when starting_side is {
    Left -> {
      let combined_hash =
        hashed_left
          |> continue_left_proof(remaining_side_proofs) // hash remaining left proofs
          |> get_hashed_bytes
          |> bytearray.concat(
              // conctenate the left and right proofs with a height byte in between
              builtin.cons_bytearray(
                left_right_intersection,
                hashed_right.inner,
              ),
            )
          |> hash.blake2b_256
          |> HashedProof
      // Note we prepend a leaf byte to the account item in the proof to account for the leaf hash
      let new_combined_hash =
        account_hash
          |> get_hashed_bytes
          |> bytearray.concat(leaf_byte, _) // add leaf byte to prove the leaf hash
          |> hash.blake2b_256
          |> builtin.cons_bytearray(intersecting_level, _) // add height byte
          |> bytearray.concat(hashed_left.inner, _) // add the left proof
          |> hash.blake2b_256
          |> HashedProof
          |> continue_left_proof(remaining_side_proofs) // hash remaining left proofs
          |> get_hashed_bytes
          |> bytearray.concat(
              // conctenate the left and right proofs with a height byte in between
              builtin.cons_bytearray(
                left_right_intersection,
                hashed_right.inner,
              ),
            )
          |> hash.blake2b_256
          |> HashedProof

      callback(combined_hash, new_combined_hash)
    }

    Right -> {
      let combined_hash =
        hashed_right
          |> continue_right_proof(remaining_side_proofs) // hash remaining right proofs
          |> get_hashed_bytes
          |> builtin.cons_bytearray(left_right_intersection, _) // add height byte
          |> bytearray.concat(hashed_left.inner, _) // add the left proof
          |> hash.blake2b_256
          |> HashedProof

      // Note we prepend a leaf byte to the account item in the proof to account for the leaf hash
      let new_combined_hash =
        account_hash
          |> get_hashed_bytes
          |> bytearray.concat(leaf_byte, _) // add leaf byte to prove the leaf hash
          |> hash.blake2b_256
          |> bytearray.concat(
              // add height byte to right hash and concat with member hash
              builtin.cons_bytearray(intersecting_level, hashed_right.inner),
            )
          |> hash.blake2b_256
          |> HashedProof
          |> continue_right_proof(remaining_side_proofs) // hash remaining right proofs
          |> get_hashed_bytes
          |> builtin.cons_bytearray(left_right_intersection, _) // add height byte
          |> bytearray.concat(hashed_left.inner, _) // add the left proof
          |> hash.blake2b_256
          |> HashedProof

      callback(combined_hash, new_combined_hash)
    }
  }
}

/// 1 byte for the height, and 32 bytes for the proof hash
/// The byte for the height is at the end
pub type LeftProof<a, level> =
  Hash<Blake2b_256, a>

/// A series of left proofs that are concatenated together with no separator
pub opaque type LeftMerkleProofs<a> {
  inner: LeftProof<a, Height>,
}

pub fn convert_bytes_to_left_proofs(bytes: ByteArray) -> LeftMerkleProofs<a> {
  expect bytearray.length(bytes) % proof_length() == 0

  LeftMerkleProofs { inner: bytes }
}

/// The new item is on the right side of the tree
/// so we prepend only left side proofs. 
/// Note we prepend a leaf byte to the first item in the proof to account for the leaf hash. 
/// Fails if left_side is empty
pub fn left_proof(
  left_leaf: HashedProof<a>,
  left_side: LeftMerkleProofs<a>,
) -> HashedProof<a> {
  if bytearray.length(left_side.inner) == 0 {
    leaf_byte
      |> bytearray.concat(left_leaf.inner)
      |> hash.blake2b_256
      |> HashedProof
  } else {
    leaf_byte
      |> bytearray.concat(left_leaf.inner)
      |> hash.blake2b_256
      |> do_left_proof(
          left_side,
          bytearray.length(left_side.inner),
          proof_length(),
        )
      |> HashedProof
  }
}

/// The new item is on the right side of the tree
/// so we prepend only left side proofs
/// This assumes the starting hash is a branch hash and not a leaf hash
fn continue_left_proof(
  starting_hash: HashedProof<a>,
  left_side: ContinuingSideProofs<a>,
) -> HashedProof<a> {
  if bytearray.length(left_side.inner) == 0 {
    starting_hash
  } else {
    HashedProof(
      do_left_proof(
        starting_hash.inner,
        LeftMerkleProofs(left_side.inner),
        bytearray.length(left_side.inner),
        0,
      ),
    )
  }
}

pub fn do_left_proof(
  proof: ByteArray,
  side: LeftMerkleProofs<a>,
  side_length: Int,
  index: Int,
) -> ByteArray {
  if index == side_length {
    proof
  } else {
    // Prepend the proof
    builtin.slice_bytearray(index, proof_length(), side.inner)
      |> bytearray.concat(proof)
      |> hash.blake2b_256
      |> do_left_proof(side, side_length, index + proof_length())
  }
}

pub fn get_left_highest_intersection_level(
  proofs: LeftMerkleProofs<a>,
) -> Option<Int> {
  if builtin.length_of_bytearray(proofs.inner) == 0 {
    None
  } else {
    Some(
      builtin.index_bytearray(
        proofs.inner,
        builtin.length_of_bytearray(proofs.inner) - 1,
      ),
    )
  }
}

/// 1 byte for the height, and 32 bytes for the proof hash
/// The byte for the height is at the end
pub type RightProof<a, level> =
  Hash<Blake2b_256, a>

/// A series of left proofs that are concatenated together with no separator
pub opaque type RightMerkleProofs<a> {
  inner: RightProof<a, Height>,
}

pub fn convert_bytes_to_right_proofs(bytes: ByteArray) -> RightMerkleProofs<a> {
  expect bytearray.length(bytes) % proof_length() == 0

  RightMerkleProofs { inner: bytes }
}

/// The new item is on the left side of the tree
/// so we prepend only append right side proofs. 
/// Note we prepend a leaf byte to the first item in the proof to account for the leaf hash. 
/// Fails if right_side is empty
pub fn right_proof(
  right_leaf: HashedProof<a>,
  right_side: RightMerkleProofs<a>,
) -> HashedProof<a> {
  if bytearray.length(right_side.inner) == 0 {
    leaf_byte
      |> bytearray.concat(right_leaf.inner)
      |> hash.blake2b_256
      |> HashedProof
  } else {
    leaf_byte
      |> bytearray.concat(right_leaf.inner)
      |> hash.blake2b_256
      |> do_right_proof(
          right_side,
          bytearray.length(right_side.inner),
          proof_length(),
        )
      |> HashedProof
  }
}

/// The new item is on the left side of the tree
/// so we append only right side proofs
/// This assumes the starting hash is a branch hash and not a leaf hash
fn continue_right_proof(
  starting_hash: HashedProof<a>,
  right_side: ContinuingSideProofs<a>,
) -> HashedProof<a> {
  if bytearray.length(right_side.inner) == 0 {
    starting_hash
  } else {
    HashedProof(
      do_right_proof(
        starting_hash.inner,
        RightMerkleProofs(right_side.inner),
        bytearray.length(right_side.inner),
        0,
      ),
    )
  }
}

fn do_right_proof(
  proof: ByteArray,
  side: RightMerkleProofs<a>,
  side_length: Int,
  index: Int,
) -> ByteArray {
  if index == side_length {
    proof
  } else {
    // Prepend the proof
    builtin.slice_bytearray(index, proof_length(), side.inner)
      |> bytearray.concat(proof, _)
      |> hash.blake2b_256
      |> do_right_proof(side, side_length, index + proof_length())
  }
}

pub fn get_right_highest_intersection_level(
  proofs: RightMerkleProofs<a>,
) -> Option<Int> {
  if builtin.length_of_bytearray(proofs.inner) == 0 {
    None
  } else {
    Some(
      builtin.index_bytearray(
        proofs.inner,
        builtin.length_of_bytearray(proofs.inner) - hash_length - 1,
      ),
    )
  }
}

pub type MerkleProofBlock<a> {
  left_leaf: ByteArray,
  right_leaf: ByteArray,
  left_proofs: ByteArray,
  right_proofs: ByteArray,
  continuing_side_proofs: ByteArray,
  remaining_proofs: ByteArray,
  left_right_intersection: Height,
  intersecting_level: Height,
}

pub fn validate_structure(proof_block: MerkleProofBlock<a>, callback) {
  let MerkleProofBlock {
    left_leaf,
    right_leaf,
    left_proofs,
    right_proofs,
    continuing_side_proofs,
    remaining_proofs,
    left_right_intersection,
    intersecting_level,
  } = proof_block

  let left_proofs = convert_bytes_to_left_proofs(left_proofs)
  let right_proofs = convert_bytes_to_right_proofs(right_proofs)
  let continuing_side_proofs = convert_to_side_proof(continuing_side_proofs)
  let remaining_proofs = convert_bytes_to_remainder_proofs(remaining_proofs)

  let left_leaf = convert_to_hashed_proof(left_leaf)
  let right_leaf = convert_to_hashed_proof(right_leaf)

  expect intersecting_level < 256 && intersecting_level > -1

  expect
    left_right_intersection < 256 && left_right_intersection > -1 && left_right_intersection > intersecting_level

  callback(
    left_leaf,
    right_leaf,
    left_proofs,
    right_proofs,
    continuing_side_proofs,
    remaining_proofs,
    left_right_intersection,
    intersecting_level,
  )
}

pub fn check_bounds(
  left_leaf: HashedProof<a>,
  right_leaf: HashedProof<a>,
  member_hash: HashedProof<a>,
) -> Bool {
  and {
    builtin.less_than_bytearray(left_leaf.inner, member_hash.inner),
    builtin.less_than_bytearray(member_hash.inner, right_leaf.inner),
    builtin.less_than_equals_bytearray(merkle_lower_bound, left_leaf.inner),
    builtin.less_than_equals_bytearray(right_leaf.inner, merkle_upper_bound),
  }
}

pub fn check_heights(
  left_proofs: LeftMerkleProofs<a>,
  right_proofs: RightMerkleProofs<a>,
  continuing_side_proofs: ContinuingSideProofs<a>,
  intersecting_level: Int,
  starting_side: Side,
) -> Bool {
  when starting_side is {
    Left -> {
      let left_height = get_left_highest_intersection_level(left_proofs)

      let continuing_height =
        lowest_continuing_side_height(continuing_side_proofs, starting_side)

      let lower_height_valid =
        when left_height is {
          Some(h) -> h < intersecting_level
          None -> True
        }

      let continuing_height_valid =
        when continuing_height is {
          Some(h) -> h > intersecting_level
          None -> True
        }

      and {
        lower_height_valid,
        continuing_height_valid,
      }
    }

    Right -> {
      let right_height = get_right_highest_intersection_level(right_proofs)

      let continuing_height =
        lowest_continuing_side_height(continuing_side_proofs, starting_side)

      let lower_height_valid =
        when right_height is {
          Some(h) -> h < intersecting_level
          None -> True
        }

      let continuing_height_valid =
        when continuing_height is {
          Some(h) -> h > intersecting_level
          None -> True
        }

      and {
        lower_height_valid,
        continuing_height_valid,
      }
    }
  }
}
