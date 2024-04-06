use aiken/builtin
use aiken/bytearray
use aiken/hash

pub const proof_length = 32

pub type Side {
  Left
  Right
}

pub type Root =
  ByteArray

pub opaque type HashedProof {
  inner: ByteArray,
}

fn get_hashed_bytes(p: HashedProof) -> ByteArray {
  p.inner
}

// Plus one byte to tell us whether to prepend or append the proof
pub fn remainder_proofs_size() {
  proof_length + 1
}

pub opaque type MerkleRemainderProofs {
  inner: ByteArray,
}

pub fn convert_bytes_to_remainder_proofs(
  bytes: ByteArray,
) -> MerkleRemainderProofs {
  // 1 byte for deciding which side the proof is on and 32 bytes for the proof hash
  expect bytearray.length(bytes) % remainder_proofs_size() == 0

  MerkleRemainderProofs { inner: bytes }
}

pub fn verify_root(
  bounds: MerkleRemainderProofs,
  hashed_proof: ByteArray,
  root: ByteArray,
) -> Bool {
  do_verify_root(hashed_proof, bounds, bytearray.length(bounds.inner), 0) == root
}

pub fn do_verify_root(
  hashed_proof: ByteArray,
  bounds: MerkleRemainderProofs,
  bounds_length: Int,
  index: Int,
) -> ByteArray {
  if index == bounds_length {
    hashed_proof
  } else {
    // determine which side the proof is on
    if builtin.index_bytearray(bounds.inner, index) == 0 {
      // Sliced bytes are prepended to the proof
      builtin.slice_bytearray(index + 1, proof_length, bounds.inner)
        |> bytearray.concat(hashed_proof)
        |> hash.blake2b_256
        |> do_verify_root(bounds, bounds_length, index + remainder_proofs_size())
    } else {
      // Sliced bytes are appended to the proof
      builtin.slice_bytearray(index + 1, proof_length, bounds.inner)
        |> bytearray.concat(hashed_proof, _)
        |> hash.blake2b_256
        |> do_verify_root(bounds, bounds_length, index + remainder_proofs_size())
    }
  }
}

pub fn combine_sides(
  hashed_left: HashedProof,
  hashed_right: HashedProof,
) -> ByteArray {
  hashed_left
    |> get_hashed_bytes
    |> bytearray.concat(hashed_right |> get_hashed_bytes)
    |> hash.blake2b_256
}

/// Combine the left and right proofs to get the new combined hash
pub fn combine_proofs(
  starting_side: Side,
  remaining_side_proofs: ByteArray,
  hashed_left: HashedProof,
  hashed_right: HashedProof,
  account_hash: ByteArray,
  callback,
) {
  when starting_side is {
    Left -> {
      let left_remaining = remaining_side_proofs |> convert_bytes_to_left_proofs

      let combined_hash =
        hashed_left.inner
          |> left_proof_with_hash(left_remaining)
          |> get_hashed_bytes
          |> bytearray.concat(hashed_right.inner)
          |> hash.blake2b_256

      let new_combined_hash =
        hashed_left.inner
          |> bytearray.concat(account_hash)
          |> hash.blake2b_256
          |> left_proof_with_hash(left_remaining)
          |> get_hashed_bytes
          |> bytearray.concat(hashed_right.inner)
          |> hash.blake2b_256

      callback(combined_hash, new_combined_hash)
    }

    Right -> {
      let right_remaining =
        remaining_side_proofs |> convert_bytes_to_right_proofs

      let combined_hash =
        hashed_right.inner
          |> right_proof_with_hash(right_remaining)
          |> get_hashed_bytes
          |> bytearray.concat(hashed_left.inner, _)
          |> hash.blake2b_256

      let new_combined_hash =
        hashed_right.inner
          |> bytearray.concat(account_hash, _)
          |> hash.blake2b_256
          |> right_proof_with_hash(right_remaining)
          |> get_hashed_bytes
          |> bytearray.concat(hashed_left.inner, _)
          |> hash.blake2b_256

      callback(combined_hash, new_combined_hash)
    }
  }
}

pub opaque type LeftMerkleProofs {
  inner: ByteArray,
}

pub fn convert_bytes_to_left_proofs(bytes: ByteArray) -> LeftMerkleProofs {
  expect bytearray.length(bytes) % proof_length == 0

  LeftMerkleProofs { inner: bytes }
}

// The new item is on the right side of the tree
// so we prepend only left side proofs
pub fn left_proof(left_side: LeftMerkleProofs) -> HashedProof {
  if bytearray.length(left_side.inner) == proof_length {
    HashedProof(left_side.inner)
  } else {
    HashedProof(
      do_left_proof(
        builtin.slice_bytearray(0, proof_length, left_side.inner),
        left_side,
        bytearray.length(left_side.inner),
        proof_length,
      ),
    )
  }
}

// The new item is on the right side of the tree
// so we prepend only left side proofs
pub fn left_proof_with_hash(
  starting_hash: ByteArray,
  left_side: LeftMerkleProofs,
) -> HashedProof {
  if bytearray.length(left_side.inner) == 0 {
    HashedProof(starting_hash)
  } else {
    HashedProof(
      do_left_proof(
        starting_hash,
        left_side,
        bytearray.length(left_side.inner),
        0,
      ),
    )
  }
}

pub fn do_left_proof(
  proof: ByteArray,
  side: LeftMerkleProofs,
  side_length: Int,
  index: Int,
) -> ByteArray {
  if index == side_length {
    proof
  } else {
    // Prepend the proof
    builtin.slice_bytearray(index, proof_length, side.inner)
      |> bytearray.concat(proof)
      |> hash.blake2b_256
      |> do_left_proof(side, side_length, index + proof_length)
  }
}

pub fn get_left_leaf(proofs: LeftMerkleProofs) -> ByteArray {
  builtin.slice_bytearray(0, proof_length, proofs.inner)
}

pub opaque type RightMerkleProofs {
  inner: ByteArray,
}

pub fn convert_bytes_to_right_proofs(bytes: ByteArray) -> RightMerkleProofs {
  expect bytearray.length(bytes) % proof_length == 0

  RightMerkleProofs { inner: bytes }
}

// The new item is on the left side of the tree
// so we append only left side proofs
pub fn right_proof(right_side: RightMerkleProofs) -> HashedProof {
  if bytearray.length(right_side.inner) == proof_length {
    HashedProof(right_side.inner)
  } else {
    HashedProof(
      do_right_proof(
        builtin.slice_bytearray(0, proof_length, right_side.inner),
        right_side,
        bytearray.length(right_side.inner),
        proof_length,
      ),
    )
  }
}

pub fn right_proof_with_hash(
  starting_hash: ByteArray,
  right_side: RightMerkleProofs,
) -> HashedProof {
  if bytearray.length(right_side.inner) == 0 {
    HashedProof(starting_hash)
  } else {
    HashedProof(
      do_right_proof(
        starting_hash,
        right_side,
        bytearray.length(right_side.inner),
        0,
      ),
    )
  }
}

pub fn do_right_proof(
  proof: ByteArray,
  side: RightMerkleProofs,
  side_length: Int,
  index: Int,
) -> ByteArray {
  if index == side_length {
    proof
  } else {
    // Prepend the proof
    builtin.slice_bytearray(index, proof_length, side.inner)
      |> bytearray.concat(proof, _)
      |> hash.blake2b_256
      |> do_right_proof(side, side_length, index + proof_length)
  }
}

pub fn get_right_leaf(proofs: RightMerkleProofs) -> ByteArray {
  builtin.slice_bytearray(0, proof_length, proofs.inner)
}
