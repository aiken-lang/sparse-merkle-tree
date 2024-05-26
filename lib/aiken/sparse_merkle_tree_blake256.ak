use aiken/builtin
use aiken/bytearray
use aiken/hash
use aiken/sparse_merkle_tree/consts.{merkle_lower_bound, merkle_upper_bound}
use aiken/sparse_merkle_tree/merkle_blake256.{
  MerkleProofBlock, Root, check_bounds, check_heights, combine_proofs,
  combine_sides, convert_bytes_to_remainder_proofs, get_starting_side,
  hash_to_hashed_proof, leaf_byte, left_proof, right_proof, validate_structure,
  verify_root,
}

pub fn init_root() -> Root<a> {
  let lower_leaf =
    leaf_byte
      |> bytearray.concat(merkle_lower_bound)
      |> hash.blake2b_256

  let upper_leaf =
    leaf_byte |> bytearray.concat(merkle_upper_bound) |> hash.blake2b_256

  upper_leaf
    |> builtin.cons_bytearray(255, _)
    |> bytearray.concat(lower_leaf, _)
    |> hash.blake2b_256
}

/// Verifies a new member was inserted correctly to the spare merkle tree.
/// Returns false if the member is already in the tree.
pub fn verify_added_member(
  member: a,
  data_serializer: fn(a) -> ByteArray,
  proof_block: MerkleProofBlock<a>,
  old_root: Root<a>,
  new_root: Root<a>,
) -> Bool {
  let member_hash = member |> data_serializer |> hash_to_hashed_proof

  let
    left_leaf,
    right_leaf,
    left_proofs,
    right_proofs,
    continuing_side_proofs,
    remaining_proofs,
    left_right_intersection,
    intersecting_level,
  <- validate_structure(proof_block)

  let starting_side =
    get_starting_side(left_leaf, right_leaf, member_hash, intersecting_level)

  let hashed_left = left_leaf |> left_proof(left_proofs)

  let hashed_right = right_leaf |> right_proof(right_proofs)

  let
    before_member_hash,
    after_member_hash,
  <-
    combine_proofs(
      starting_side,
      continuing_side_proofs,
      hashed_left,
      hashed_right,
      member_hash,
      left_right_intersection,
      intersecting_level,
    )

  and {
    check_bounds(left_leaf, right_leaf, member_hash),
    // Verify old and new roots
    verify_root(remaining_proofs, before_member_hash, old_root),
    verify_root(remaining_proofs, after_member_hash, new_root),
    check_heights(
      left_proofs,
      right_proofs,
      continuing_side_proofs,
      intersecting_level,
      starting_side,
    ),
  }
}

/// Verifies a new member was removed correctly from the spare merkle tree.
/// Returns false if the member was not in the tree.
pub fn verify_deleted_member(
  member: a,
  data_serializer: fn(a) -> ByteArray,
  proof_block: MerkleProofBlock<a>,
  old_root: Root<a>,
  new_root: Root<a>,
) -> Bool {
  let member_hash = member |> data_serializer |> hash_to_hashed_proof

  let
    left_leaf,
    right_leaf,
    left_proofs,
    right_proofs,
    continuing_side_proofs,
    remaining_proofs,
    left_right_intersection,
    intersecting_level,
  <- validate_structure(proof_block)

  let starting_side =
    get_starting_side(left_leaf, right_leaf, member_hash, intersecting_level)

  let hashed_left = left_leaf |> left_proof(left_proofs)

  let hashed_right = right_leaf |> right_proof(right_proofs)

  let
    before_member_hash,
    after_member_hash,
  <-
    combine_proofs(
      starting_side,
      continuing_side_proofs,
      hashed_left,
      hashed_right,
      member_hash,
      left_right_intersection,
      intersecting_level,
    )

  and {
    check_bounds(left_leaf, right_leaf, member_hash),
    // Verify old and new roots
    verify_root(remaining_proofs, before_member_hash, new_root),
    verify_root(remaining_proofs, after_member_hash, old_root),
  }
}

/// Verifies a member exists in the spare merkle tree.
/// Returns false if the member was not in the tree.
pub fn member_in_tree(
  member: a,
  data_serializer: fn(a) -> ByteArray,
  remaining_proofs: ByteArray,
  root: Root<a>,
) -> Bool {
  let member_hash = member |> data_serializer |> hash_to_hashed_proof

  let remaining_proofs = remaining_proofs |> convert_bytes_to_remainder_proofs

  verify_root(remaining_proofs, member_hash, root)
}

/// Verifies a member does not exist in the spare merkle tree.
/// Returns false if the member was in the tree.
pub fn member_not_in_tree(
  member: a,
  data_serializer: fn(a) -> ByteArray,
  proof_block: MerkleProofBlock<a>,
  root: Root<a>,
) -> Bool {
  let member_hash = member |> data_serializer |> hash_to_hashed_proof

  let
    left_leaf,
    right_leaf,
    left_proofs,
    right_proofs,
    _continuing_side_proofs,
    remaining_proofs,
    left_right_intersection,
    _intersecting_level,
  <- validate_structure(proof_block)

  // Hash the left and right proofs
  let hashed_left = left_leaf |> left_proof(left_proofs)

  let hashed_right = right_leaf |> right_proof(right_proofs)

  let combined_hash =
    combine_sides(hashed_left, hashed_right, left_right_intersection)

  and {
    // Check valid bounds
    check_bounds(left_leaf, right_leaf, member_hash),
    // Verify old and new roots
    verify_root(remaining_proofs, combined_hash, root),
    proof_block.continuing_side_proofs == "",
  }
}
