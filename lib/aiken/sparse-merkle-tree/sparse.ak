use aiken/builtin
use aiken/bytearray
use aiken/hash
use aiken/sparse_merkle_tree/consts.{merkle_lower_bound, merkle_upper_bound}
use aiken/sparse_merkle_tree/merkle.{
  LeftMerkleProofs, MerkleRemainderProofs, RightMerkleProofs, Root, Side,
  combine_proofs, combine_sides, get_left_leaf, get_right_leaf, left_proof,
  right_proof, verify_root,
}

pub fn init_root() -> Root {
  merkle_lower_bound
    |> bytearray.concat(merkle_upper_bound)
    |> hash.blake2b_256
}

/// Verifies a new member was inserted correctly to the spare merkle tree.
/// Returns false if the member is already in the tree.
pub fn verify_added_member(
  new_member: Data,
  starting_side: Side,
  left_proofs: LeftMerkleProofs,
  right_proofs: RightMerkleProofs,
  remaining_side_proofs: ByteArray,
  remaining_proofs: MerkleRemainderProofs,
  old_root: Root,
  new_root: Root,
) -> Bool {
  let account_hash = new_member |> builtin.serialise_data |> hash.blake2b_256

  // Get left and right leaf to ensure the new item
  // is between 2 existing leafs in the tree
  let left_leaf = left_proofs |> get_left_leaf

  let right_leaf = right_proofs |> get_right_leaf

  // Hash the left and right proofs
  let hashed_left = left_proofs |> left_proof

  let hashed_right = right_proofs |> right_proof

  let
    before_member_hash,
    after_member_hash,
  <-
    combine_proofs(
      starting_side,
      remaining_side_proofs,
      hashed_left,
      hashed_right,
      account_hash,
    )

  and {
    // Check valid bounds
    builtin.less_than_bytearray(left_leaf, account_hash),
    builtin.less_than_bytearray(account_hash, right_leaf),
    builtin.less_than_equals_bytearray(merkle_lower_bound, left_leaf),
    builtin.less_than_bytearray(merkle_lower_bound, right_leaf),
    // Verify old and new roots
    verify_root(remaining_proofs, before_member_hash, old_root),
    verify_root(remaining_proofs, after_member_hash, new_root),
  }
}

/// Verifies a new member was removed correctly from the spare merkle tree.
/// Returns false if the member was not in the tree.
pub fn verify_deleted_member(
  member: Data,
  starting_side: Side,
  left_proofs: LeftMerkleProofs,
  right_proofs: RightMerkleProofs,
  remaining_side_proofs: ByteArray,
  remaining_proofs: MerkleRemainderProofs,
  old_root: Root,
  new_root: Root,
) -> Bool {
  let account_hash = member |> builtin.serialise_data |> hash.blake2b_256

  // Get left and right leaf to ensure the new item
  // is between 2 existing leafs in the tree
  let left_leaf = left_proofs |> get_left_leaf

  let right_leaf = right_proofs |> get_right_leaf

  // Hash the left and right proofs
  let hashed_left = left_proofs |> left_proof

  let hashed_right = right_proofs |> right_proof

  let
    without_member_hash,
    with_member_hash,
  <-
    combine_proofs(
      starting_side,
      remaining_side_proofs,
      hashed_left,
      hashed_right,
      account_hash,
    )

  and {
    // Check valid bounds
    builtin.less_than_bytearray(left_leaf, account_hash),
    builtin.less_than_bytearray(account_hash, right_leaf),
    builtin.less_than_equals_bytearray(merkle_lower_bound, left_leaf),
    builtin.less_than_bytearray(merkle_lower_bound, right_leaf),
    // Verify old and new roots
    verify_root(remaining_proofs, with_member_hash, old_root),
    verify_root(remaining_proofs, without_member_hash, new_root),
  }
}

/// Verifies a member exists in the spare merkle tree.
/// Returns false if the member was not in the tree.
pub fn member_in_tree(
  member: Data,
  remaining_proofs: MerkleRemainderProofs,
  root: Root,
) -> Bool {
  let account_hash = member |> builtin.serialise_data |> hash.blake2b_256

  verify_root(remaining_proofs, account_hash, root)
}

/// Verifies a member does not exist in the spare merkle tree.
/// Returns false if the member was in the tree.
pub fn member_not_in_tree(
  member: Data,
  left_proofs: LeftMerkleProofs,
  right_proofs: RightMerkleProofs,
  remaining_proofs: MerkleRemainderProofs,
  root: Root,
) -> Bool {
  let account_hash = member |> builtin.serialise_data |> hash.blake2b_256

  // Get left and right leaf to ensure the new item
  // is between 2 existing leafs in the tree
  let left_leaf = left_proofs |> get_left_leaf

  let right_leaf = right_proofs |> get_right_leaf

  // Hash the left and right proofs
  let hashed_left = left_proofs |> left_proof

  let hashed_right = right_proofs |> right_proof

  let combined_hash = combine_sides(hashed_left, hashed_right)

  and {
    // Check valid bounds
    builtin.less_than_bytearray(left_leaf, account_hash),
    builtin.less_than_bytearray(account_hash, right_leaf),
    builtin.less_than_equals_bytearray(merkle_lower_bound, left_leaf),
    builtin.less_than_bytearray(merkle_lower_bound, right_leaf),
    // Verify old and new roots
    verify_root(remaining_proofs, combined_hash, root),
  }
}
