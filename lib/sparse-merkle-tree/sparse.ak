use aiken/builtin
use aiken/bytearray
use aiken/hash
use sparse_merkle_tree/consts.{merkle_lower_bound, merkle_upper_bound}
use sparse_merkle_tree/merkle.{
  LeftMerkleProofs, MerkleRemainderProofs, RightMerkleProofs, Root, Side,
  combine_proofs, get_left_leaf, get_right_leaf, left_proof, right_proof,
  verify_root,
}

pub fn init_root() -> Root {
  merkle_lower_bound
    |> bytearray.concat(merkle_upper_bound)
    |> hash.blake2b_256
}

/// Add a new member to the spare merkle tree.
/// Fails if the member is already in the tree.
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
    starting_hash,
    new_starting_hash,
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
    verify_root(remaining_proofs, starting_hash, old_root),
    verify_root(remaining_proofs, new_starting_hash, new_root),
  }
}
