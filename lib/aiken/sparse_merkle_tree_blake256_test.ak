use aiken/builtin
use aiken/bytearray
use aiken/hash
use aiken/sparse_merkle_tree/consts.{merkle_lower_bound, merkle_upper_bound}
use aiken/sparse_merkle_tree/merkle_blake256.{
  MerkleProofBlock, Root, check_bounds, check_heights, combine_proofs,
  get_starting_side, hash_to_hashed_proof, leaf_byte, left_proof, right_proof,
  test_add_member, to_string, validate_structure, verify_root,
}
use aiken/sparse_merkle_tree_blake256.{init_root}

fn add_member(
  member: a,
  data_serializer: fn(a) -> ByteArray,
  proof_block: MerkleProofBlock<a>,
  old_root: Root<a>,
) -> ByteArray {
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

  trace to_string(member_hash)

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

  expect and {
      check_bounds(left_leaf, right_leaf, member_hash)?,
      // Verify old and new roots
      verify_root(remaining_proofs, before_member_hash, old_root)?,
      check_heights(
        left_proofs,
        right_proofs,
        continuing_side_proofs,
        intersecting_level,
        starting_side,
      )?,
    }

  test_add_member(remaining_proofs, after_member_hash)
}

test sparse_merkle_proof_1() {
  let old_root = init_root()

  let expected_root =
    #"18c8dbcc059576ec251c90862baee3387c4ea916ef72e6f7dbf15502521ebed2"

  // #"7cf7b9047b2ebdf8bcd289e621c7a8bd304f77f312c287c41848605d8b0deb70"
  let member = "apple (0)"

  let data_serializer = identity

  let proof_block =
    MerkleProofBlock {
      left_leaf: merkle_lower_bound,
      right_leaf: merkle_upper_bound,
      left_proofs: "",
      right_proofs: "",
      continuing_side_proofs: "",
      remaining_proofs: "",
      left_right_intersection: 255,
      intersecting_level: 254,
    }

  let actual_root = add_member(member, data_serializer, proof_block, old_root)

  expected_root == actual_root
}

test sparse_merkle_proof_2() {
  let old_root =
    #"18c8dbcc059576ec251c90862baee3387c4ea916ef72e6f7dbf15502521ebed2"

  let expected_root =
    #"49148fa603b03d70fff1733cb9a70a35b9057637e11cde68e30f6f624b001504"

  // #"a909ba8699e34f8a78bacd04266b57f36ff3a758b93c0c31b0aaa18ba0be1e87"
  let member = "apricot (0)"

  let data_serializer = identity

  let proof_block =
    MerkleProofBlock {
      left_leaf: #"7cf7b9047b2ebdf8bcd289e621c7a8bd304f77f312c287c41848605d8b0deb70",
      right_leaf: merkle_upper_bound,
      left_proofs: bytearray.concat(
        bytearray.concat(leaf_byte, merkle_lower_bound) |> hash.blake2b_256,
        #"fe",
      ),
      right_proofs: "",
      continuing_side_proofs: "",
      remaining_proofs: "",
      left_right_intersection: 255,
      intersecting_level: 254,
    }

  let actual_root = add_member(member, data_serializer, proof_block, old_root)

  expected_root == actual_root
}

test sparse_merkle_proof_3() {
  let old_root =
    #"49148fa603b03d70fff1733cb9a70a35b9057637e11cde68e30f6f624b001504"

  let expected_root =
    #"9ea42e89c070ee103f27ae748c0aa9ce268d2f44e66568423409fa4f659cdb7a"

  // #"55d5551e8e1323d35afe53cf8698867c9de9a408e97ee968dc8414d527cc719c"
  let member = "banana (328)"

  let data_serializer = identity

  let proof_block =
    MerkleProofBlock {
      left_leaf: merkle_lower_bound,
      right_leaf: #"7cf7b9047b2ebdf8bcd289e621c7a8bd304f77f312c287c41848605d8b0deb70",
      left_proofs: "",
      right_proofs: #"",
      continuing_side_proofs: "",
      // 01 for Left, ff for Height, rest is the hash of the right side of the tree
      remaining_proofs: #"01ffdb65bcd7895000b3a79103f0e4089eb8f7c1521fe372b388630e38883ad5e832",
      left_right_intersection: 254,
      intersecting_level: 253,
    }

  let actual_root = add_member(member, data_serializer, proof_block, old_root)

  expected_root == actual_root
}

test sparse_merkle_proof_4() {
  let old_root =
    #"9ea42e89c070ee103f27ae748c0aa9ce268d2f44e66568423409fa4f659cdb7a"

  let expected_root =
    #"8333b7d8020aa5101ae770c2b8ea84ad84834ea106413d309fbbf226816b6a17"

  // #"3378b5c960257ffe7c3e86d00563739bdf7db730e10732f6b943a4c1802fd05e"
  let member = "blackberry (0)"

  let data_serializer = identity

  let proof_block =
    MerkleProofBlock {
      left_leaf: merkle_lower_bound,
      right_leaf: #"55d5551e8e1323d35afe53cf8698867c9de9a408e97ee968dc8414d527cc719c",
      left_proofs: #"",
      right_proofs: bytearray.concat(
        #"fd",
        bytearray.concat(
          leaf_byte,
          #"7cf7b9047b2ebdf8bcd289e621c7a8bd304f77f312c287c41848605d8b0deb70",
        )
          |> hash.blake2b_256,
      ),
      continuing_side_proofs: "",
      // 01 for Left, ff for Height, rest is the hash of the right side of the tree
      remaining_proofs: #"01ffdb65bcd7895000b3a79103f0e4089eb8f7c1521fe372b388630e38883ad5e832",
      left_right_intersection: 254,
      intersecting_level: 253,
    }

  let actual_root = add_member(member, data_serializer, proof_block, old_root)

  expected_root == actual_root
}
