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
      // 01 for Right, ff for Height, rest is the hash of the right side of the tree
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
      // 01 for Right, ff for Height, rest is the hash of the right side of the tree
      remaining_proofs: #"01ffdb65bcd7895000b3a79103f0e4089eb8f7c1521fe372b388630e38883ad5e832",
      left_right_intersection: 254,
      intersecting_level: 253,
    }

  let actual_root = add_member(member, data_serializer, proof_block, old_root)

  expected_root == actual_root
}

test sparse_merkle_proof_5() {
  let old_root =
    #"8333b7d8020aa5101ae770c2b8ea84ad84834ea106413d309fbbf226816b6a17"

  let expected_root =
    #"e53502fcf8e19ddd4130fb7430c89f7092e96493d7081486c8b9f452217096df"

  // #"f674b9b0c22bb6f74dd54716b875e13416a1d270bdf0257c6fd4b864b3cb5b98"
  let member = "blueberry (92383)"

  let data_serializer = identity

  let proof_block =
    MerkleProofBlock {
      left_leaf: #"a909ba8699e34f8a78bacd04266b57f36ff3a758b93c0c31b0aaa18ba0be1e87",
      right_leaf: merkle_upper_bound,
      left_proofs: #"",
      right_proofs: #"",
      continuing_side_proofs: "",
      // 00 for Left, ff as the last byte for Height, rest is the hash of the left side of the tree
      remaining_proofs: #"0020239d3b582b94d8580b200cc76df1e787e5040f5fe8737ca47eb311763ef261ff",
      left_right_intersection: 254,
      intersecting_level: 251,
    }

  let actual_root = add_member(member, data_serializer, proof_block, old_root)

  expected_root == actual_root
}

test sparse_merkle_proof_6() {
  let old_root =
    #"e53502fcf8e19ddd4130fb7430c89f7092e96493d7081486c8b9f452217096df"

  let expected_root =
    #"d3161d3695bfb1ddedb5217a712350661bb8042ee7a73deec3686730ac872600"

  // #"6a91502556c5251ffcd0c5e3a40628de24f9ee0b337b31f2f79b160c5915f64e"
  let member = "cherry (0)"

  let data_serializer = identity

  let proof_block =
    MerkleProofBlock {
      left_leaf: #"55d5551e8e1323d35afe53cf8698867c9de9a408e97ee968dc8414d527cc719c",
      right_leaf: #"7cf7b9047b2ebdf8bcd289e621c7a8bd304f77f312c287c41848605d8b0deb70",
      left_proofs: #"",
      right_proofs: #"",
      continuing_side_proofs: "",
      remaining_proofs: #"006a07943147eb4b5f8a0dbb8f8d769a82b38d7c8cdc7fd15c2dc463e88febf453fe01ffaf34fabe162f46ace7707c18d08945b9ceefe15f2ef14d7f39d0cba6715c9dfa",
      left_right_intersection: 253,
      intersecting_level: 252,
    }

  let actual_root = add_member(member, data_serializer, proof_block, old_root)

  expected_root == actual_root
}

test sparse_merkle_proof_7() {
  let old_root =
    #"d3161d3695bfb1ddedb5217a712350661bb8042ee7a73deec3686730ac872600"

  let expected_root =
    #"913b8548e5bd6531610e5eacce933ffec3a29575f5e384fb795320d15ea28c9b"

  // #"af7cd63fd75f935961ba7048b7f81244366198bd43fa60dfc43195a61507b859"
  let member = "coconut (0)"

  let data_serializer = identity

  let proof_block =
    MerkleProofBlock {
      left_leaf: #"a909ba8699e34f8a78bacd04266b57f36ff3a758b93c0c31b0aaa18ba0be1e87",
      right_leaf: #"f674b9b0c22bb6f74dd54716b875e13416a1d270bdf0257c6fd4b864b3cb5b98",
      left_proofs: #"",
      right_proofs: builtin.cons_bytearray(
        251,
        bytearray.concat(leaf_byte, merkle_upper_bound)
          |> hash.blake2b_256,
      ),
      continuing_side_proofs: "",
      remaining_proofs: #"00dfaffc19b4f04093ee4b24b7742bfd73343ae8f4569f5dc1bf95c6d8fb16f5c3ff",
      left_right_intersection: 254,
      intersecting_level: 250,
    }

  let actual_root = add_member(member, data_serializer, proof_block, old_root)

  expected_root == actual_root
}

test sparse_merkle_proof_8() {
  let old_root =
    #"913b8548e5bd6531610e5eacce933ffec3a29575f5e384fb795320d15ea28c9b"

  let expected_root =
    #"5a812ad3240bc532aea6f0b8427ccf929a20bdd0a08bcad062207b14a65e9be8"

  // #"066d2fb8388c75bc53d55bd32eccec14a9b143d64008bc5b55182bd66d8ec160"
  let member = "cranberry (0)"

  let data_serializer = identity

  let proof_block =
    MerkleProofBlock {
      left_leaf: merkle_lower_bound,
      right_leaf: #"3378b5c960257ffe7c3e86d00563739bdf7db730e10732f6b943a4c1802fd05e",
      left_proofs: #"",
      right_proofs: #"",
      continuing_side_proofs: "",
      remaining_proofs: #"01feabcc6f35d5c67f5c8e537d22561cca4dd97e34a5f9e26c332dca9f7e0c5eea0001ffba0aafa15cc035ab43b2384b40c159178eb40395a5d69b5fb7debd4097a6bd92",
      left_right_intersection: 253,
      intersecting_level: 250,
    }

  let actual_root = add_member(member, data_serializer, proof_block, old_root)

  expected_root == actual_root
}

test sparse_merkle_proof_9() {
  let old_root =
    #"5a812ad3240bc532aea6f0b8427ccf929a20bdd0a08bcad062207b14a65e9be8"

  let expected_root =
    #"5cd33d77b3e53cd5433d5c56fb0cc3190a97a09e8e43382dac90883154f75885"

  // #"a454a2dad11be714f134e4d84321728dc596ecf5c91dda47e01c322bf2ad6a37"
  let member = "durian (0)"

  let data_serializer = identity

  let left_proofs =
    #"6a91502556c5251ffcd0c5e3a40628de24f9ee0b337b31f2f79b160c5915f64e"
      |> bytearray.concat(leaf_byte, _)
      |> hash.blake2b_256
      |> bytearray.concat(#"fc")
      |> bytearray.concat(
          bytearray.concat(
            leaf_byte,
            #"55d5551e8e1323d35afe53cf8698867c9de9a408e97ee968dc8414d527cc719c",
          )
            |> hash.blake2b_256
            |> bytearray.concat(#"fd"),
        )
      |> bytearray.concat(
          #"283918a40948a0e69cd88d289b09c54c94300a9c0d379c8b55b8974ec30a3f8a",
        )
      |> bytearray.concat(#"fe")

  let proof_block =
    MerkleProofBlock {
      left_leaf: #"7cf7b9047b2ebdf8bcd289e621c7a8bd304f77f312c287c41848605d8b0deb70",
      right_leaf: #"a909ba8699e34f8a78bacd04266b57f36ff3a758b93c0c31b0aaa18ba0be1e87",
      left_proofs,
      right_proofs: bytearray.concat(
        #"fa",
        bytearray.concat(
          leaf_byte,
          #"af7cd63fd75f935961ba7048b7f81244366198bd43fa60dfc43195a61507b859",
        )
          |> hash.blake2b_256,
      ),
      continuing_side_proofs: #"feb86f38e6fc5114300c6974b11b583a5df4044b5cda79a4223f4ccd05b81e9355",
      remaining_proofs: #"",
      left_right_intersection: 255,
      intersecting_level: 251,
    }

  let actual_root = add_member(member, data_serializer, proof_block, old_root)

  expected_root == actual_root
}
