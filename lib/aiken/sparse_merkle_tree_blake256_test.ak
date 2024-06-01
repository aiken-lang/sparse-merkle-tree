use aiken/builtin
use aiken/bytearray
use aiken/cbor
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

fn helper_9_left_proofs() {
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
}

test sparse_merkle_proof_9() {
  let old_root =
    #"5a812ad3240bc532aea6f0b8427ccf929a20bdd0a08bcad062207b14a65e9be8"

  let expected_root =
    #"5cd33d77b3e53cd5433d5c56fb0cc3190a97a09e8e43382dac90883154f75885"

  // #"a454a2dad11be714f134e4d84321728dc596ecf5c91dda47e01c322bf2ad6a37"
  let member = "durian (0)"

  let data_serializer = identity

  let proof_block =
    MerkleProofBlock {
      left_leaf: #"7cf7b9047b2ebdf8bcd289e621c7a8bd304f77f312c287c41848605d8b0deb70",
      right_leaf: #"a909ba8699e34f8a78bacd04266b57f36ff3a758b93c0c31b0aaa18ba0be1e87",
      left_proofs: helper_9_left_proofs(),
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

test sparse_merkle_proof_9_invalid_height() fail {
  let old_root =
    #"5a812ad3240bc532aea6f0b8427ccf929a20bdd0a08bcad062207b14a65e9be8"

  let expected_root =
    #"5cd33d77b3e53cd5433d5c56fb0cc3190a97a09e8e43382dac90883154f75885"

  // #"a454a2dad11be714f134e4d84321728dc596ecf5c91dda47e01c322bf2ad6a37"
  let member = "durian (0)"

  let data_serializer = identity

  let proof_block =
    MerkleProofBlock {
      left_leaf: #"7cf7b9047b2ebdf8bcd289e621c7a8bd304f77f312c287c41848605d8b0deb70",
      right_leaf: #"a909ba8699e34f8a78bacd04266b57f36ff3a758b93c0c31b0aaa18ba0be1e87",
      left_proofs: helper_9_left_proofs(),
      right_proofs: bytearray.concat(
        #"fa",
        bytearray.concat(
          leaf_byte,
          #"af7cd63fd75f935961ba7048b7f81244366198bd43fa60dfc43195a61507b859",
        )
          |> hash.blake2b_256,
      )
        |> bytearray.concat(
            #"feb86f38e6fc5114300c6974b11b583a5df4044b5cda79a4223f4ccd05b81e9355",
          ),
      continuing_side_proofs: #"",
      remaining_proofs: #"",
      left_right_intersection: 255,
      intersecting_level: 251,
    }

  let actual_root = add_member(member, data_serializer, proof_block, old_root)

  expected_root == actual_root
}

test sparse_merkle_proof_10() {
  let old_root =
    #"5cd33d77b3e53cd5433d5c56fb0cc3190a97a09e8e43382dac90883154f75885"

  let expected_root =
    #"ce21ae7b870c1012db2b9d469e95a05540ad74640c236776139e52118d39f2fc"

  // #"138b407b7cc00a52955272bfd7d66b47c8965066bb6ff93b51ad4f9b34e2c445"
  let member = "fig (0)"

  let data_serializer = identity

  let proof_block =
    MerkleProofBlock {
      left_leaf: #"066d2fb8388c75bc53d55bd32eccec14a9b143d64008bc5b55182bd66d8ec160",
      right_leaf: #"3378b5c960257ffe7c3e86d00563739bdf7db730e10732f6b943a4c1802fd05e",
      left_proofs: bytearray.concat(
        bytearray.concat(leaf_byte, merkle_lower_bound)
          |> hash.blake2b_256,
        #"fa",
      ),
      right_proofs: "",
      continuing_side_proofs: #"",
      remaining_proofs: #"01feabcc6f35d5c67f5c8e537d22561cca4dd97e34a5f9e26c332dca9f7e0c5eea0001ff630076edad162e85a61dd7a735d24cde19558aad11e5971d6015120929aac39f",
      left_right_intersection: 253,
      intersecting_level: 252,
    }

  let actual_root = add_member(member, data_serializer, proof_block, old_root)

  expected_root == actual_root
}

fn helper_11_left_proofs() {
  #"a909ba8699e34f8a78bacd04266b57f36ff3a758b93c0c31b0aaa18ba0be1e87"
    |> bytearray.concat(leaf_byte, _)
    |> hash.blake2b_256
    |> bytearray.concat(#"fa")
    |> bytearray.concat(
        bytearray.concat(
          leaf_byte,
          #"a454a2dad11be714f134e4d84321728dc596ecf5c91dda47e01c322bf2ad6a37",
        )
          |> hash.blake2b_256,
      )
    |> bytearray.concat(#"fb")
}

test sparse_merkle_proof_11() {
  let old_root =
    #"ce21ae7b870c1012db2b9d469e95a05540ad74640c236776139e52118d39f2fc"

  let expected_root =
    #"0170b41f8f90f96eb95a0dfc66b959fb4e7060ed738ee162076d03597a0f468f"

  // #"e38564f70616708ffcd52bca9e48480f80168c232a9acfe7fa7e469b62f33c0b"
  let member = "grape (110606)"

  let data_serializer = identity

  let proof_block =
    MerkleProofBlock {
      left_leaf: #"af7cd63fd75f935961ba7048b7f81244366198bd43fa60dfc43195a61507b859",
      right_leaf: #"f674b9b0c22bb6f74dd54716b875e13416a1d270bdf0257c6fd4b864b3cb5b98",
      left_proofs: helper_11_left_proofs(),
      right_proofs: bytearray.concat(
        #"fb",
        bytearray.concat(leaf_byte, merkle_upper_bound)
          |> hash.blake2b_256,
      ),
      continuing_side_proofs: #"",
      remaining_proofs: #"00ab1f2bf177fa615f86f997bc8d92bc27d61f923a34e30e0ac659e831a2e90955ff",
      left_right_intersection: 254,
      intersecting_level: 252,
    }

  let actual_root = add_member(member, data_serializer, proof_block, old_root)

  expected_root == actual_root
}

fn helper_12_right_proofs() {
  let first =
    #"6a91502556c5251ffcd0c5e3a40628de24f9ee0b337b31f2f79b160c5915f64e"
  let second =
    #"7cf7b9047b2ebdf8bcd289e621c7a8bd304f77f312c287c41848605d8b0deb70"

  let first_hash = first |> bytearray.concat(leaf_byte, _) |> hash.blake2b_256
  let second_hash = second |> bytearray.concat(leaf_byte, _) |> hash.blake2b_256

  let first_proof =
    first_hash
      |> bytearray.concat(#"fc")
      |> bytearray.concat(second_hash)
      |> hash.blake2b_256

  bytearray.concat(#"fd", first_proof)
}

test sparse_merkle_proof_12() {
  let old_root =
    #"0170b41f8f90f96eb95a0dfc66b959fb4e7060ed738ee162076d03597a0f468f"

  let expected_root =
    #"92cc9d3ed08668c5d71243ccac72b76b46c924e5cee13583665a13920b244e23"

  // #"3f6ceadf0a21a7a754b9c796a18e83df1da75e59c2f88d09011995ba8dab9059"
  let member = "grapefruit (0)"

  let data_serializer = identity

  let proof_block =
    MerkleProofBlock {
      left_leaf: #"3378b5c960257ffe7c3e86d00563739bdf7db730e10732f6b943a4c1802fd05e",
      right_leaf: #"55d5551e8e1323d35afe53cf8698867c9de9a408e97ee968dc8414d527cc719c",
      left_proofs: #"",
      right_proofs: helper_12_right_proofs(),
      continuing_side_proofs: #"4ac5fceda4fe0ba6787bf5967fc6d24698d0e845ea69f7fec3e41f067928e9f1fd",
      remaining_proofs: #"01ff26363294ff627e13438ecc429926a7cb64686944ec0587128338e3b447dc30e5",
      left_right_intersection: 254,
      intersecting_level: 251,
    }

  let actual_root = add_member(member, data_serializer, proof_block, old_root)

  expected_root == actual_root
}

test sparse_merkle_proof_13() {
  let old_root =
    #"92cc9d3ed08668c5d71243ccac72b76b46c924e5cee13583665a13920b244e23"

  let expected_root =
    #"3e317cdd9858742e7dfddd9200f0d18370970f1bf0a6805a41879fa90c92448a"

  // #"67642ed4cf75856be51541aad36230c8a818513f58888d45b5448e867290e791"
  let member = "guava (0)"

  let data_serializer = identity

  let proof_block =
    MerkleProofBlock {
      left_leaf: #"55d5551e8e1323d35afe53cf8698867c9de9a408e97ee968dc8414d527cc719c",
      right_leaf: #"6a91502556c5251ffcd0c5e3a40628de24f9ee0b337b31f2f79b160c5915f64e",
      left_proofs: #"",
      right_proofs: #"",
      continuing_side_proofs: #"fc12c039450868861fbd107ea5d22b530ac88b258820c868a2129b492e06597e83",
      remaining_proofs: #"00cc6bd81bceb4bf6ff011ab4c90e6e75902e85d8651afdf8479873da399382cbafe01ff26363294ff627e13438ecc429926a7cb64686944ec0587128338e3b447dc30e5",
      left_right_intersection: 253,
      intersecting_level: 251,
    }

  let actual_root = add_member(member, data_serializer, proof_block, old_root)

  expected_root == actual_root
}

test sparse_merkle_proof_14() {
  let old_root =
    #"3e317cdd9858742e7dfddd9200f0d18370970f1bf0a6805a41879fa90c92448a"

  let expected_root =
    #"ef88107c33a1648bf7715acc3a9fbdf3dc495b64247e8074d4585cf6aa35ad9a"

  // #"e0d9ffff534b7c5dad98baa3b5bd143e75ac512243f103c9c7f7da33cf7ce35d"
  let member = "kiwi (0)"

  let data_serializer = identity

  let proof_block =
    MerkleProofBlock {
      left_leaf: #"af7cd63fd75f935961ba7048b7f81244366198bd43fa60dfc43195a61507b859",
      right_leaf: #"e38564f70616708ffcd52bca9e48480f80168c232a9acfe7fa7e469b62f33c0b",
      left_proofs: #"bf15c1592cd12d254b8203d5085eb068eb56f68e5e09b9cb8362df3c94493cd1fadbb028d68f52c20d4055736b69101407d2aefa8d09e9bb7e3ea49f649a6155d3fb",
      right_proofs: #"",
      continuing_side_proofs: #"fcb86f38e6fc5114300c6974b11b583a5df4044b5cda79a4223f4ccd05b81e9355",
      remaining_proofs: #"00ef4267ae7f358032de7a4b03a94e0053c8b2053f7f3192b2d4d3b3de58311177ff",
      left_right_intersection: 254,
      intersecting_level: 249,
    }

  let actual_root = add_member(member, data_serializer, proof_block, old_root)

  expected_root == actual_root
}

test sparse_merkle_proof_15() {
  let old_root =
    #"ef88107c33a1648bf7715acc3a9fbdf3dc495b64247e8074d4585cf6aa35ad9a"

  let expected_root =
    #"9ab9a24cdd3fa9d34bc08ac18a55b5cdbda84cc5a2b77a5c2c9c779ff3cf1547"

  // #"aaf5cb049f3b772c03029f8d44b420ae681c904f0b41ea53360e17fa7f6815c6"
  let member = "kumquat (0)"

  let data_serializer = identity

  let proof_block =
    MerkleProofBlock {
      left_leaf: #"a909ba8699e34f8a78bacd04266b57f36ff3a758b93c0c31b0aaa18ba0be1e87",
      right_leaf: #"af7cd63fd75f935961ba7048b7f81244366198bd43fa60dfc43195a61507b859",
      left_proofs: #"",
      right_proofs: #"",
      continuing_side_proofs: #"",
      remaining_proofs: #"00dbb028d68f52c20d4055736b69101407d2aefa8d09e9bb7e3ea49f649a6155d3fb01fead29ecde0090b8b3098d28675be169f0feda70139ea1dd2c3470620036e01ed700ef4267ae7f358032de7a4b03a94e0053c8b2053f7f3192b2d4d3b3de58311177ff",
      left_right_intersection: 250,
      intersecting_level: 249,
    }

  let actual_root = add_member(member, data_serializer, proof_block, old_root)

  expected_root == actual_root
}

test sparse_merkle_proof_16() {
  let old_root =
    #"9ab9a24cdd3fa9d34bc08ac18a55b5cdbda84cc5a2b77a5c2c9c779ff3cf1547"

  let expected_root =
    #"1b723906517ef72f8b1d59af10f08b771565686301d499cf2d0e3d3fb1459c66"

  // #"e385223186560a8a8b36a5e829075d4bb8663d5734f1c349f5a63ca424c97814"
  let member = "lemon (37694)"

  let data_serializer = identity

  let proof_block =
    MerkleProofBlock {
      left_leaf: #"e0d9ffff534b7c5dad98baa3b5bd143e75ac512243f103c9c7f7da33cf7ce35d",
      right_leaf: #"e38564f70616708ffcd52bca9e48480f80168c232a9acfe7fa7e469b62f33c0b",
      left_proofs: #"",
      right_proofs: #"",
      continuing_side_proofs: #"",
      remaining_proofs: #"01fcb86f38e6fc5114300c6974b11b583a5df4044b5cda79a4223f4ccd05b81e9355006dd12185c33ff535f91e2c87115843e07bdce28d131d4e17c7ead62282845cecfe00ef4267ae7f358032de7a4b03a94e0053c8b2053f7f3192b2d4d3b3de58311177ff",
      left_right_intersection: 249,
      intersecting_level: 238,
    }

  let actual_root = add_member(member, data_serializer, proof_block, old_root)

  expected_root == actual_root
}

test sparse_merkle_proof_17() {
  let old_root =
    #"1b723906517ef72f8b1d59af10f08b771565686301d499cf2d0e3d3fb1459c66"

  let expected_root =
    #"11b63fd19c821efadc7fffea9be9de5ec5425649bdfde63f67af034a6d1cb500"

  // #"6f4ea6fccf5ca9a04569c75849d411720dcf223671be4a75e168f47d6762473f"
  let member = "lime (0)"

  let data_serializer = identity

  let proof_block =
    MerkleProofBlock {
      left_leaf: #"6a91502556c5251ffcd0c5e3a40628de24f9ee0b337b31f2f79b160c5915f64e",
      right_leaf: #"7cf7b9047b2ebdf8bcd289e621c7a8bd304f77f312c287c41848605d8b0deb70",
      left_proofs: #"",
      right_proofs: #"",
      continuing_side_proofs: #"c46b05724575cee0741030ca4269eb52a099df1f5e36311bb6bd1024ede59236fb",
      remaining_proofs: #"00eca601a0494aad382aafa43b6b6972e46a130f5d6b5b81b1fed4ed1b43fa3616fd00cc6bd81bceb4bf6ff011ab4c90e6e75902e85d8651afdf8479873da399382cbafe01ff29343c96b3b2de5abcc8776d85c4b6b8d044d3ea6fb55e78230181d8a0cc105c",
      left_right_intersection: 252,
      intersecting_level: 250,
    }

  let actual_root = add_member(member, data_serializer, proof_block, old_root)

  expected_root == actual_root
}

test sparse_merkle_proof_x() {
  let old_root =
    #"bac6ba4a2096ec1495d2ccc0c4887e6edba895a8a0a4e73ae83270eab3915b52"

  let expected_root =
    #"07a52860f50b324e25f3e37877778699b919ac814bb597c1a4be3623e4b2f490"

  // #"bd0f991572aef335da6ea31786aa8f147f5a4a1d374251548b2d03c008274595"
  let member = "yuzu (0)"

  let data_serializer = identity

  let proof_block =
    MerkleProofBlock {
      left_leaf: #"ba830de32503d8941eee8b8689332e8903841663d99c4442434858b1a147da75",
      right_leaf: #"c85531ce450e18f357f214ca0ef1f2bac4a010a1af5af81ddebf137608c5aad3",
      left_proofs: #"",
      right_proofs: #"fd0a45855e42b616c2ab268fb6419f821c68634637380683d0c894216f83ad6ef4",
      continuing_side_proofs: #"bc0d60e5f1a745633d297f0275d0a6e51171a674b5246df446b6549207ec3bddfc9763947dcfc708abcd0f5bfc8ccec310b91c1db4acd90582d7d2fd2aed3a3ee9fd",
      remaining_proofs: #"004ade9ca0cbd69b8322a0744fa751b4d4a91a280e4945ba5874a0c3fbfe76524dff",
      left_right_intersection: 254,
      intersecting_level: 250,
    }

  let actual_root = add_member(member, data_serializer, proof_block, old_root)

  expected_root == actual_root
}

test sparse_merkle_proof_bitcoin0_12() {
  let old_root =
    #"4aa209b47965b6a849953779938173f05bacde1df715368e343a4378331f00a1"

  let expected_root =
    #"e1f31529b8c64f911ac0e974b61dc75a02df85f8e82e9aaaab391d4f808b0e2f"

  // #"e76950a269b0c113c531238aa57b2271b9a6b1006ef36b6ec29289c385a45e91"
  let member =
    #"0000000097be56d606cdd9c54b04d4747e957d3608abe69198c661f2add73073"

  let data_serializer = identity

  let proof_block =
    MerkleProofBlock {
      left_leaf: #"d4021488c039595fcb330d4d4670fb038747e98e02f2eaed3a8ef1b21dc31620",
      right_leaf: #"ebb7a5b9485ebf3d53a9346b79ef0b2421871299f36d71e00c1dd19a02f70272",
      left_proofs: #"d573180cc035518928c70571a35eb961685197fd1e4c0567dacfd4460615fa8bfc",
      right_proofs: #"fab66272e4e204d0670fc0b75effbd3e2e3323da698ba22d80dbb082beacd0e5b0",
      continuing_side_proofs: #"fcc66d906756f4d29c2f34819e5d6505b48e73524f5f259a03d1f27d4710c7cdbc",
      remaining_proofs: #"00c685d33527ad2dcf8b6450498ef57fddb840c787c50d234e349e7ca50d71b549fe00e388b5fe613ee6ae037be1b0625fbf6f6624beb98e6b58bd3482c9c4294797b5ff",
      left_right_intersection: 253,
      intersecting_level: 251,
    }

  let actual_root = add_member(member, data_serializer, proof_block, old_root)

  expected_root == actual_root
}

test sparse_merkle_proof_bitcoin20k() {
  let old_root =
    #"0c2335d5b6cb0b8c822ab73c59c5dcc5d75b697be2329ed9e1e348ef5328e83d"

  let expected_root =
    #"d429b065ba94985ca9b3abf6299a5cba81add0c90aa15a26e136d7140cabe1d8"

  // #"bc1daccbad8a5820b976a217c0ff3ef8b29ede6553cae4090356ffebf1dd7cf8"
  let member =
    #"00000000ba36eb929dc90170a96ee3efb76cbebee0e0e5c4da9eb0b6e74d9124"

  let data_serializer = identity

  let proof_block =
    MerkleProofBlock {
      left_leaf: #"bc1ca0cbcf9925bb28b1b5ae1f34db929c98ff7880e4c272c5aa27a9fee76fe1",
      right_leaf: #"bc22334d33a3839a9dac95bf25735406af5f02f95ae132360ab301891b1cfb6c",
      left_proofs: #"",
      right_proofs: #"f3da4ee37dfdf3c42bdfd0a6e9a82a9a5385a10ec3ea00144bc3c5ae60ec6a44eef4aacffe9e203b017d02a84f0f85f7d08f09a58a30cac39852f8fa5fb43a408bea",
      continuing_side_proofs: #"d9a1b49e8bfd5078a0650070e262285204982deb602b5ab539771b730b6d6ee1f31eca8e2d3903bed86dc27e88456655020b15aab17b175e3ebaeda94d3c8b085ff4",
      remaining_proofs: #"01f626bbffdd6cc91ab105c2a76b58b17697a51d938ea16b930e8c577a13aa467bb001f7d9dfca90ee9916311dc85cca454bcbbb28dec8de2e4d4fcdac5ec0159e9a998401f8f3904d9be863ff4fee423cb8e08f29111299c9a7717549e875e265a659cf5a2c01f9ae59d09a8003fe3b62547c95454e9b268b15cedec3d4060d2e5eb3364e9c10e20062ab74209c26d3ee8add422ebb3e97d16b8f76a014c149482c6ceb2665c10b65fa0037055c548a34c5480c73299f2f20af25a76f583e5b6b893e7955a8df22d58c3bfb0042216e091635d737f234822cd386edc12a8243773716126f891fe0e4a60ca652fc0062ffd39cbe7e6999bfd221067038f42456c3560c0db1d53c759372896cc54504fd01fe766c637a5b6a2665d2f1af04ef1ea57e6039620604c2f42a6726085361a3c43300b4442d490c6c35e3f98f5766bb9b56f69cca2c9f459333551f60cfd898aace0aff",
      left_right_intersection: 245,
      intersecting_level: 240,
    }

  trace cbor.diagnostic(
    builtin.length_of_bytearray(builtin.serialise_data(proof_block)),
  )

  let actual_root = add_member(member, data_serializer, proof_block, old_root)

  expected_root == actual_root
}
