use aiken/builtin
use aiken/bytearray
use aiken/cbor
use aiken/fuzz.{and_then, bytearray as byte_fuzzer, map}
use aiken/hash
use aiken/list
use aiken/math
use aiken/sparse_merkle_tree/merkle.{
  Left, Right, combine_proofs, convert_bytes_to_left_proofs,
  convert_bytes_to_remainder_proofs, convert_bytes_to_right_proofs, leaf_byte,
  left_proof, right_proof, verify_root,
}
use aiken/string

fn list_at(l: List<a>, index: Int) -> a {
  if index == 0 {
    builtin.head_list(l)
  } else {
    list_at(builtin.tail_list(l), index - 1)
  }
}

fn get_16_bytearrays() -> Fuzzer<List<ByteArray>> {
  let a <- and_then(byte_fuzzer())
  let b <- and_then(byte_fuzzer())
  let c <- and_then(byte_fuzzer())
  let d <- and_then(byte_fuzzer())
  let e <- and_then(byte_fuzzer())
  let f <- and_then(byte_fuzzer())
  let g <- and_then(byte_fuzzer())
  let h <- and_then(byte_fuzzer())
  let i <- and_then(byte_fuzzer())
  let j <- and_then(byte_fuzzer())
  let k <- and_then(byte_fuzzer())
  let l <- and_then(byte_fuzzer())
  let m <- and_then(byte_fuzzer())
  let n <- and_then(byte_fuzzer())
  let o <- and_then(byte_fuzzer())
  let p <- map(byte_fuzzer())

  [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p]
}

pub fn get_128_bytearrays() -> Fuzzer<List<ByteArray>> {
  let a1 <- and_then(get_16_bytearrays())
  let a2 <- and_then(get_16_bytearrays())
  let a3 <- and_then(get_16_bytearrays())
  let a4 <- and_then(get_16_bytearrays())
  let a5 <- and_then(get_16_bytearrays())
  let a6 <- and_then(get_16_bytearrays())
  let a7 <- and_then(get_16_bytearrays())
  let a8 <- map(get_16_bytearrays())

  a1
    |> list.concat(a2)
    |> list.concat(a3)
    |> list.concat(a4)
    |> list.concat(a5)
    |> list.concat(a6)
    |> list.concat(a7)
    |> list.concat(a8)
}

// fn get_index_and_level_in_bytearray_list() -> Fuzzer<(Int, List<ByteArray>)> {
//   let bytes_list <- and_then(get_128_bytearrays())

//   let index <- map(int_between(23, 99))

//   (index, bytes_list)
// }

// assume list is even
fn merklize_one_level(leaves: List<ByteArray>) -> List<ByteArray> {
  when leaves is {
    [] ->
      []
    [_] -> fail @"impossible"
    [a, b, ..rest] -> {
      let hash = bytearray.concat(a, b) |> hash.blake2b_256

      [hash, ..merklize_one_level(rest)]
    }
  }
}

test merkle_1(bytes_list via get_16_bytearrays()) {
  let first_item = list_at(bytes_list, 7)

  let first_proof = list_at(bytes_list, 6)

  let level_one = merklize_one_level(bytes_list)

  let level_one_hash = list_at(level_one, 2)

  let level_two = merklize_one_level(level_one)

  let level_two_hash = list_at(level_two, 0)

  let level_three = merklize_one_level(level_two)

  let level_three_hash = list_at(level_three, 1)

  expect [root] = merklize_one_level(level_three)

  let proof_list =
    [
      #[0],
      first_proof,
      #[0],
      level_one_hash,
      #[0],
      level_two_hash,
      #[1],
      level_three_hash,
    ]

  let proofs =
    list.foldr(proof_list, #"", fn(x, acc) { bytearray.concat(x, acc) })

  let remaining_proofs = proofs |> convert_bytes_to_remainder_proofs

  verify_root(remaining_proofs, first_item, root)
}

test merkle_2(bytes_list via get_16_bytearrays()) {
  let first_item = list_at(bytes_list, 9)

  let first_proof = list_at(bytes_list, 8)

  let level_one = merklize_one_level(bytes_list)

  let level_one_hash = list_at(level_one, 5)

  let level_two = merklize_one_level(level_one)

  let level_two_hash = list_at(level_two, 3)

  let level_three = merklize_one_level(level_two)

  let level_three_hash = list_at(level_three, 0)

  expect [root] = merklize_one_level(level_three)

  let proof_list =
    [
      #[0],
      first_proof,
      #[1],
      level_one_hash,
      #[1],
      level_two_hash,
      #[0],
      level_three_hash,
    ]

  let proofs =
    list.foldr(proof_list, #"", fn(x, acc) { bytearray.concat(x, acc) })

  let remaining_proofs = proofs |> convert_bytes_to_remainder_proofs

  verify_root(remaining_proofs, first_item, root)
}

test merkle_3(bytes_list via get_16_bytearrays()) {
  let branch_list =
    bytes_list
      |> list.map(
          fn(x) {
            x
              |> bytearray.concat(leaf_byte, _)
              |> hash.blake2b_256
          },
        )

  let new_item = list_at(bytes_list, 9) |> hash.blake2b_256

  let left_side_closest = list_at(bytes_list, 7)

  let left_side_neighbor = list_at(branch_list, 6)

  let right_side_closest = list_at(bytes_list, 12)

  let right_side_neighbor = list_at(branch_list, 13)

  let level_one = merklize_one_level(branch_list)

  let level_one_left = list_at(level_one, 2)

  let level_one_right = list_at(level_one, 7)

  let level_two = merklize_one_level(level_one)

  let level_two_left = list_at(level_two, 0)

  let level_two_modified =
    list.indexed_map(
      level_two,
      fn(i, x) {
        if i == 2 {
          new_item
            |> bytearray.concat(leaf_byte, _)
            |> hash.blake2b_256
        } else {
          x
        }
      },
    )

  let level_three = merklize_one_level(level_two_modified)

  expect [root] = merklize_one_level(level_three)

  let left_list =
    [left_side_closest, left_side_neighbor, level_one_left, level_two_left]

  let right_list =
    [right_side_closest, right_side_neighbor, level_one_right]

  let remaining_side_proofs = ""

  let proof_list =
    []

  let left_proofs =
    list.foldr(left_list, #"", fn(x, acc) { bytearray.concat(x, acc) })

  let right_proofs =
    list.foldr(right_list, #"", fn(x, acc) { bytearray.concat(x, acc) })

  let proofs =
    list.foldr(proof_list, #"", fn(x, acc) { bytearray.concat(x, acc) })

  let left_proof_final =
    left_proofs
      |> convert_bytes_to_left_proofs
      |> left_proof

  let right_proof_final =
    right_proofs
      |> convert_bytes_to_right_proofs
      |> right_proof

  let remaining_proofs = proofs |> convert_bytes_to_remainder_proofs

  let
    _,
    combined_hash,
  <-
    combine_proofs(
      Right,
      remaining_side_proofs,
      left_proof_final,
      right_proof_final,
      new_item,
    )

  verify_root(remaining_proofs, combined_hash, root)
}

fn merkle_4_setup() {
  let bytes_list =
    [
      #"0379899ac4a85a30898d29e5041f8c6cf398d370f08b48ce258cdc376e5b8c8c",
      #"2413b790b449b5134f357e5afed5149073b21bb6808650f1da5c821bef9fb25a",
      #"56b3f804e7d380264dd9d26b8f5af2fc5624b9c7c4751c16d288a28ee9d2e401",
      #"a801bfafdc95b4f98196ada7d4d99ca22c2e3ca4f2a5b9704ad48ba0bacf6313",
      #"1f90b49b9ff263fceb6bb86286a771697f99b7b8282270876c5b6aa04c28fa18",
      #"3c4cb28da90f5a784cdbdd3c1c154cdd5a7b44b31882a5bb1ee7f3e9a14a77d8",
      #"541431258d0e7b58145337cb491cd98d425e7fd77bbd81679a28ab5689a4ac5e",
      #"dcf93f6a91df8ff87f4e17ec954a79ab3ebf330b87d9e3457b6f0eef1230abe4",
      #"1e6b2d4e73051f97dc43ca3319e07c0f49bc1e493d56814537c6125c43359c7d",
      #"9581c5e21a94884538e1212bb666df18bd353eb1c03c20bd473fa6f3fc21162c",
      #"30a6de707aa2ac2fa0d302b6a321c63291f147a3c6c2f3172fbf484ce42761d5",
      #"29847997b0d56a12b7fd2ac72618bba69cf28293a03d88c3bd0ee9ee1fee110d",
      #"77bbf46b3cc8f5620d170b201bb2a7e3a4508e53b2ae17cf1d1b9add18314cc3",
      #"83d32921e87c9a88db3ac56a1e6b8552c9732911a977927bd2e58b3add48683c",
      #"064d2e79dc1f95fbdf8ebad4f95676c10ffc1696131731badf30b38f4f60b66d",
      #"03cfeeb613c20b73496ea0402a36ba05733d7cea285676c5f540e98b5ff39930",
    ]

  let branch_list =
    bytes_list
      |> list.map(
          fn(x) {
            x
              |> bytearray.concat(leaf_byte, _)
              |> hash.blake2b_256
          },
        )

  let new_item = list_at(bytes_list, 9) |> hash.blake2b_256

  let left_side_closest = list_at(bytes_list, 7)

  let left_side_neighbor = list_at(branch_list, 6)

  let right_side_closest = list_at(bytes_list, 12)

  let right_side_neighbor = list_at(branch_list, 13)

  let level_one = merklize_one_level(branch_list)

  let level_one_left = list_at(level_one, 2)

  let level_one_right = list_at(level_one, 7)

  let level_two = merklize_one_level(level_one)

  let level_two_left = list_at(level_two, 0)

  let level_two_modified =
    list.indexed_map(
      level_two,
      fn(i, x) {
        if i == 2 {
          new_item
            |> bytearray.concat(leaf_byte, _)
            |> hash.blake2b_256
        } else {
          x
        }
      },
    )

  let level_three = merklize_one_level(level_two_modified)

  expect [root] = merklize_one_level(level_three)

  let left_list =
    [left_side_closest, left_side_neighbor, level_one_left, level_two_left]

  let right_list =
    [right_side_closest, right_side_neighbor, level_one_right]

  let proof_list =
    []

  let left_proofs =
    list.foldr(left_list, #"", fn(x, acc) { bytearray.concat(x, acc) })

  let right_proofs =
    list.foldr(right_list, #"", fn(x, acc) { bytearray.concat(x, acc) })

  let proofs =
    list.foldr(proof_list, #"", fn(x, acc) { bytearray.concat(x, acc) })

  fn(g) { g(left_proofs, right_proofs, proofs, new_item, root) }
}

test merkle_4() {
  let left_proofs, right_proofs, proofs, new_item, root <- merkle_4_setup()()

  let remaining_side_proofs = ""

  let left_proof_final =
    left_proofs
      |> convert_bytes_to_left_proofs
      |> left_proof

  let right_proof_final =
    right_proofs
      |> convert_bytes_to_right_proofs
      |> right_proof

  let remaining_proofs = proofs |> convert_bytes_to_remainder_proofs

  let
    _,
    combined_hash,
  <-
    combine_proofs(
      Right,
      remaining_side_proofs,
      left_proof_final,
      right_proof_final,
      new_item,
    )

  verify_root(remaining_proofs, combined_hash, root)?
}

fn merkle_5_setup() {
  let bytes_list =
    [
      #"037989aac4a85a30898d29e5041f8c6cf398d370f08b48ce258cdc376e5b8c8c",
      #"2413b790b449b5134f357e5afed5149073b21bb6808650f1da5c821bef9fb25a",
      #"56b3f804e7d380264dd9d26b8f5af2fc5624b9c7c4751c16d288a28ee9d2e401",
      #"a801bfafdc95b4f98196ada7d4d99ca22c2e3ca4f2a5b9704ad48ba0bacf6313",
      #"1f90b49b9ff263fceb6bb86286a771697f99b7b8282270876c5b6aa04c28fa18",
      #"3c4cb28da90f5a784cdbdd3c1c154cdd5a7b44b31882a5bb1ee7f3e9a14a77d8",
      #"541431258d0e7b58145337cb491cd98d425e7fd77bbd81679a28ab5689a4ac5e",
      #"dcf93f6a91df8ff87f4e17ec954a79ab3ebf330b87d9e3457b6f0eef1230abe4",
      #"1e6b2d4e73051f97dc43ca3319e07c0f49bc1e493d56814537c6125c43359c7d",
      #"9581c5e21a94884538e1212bb666df18bd353eb1c03c20bd473fa6f3fc21162c",
      #"30a6de707aa2ac2fa0d302b6a321c63291f147a3c6c2f3172fbf484ce42761d5",
      #"29847997b0d56a12b7fd2ac72618bba69cf28293a03d88c3bd0ee9ee1fee110d",
      #"77bbf46b3cc8f5620d170b201bb2a7e3a4508e53b2ae17cf1d1b9add18314cc3",
      #"83d32921e87c9a88db3ac56a1e6b8552c9732911a977927bd2e58b3add48683c",
      #"064d2e79dc1f95fbdf8ebad4f95676c10ffc1696131731badf30b38f4f60b66d",
      #"04cfeeb613c20b73496ea0402a36ba05733d7cea285676c5f540e98b5ff39930",
      #"0379899ac4a85a30898d29e5041f8c6cf398d370f08b48ce258cdc376e5b8c8c",
      #"2413b790b449b5134f357e5afed5149073b21bb6808650f1da5c821bef9fb25a",
      #"56b3f804e7d380264dd9d26b8f5af2fc5624b9c7c4751c16d288a28ee9d2e401",
      #"a801bfafdc95b4f98196ada7d4d99ca22c2e3ca4f2a5b9704ad48ba0bacf6313",
      #"1f90b49b9ff263fceb6bb86286a771697f99b7b8282270876c5b6aa04c28fa18",
      #"3c4cb28da90f5a784cdbdd3c1c154cdd5a7b44b31882a5bb1ee7f3e9a14a77d8",
      #"541431258d0e7b58145337cb491cd98d425e7fd77bbd81679a28ab5689a4ac5e",
      #"dcf93f6a91df8ff87f4e17ec954a79ab3ebf330b87d9e3457b6f0eef1230abe4",
      #"1e6b2d4e73051f97dc43ca3319e07c0f49bc1e493d56814537c6125c43359c7d",
      #"9581c5e21a94884538e1212bb666df18bd353eb1c03c20bd473fa6f3fc21162c",
      #"30a6de707aa2ac2fa0d302b6a321c63291f147a3c6c2f3172fbf484ce42761d5",
      #"29847997b0d56a12b7fd2ac72618bba69cf28293a03d88c3bd0ee9ee1fee110d",
      #"77bbf46b3cc8f5620d170b201bb2a7e3a4508e53b2ae17cf1d1b9add18314cc3",
      #"83d32921e87c9a88db3ac56a1e6b8552c9732911a977927bd2e58b3add48683c",
      #"064d2e79dc1f95fbdf8ebad4f95676c10ffc1696131731badf30b38f4f60b66d",
      #"05cfeeb613c20b73496ea0402a36ba05733d7cea285676c5f540e98b5ff39930",
    ]

  let branch_list =
    bytes_list
      |> list.map(
          fn(x) {
            x
              |> bytearray.concat(leaf_byte, _)
              |> hash.blake2b_256
          },
        )

  let new_item = list_at(bytes_list, 15) |> hash.blake2b_256

  let left_side_closest = list_at(bytes_list, 11)

  let left_side_neighbor = list_at(branch_list, 10)

  let right_side_closest = list_at(bytes_list, 16)

  let right_side_neighbor = list_at(branch_list, 17)

  let level_one = merklize_one_level(branch_list)

  let level_one_left = list_at(level_one, 4)

  let level_one_right = list_at(level_one, 9)

  let level_two = merklize_one_level(level_one)

  let level_two_right = list_at(level_two, 5)

  let level_two_modified =
    list.indexed_map(
      level_two,
      fn(i, x) {
        if i == 3 {
          new_item
            |> bytearray.concat(leaf_byte, _)
            |> hash.blake2b_256
        } else {
          x
        }
      },
    )

  let level_three = merklize_one_level(level_two_modified)

  let level_three_right = list_at(level_three, 3)

  let remaining_left_side_proofs = list_at(level_three, 0)

  let level_four = merklize_one_level(level_three)

  expect [root] = merklize_one_level(level_four)

  let left_list =
    [left_side_closest, left_side_neighbor, level_one_left]

  let right_list =
    [
      right_side_closest,
      right_side_neighbor,
      level_one_right,
      level_two_right,
      level_three_right,
    ]

  let proof_list =
    []

  let left_proofs =
    list.foldr(left_list, #"", fn(x, acc) { bytearray.concat(x, acc) })

  let right_proofs =
    list.foldr(right_list, #"", fn(x, acc) { bytearray.concat(x, acc) })

  let proofs =
    list.foldr(proof_list, #"", fn(x, acc) { bytearray.concat(x, acc) })

  fn(g) {
    g(
      left_proofs,
      right_proofs,
      remaining_left_side_proofs,
      proofs,
      new_item,
      root,
    )
  }
}

test output_merkle() {
  let thing =
    [
      #"0000000000000000000000000000000000000000000000000000000000000000",
      #"037989aac4a85a30998d29e5041f8c6cf398d370f08b48ce258cdc376e5b8c8c",
      #"0379899ac4a85a30891d29e5041f8c6cf398d370f08b48ce258cdc376e5b8c8c",
      #"2483b790b459b5134f357e5afed5149073b21bb6808650f1da5c821bef9fb25a",
      #"56b3f804e7e380264dd9d26b8f5af2fc5624b9c7c4751c16d288a28ee9d2e401",
      #"a802bfafdc95b4f98196ada7d4d99ca22c2e3ca4f2a5b9704ad48ba0bacf6313",
      #"1f90c49b9ff263fceb6bb86286a771697f99b7b8282270876c5b6aa04c28fa18",
      #"3c4cc28da90f5a784cdbdd3c1c154cdd5a7b44b31882a5bb1ee7f3e9a14a77d8",
      #"541431358d0e7b58145337cb491cd98d425e7fd77bbd81679a28ab5689a4ac5e",
      #"dcf93f6a91de8ff87f4e17ec954a79ab3ebf330b87d9e3457b6f0eef1230abe4",
      #"1e6b2d4e73031f97dc43ca3319e07c0f49bc1e493d56814537c6125c43359c7d",
      #"9581c5e21a94584538e1212bb666df18bd353eb1c03c20bd473fa6f3fc21162c",
      #"30a6de707aa2bc2fa0d302b6a321c63291f147a3c6c2f3172fbf484ce42761d5",
      #"29847997b0d57a12b7fd2ac72618bba69cf28293a03d88c3bd0ee9ee1fee110d",
      #"77bbf46b3cc8f5621d170b201bb2a7e3a4508e53b2ae17cf1d1b9add18314cc3",
      #"83d32921e47c9a88db3ac56a1e6b8552c9732911a977927bd2e58b3add48683c",
      #"064d2e79dc1f93fbdf8ebad4f95676c10ffc1696131731badf30b38f4f60b66d",
      #"04cfeeb613c20b73496ea0402a31ba05733d7cea285676c5f540e98b5ff39930",
      #"2413b790b449b5134f357e5afed5149073b21bb6808650f1da5c821bef9fb25a",
      #"56b3f804e7d380264dd9d26b8f5af2fc5624b9c7c4751c16d288a28ee9d2e401",
      #"a801bfafdc95b4f98196ada7d4d99ca22c2e3ca4f2a5b9704ad48ba0bacf6313",
      #"1f90b49b9ff263fceb6bb86286a771697f99b7b8282270876c5b6aa04c28fa18",
      #"3c4cb28da90f5a784cdbdd3c1c154cdd5a7b44b31882a5bb1ee7f3e9a14a77d8",
      #"541431258d0e7b58145337cb491cd98d425e7fd77bbd81679a28ab5689a4ac5e",
      #"dcf93f6a91df8ff87f4e17ec954a79ab3ebf330b87d9e3457b6f0eef1230abe4",
      #"1e6b2d4e73051f97dc43ca3319e07c0f49bc1e493d56814537c6125c43359c7d",
      #"9581c5e21a94884538e1212bb666df18bd353eb1c03c20bd473fa6f3fc21162c",
      #"30a6de707aa2ac2fa0d302b6a321c63291f147a3c6c2f3172fbf484ce42761d5",
      #"29847997b0d56a12b7fd2ac72618bba69cf28293a03d88c3bd0ee9ee1fee110d",
      #"77bbf46b3cc8f5620d170b201bb2a7e3a4508e53b2ae17cf1d1b9add18314cc3",
      #"83d32921e87c9a88db3ac56a1e6b8552c9732911a977927bd2e58b3add48683c",
      #"064d2e79dc1f95fbdf8ebad4f95676c10ffc1696131731badf30b38f4f60b66d",
      #"05cfeeb613c20b73496ea0402a36ba05733d7cea285676c5f540e98b5ff39930",
      #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ]

  let thing =
    thing
      |> list.sort(bytearray.compare)

  let thing =
    thing
      |> list.map(
          fn(x) {
            (
              builtin.bytearray_to_integer(True, x),
              x
                |> bytearray.concat(leaf_byte, _)
                |> hash.blake2b_256,
            )
          },
        )

  let (_, level_one) = sparse_merkelize_level(thing)
  let (_, level_two) = sparse_merkelize_level(level_one)
  let (_, level_three) = sparse_merkelize_level(level_two)
  let (_, level_four) = sparse_merkelize_level(level_three)
  let (_, level_five) = sparse_merkelize_level(level_four)
  let (_, level_six) = sparse_merkelize_level(level_five)
  let (_, level_seven) = sparse_merkelize_level(level_six)
  let (_, level_eight) = sparse_merkelize_level(level_seven)
  let (_, level_nine) = sparse_merkelize_level(level_eight)

  trace [
    @"\n\nthing\n",
    cbor.diagnostic(thing),
    @"\n\nlevel_one\n",
    cbor.diagnostic(level_one),
    @"\n\nlevel_two\n",
    cbor.diagnostic(level_two),
    @"\n\nlevel_three\n",
    cbor.diagnostic(level_three),
    @"\n\nlevel_four\n",
    cbor.diagnostic(level_four),
    @"\n\nlevel_five\n",
    cbor.diagnostic(level_five),
    @"\n\nlevel_six\n",
    cbor.diagnostic(level_six),
    @"\n\nlevel_seven\n",
    cbor.diagnostic(level_seven),
    @"\n\nlevel_eight\n",
    cbor.diagnostic(level_eight),
    @"\n\nlevel_nine\n",
    cbor.diagnostic(level_nine),
  ]
    |> string.join(@"")
  True
}

test merkle_5() {
  let
    left_proofs,
    right_proofs,
    remaining_left_side_proofs,
    proofs,
    new_item,
    root,
  <- merkle_5_setup()()

  let left_proof_final =
    left_proofs
      |> convert_bytes_to_left_proofs
      |> left_proof

  let right_proof_final =
    right_proofs
      |> convert_bytes_to_right_proofs
      |> right_proof

  let remaining_proofs = proofs |> convert_bytes_to_remainder_proofs

  let
    _,
    combined_hash,
  <-
    combine_proofs(
      Left,
      remaining_left_side_proofs,
      left_proof_final,
      right_proof_final,
      new_item,
    )

  verify_root(remaining_proofs, combined_hash, root)
}

fn fold2_items(
  l: List<a>,
  default: b,
  f: fn(a, a, b) -> b,
  f1: fn(a, b) -> b,
) -> b {
  when l is {
    [] -> default
    [x, ..rest] ->
      when rest is {
        [] -> f1(x, default)
        [y, ..rest] -> f(x, y, fold2_items(rest, default, f, f1))
      }
  }
}

fn sparse_merkelize_level(
  l: List<(Int, ByteArray)>,
) -> (Int, List<(Int, ByteArray)>) {
  expect Some(smallest_distance) =
    l
      |> fold2_items(
          None,
          fn(x, y, acc) {
            let distance = y.1st - x.1st
            when acc is {
              None -> Some(distance)
              Some(d) -> Some(math.min(d, distance))
            }
          },
          fn(_x, acc) { acc },
        )

  let divisor = math.pow2(math.log(smallest_distance, 2)) * 2

  let new_list =
    l
      |> list.foldr(
          [],
          fn(x, acc: List<(Int, ByteArray)>) {
            when acc is {
              [] ->
                [(x.1st / divisor, x.2nd)]
              [y, ..rest] -> {
                let x_d = x.1st / divisor
                let y_d = y.1st

                if x_d == y_d {
                  let new_bytes =
                    bytearray.concat(x.2nd, y.2nd) |> hash.blake2b_256
                  [(x_d, new_bytes), ..rest]
                } else {
                  [(x_d, x.2nd), ..acc]
                }
              }
            }
          },
        )

  (divisor, new_list)
}
// fn get_index(l: List<(Int, a)>, key: Int, current_index: Int) -> Int {
//   expect [(key2, _), ..rest] = l

//   if key == key2 {
//     current_index
//   } else {
//     get_index(rest, key, current_index + 1)
//   }
// }

// fn do_get_proofs(
//   map_list: List<(Int, ByteArray)>,
//   index: Int,
//   item: (Int, ByteArray),
//   left: List<ByteArray>,
//   right: List<ByteArray>,
//   remaining_side,
//   remaining_proofs,
//   left_final,
//   right_final,
//   remaining_side_final,
//   side_final,
// ) {
//   let (divisor, next_level) = sparse_merkelize_level(map_list)

//   let item_key = item.1st / divisor

//   let new_item_index = get_index(next_level, item_key, 0)

//   let new_item = list_at(next_level, new_item_index)

//   if new_item.2nd == item.2nd {
//     let new_left = list_at(next_level, new_item_index - 1)
//     let new_right = list_at(next_level, new_item_index + 1)

//     let left =
//       if new_left.2nd == list_at(left, 0) {
//         left
//       } else {
//         let thing = list_at(map_list, index - 2)
//         [thing.2nd, ..left]
//       }

//     let right =
//       if new_right.2nd == list_at(right, 0) {
//         right
//       } else {
//         let thing = list_at(map_list, index + 2)
//         [thing.2nd, ..right]
//       }

//     do_get_proofs(
//       next_level,
//       new_item_index,
//       new_item,
//       left,
//       right,
//       remaining_side,
//       remaining_proofs,
//       left_final,
//       right_final,
//       remaining_side_final,
//       side_final,
//     )
//   } else {
//     todo
//   }
// }
// test merkle7() {
// let (index, bytes_list) = thing

// let map_list =
//   bytes_list
//     |> list.sort(bytearray.compare)
//     |> list.map(fn(x) { (builtin.bytearray_to_integer(True, x), x) })
//     |> list.unique

// let item = list_at(map_list, index)
// let left = list_at(map_list, index - 1)
// let left =
//   [left.2nd]
// let right = list_at(map_list, index + 1)
// let right =
//   [right.2nd]
// let (divisor, level_one) = sparse_merkelize_level(map_list)
//   True
// }
