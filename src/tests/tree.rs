use hexlit::hex;
use itertools::Itertools;

use crate::{
    blake2b::Blake2bHasher,
    default_store::DefaultStore,
    h256::H256,
    merge::{merge, MergeValue},
    traits::{StoreReadOps, Value},
    tree::SparseMerkleTree,
};

#[allow(clippy::upper_case_acronyms)]
type SMT = SparseMerkleTree<Blake2bHasher, H256, DefaultStore<H256>>;

fn test_proof(mut tree: SMT, hex_key: [u8; 32]) {
    let (proofs, mut left_vec, continuing_side, mut right_vec, started_left_side, key) = tree
        .modify_root_proof(vec![hex_key.into()])
        .unwrap()
        .pop()
        .unwrap();

    if started_left_side {
        let mut left_hash = left_vec.remove(0);

        // Need to do a leaf hash
        left_hash = MergeValue::from_h256(left_hash.hash().to_h256::<Blake2bHasher>());

        for val in left_vec {
            left_hash = merge::<Blake2bHasher>(&val, &left_hash);
        }

        let mut right_hash = right_vec.remove(0);

        // Need to do a leaf hash
        right_hash = MergeValue::from_h256(right_hash.hash().to_h256::<Blake2bHasher>());
        for val in right_vec {
            right_hash = merge::<Blake2bHasher>(&right_hash, &val);
        }

        let mut with_item_hash = merge::<Blake2bHasher>(
            &left_hash,
            &MergeValue::from_h256(key.to_h256::<Blake2bHasher>()),
        );

        let mut without_item = left_hash;

        for val in continuing_side {
            with_item_hash = merge::<Blake2bHasher>(&val, &with_item_hash);
            without_item = merge::<Blake2bHasher>(&val, &without_item);
        }

        let mut combined_hash = merge::<Blake2bHasher>(&with_item_hash, &right_hash);
        let mut other_combined_hash = merge::<Blake2bHasher>(&without_item, &right_hash);

        for (i, val) in proofs.into_iter().enumerate() {
            println!("I IS {}", i);

            match val {
                crate::merkle_proof::Side::Left(x) => {
                    combined_hash = merge::<Blake2bHasher>(&x, &combined_hash);
                    other_combined_hash = merge::<Blake2bHasher>(&x, &other_combined_hash);
                }
                crate::merkle_proof::Side::Right(x) => {
                    combined_hash = merge::<Blake2bHasher>(&combined_hash, &x);
                    other_combined_hash = merge::<Blake2bHasher>(&other_combined_hash, &x);
                }
            }
        }

        assert_eq!(*tree.root(), combined_hash.hash());

        tree.update(key, key, false).unwrap();

        assert_eq!(*tree.root(), other_combined_hash.hash());
    } else {
        let mut right_hash = right_vec.remove(0);

        // Need to do a leaf hash
        right_hash = MergeValue::from_h256(right_hash.hash().to_h256::<Blake2bHasher>());

        for val in right_vec {
            right_hash = merge::<Blake2bHasher>(&right_hash, &val);
        }

        let mut left_hash = left_vec.remove(0);

        // Need to do a leaf hash
        left_hash = MergeValue::from_h256(left_hash.hash().to_h256::<Blake2bHasher>());
        for val in left_vec {
            left_hash = merge::<Blake2bHasher>(&val, &left_hash);
        }

        let mut with_item_hash = merge::<Blake2bHasher>(
            &MergeValue::from_h256(key.to_h256::<Blake2bHasher>()),
            &right_hash,
        );

        let mut without_item = right_hash;

        for val in continuing_side {
            with_item_hash = merge::<Blake2bHasher>(&with_item_hash, &val);
            without_item = merge::<Blake2bHasher>(&without_item, &val);
        }

        let mut combined_hash = merge::<Blake2bHasher>(&left_hash, &with_item_hash);
        let mut other_combined_hash = merge::<Blake2bHasher>(&left_hash, &without_item);

        for (i, val) in proofs.into_iter().enumerate() {
            println!("I IS {}", i);

            match val {
                crate::merkle_proof::Side::Left(x) => {
                    combined_hash = merge::<Blake2bHasher>(&x, &combined_hash);
                    other_combined_hash = merge::<Blake2bHasher>(&x, &other_combined_hash);
                }
                crate::merkle_proof::Side::Right(x) => {
                    combined_hash = merge::<Blake2bHasher>(&combined_hash, &x);
                    other_combined_hash = merge::<Blake2bHasher>(&other_combined_hash, &x);
                }
            }
        }

        assert_eq!(*tree.root(), combined_hash.hash());

        tree.update(key, key, false).unwrap();

        assert_eq!(*tree.root(), other_combined_hash.hash());
    }
}

#[test]
fn my_test() {
    let mut bytes_list: [[u8; 32]; 32] = [
        hex!("037989aac4a85a30998d29e5041f8c6cf398d370f08b48ce258cdc376e5b8c8c"),
        hex!("0379899ac4a85a30891d29e5041f8c6cf398d370f08b48ce258cdc376e5b8c8c"),
        hex!("2483b790b459b5134f357e5afed5149073b21bb6808650f1da5c821bef9fb25a"),
        hex!("56b3f804e7e380264dd9d26b8f5af2fc5624b9c7c4751c16d288a28ee9d2e401"),
        hex!("a802bfafdc95b4f98196ada7d4d99ca22c2e3ca4f2a5b9704ad48ba0bacf6313"),
        hex!("1f90c49b9ff263fceb6bb86286a771697f99b7b8282270876c5b6aa04c28fa18"),
        hex!("3c4cc28da90f5a784cdbdd3c1c154cdd5a7b44b31882a5bb1ee7f3e9a14a77d8"),
        hex!("541431358d0e7b58145337cb491cd98d425e7fd77bbd81679a28ab5689a4ac5e"),
        hex!("dcf93f6a91de8ff87f4e17ec954a79ab3ebf330b87d9e3457b6f0eef1230abe4"),
        hex!("1e6b2d4e73031f97dc43ca3319e07c0f49bc1e493d56814537c6125c43359c7d"),
        hex!("9581c5e21a94584538e1212bb666df18bd353eb1c03c20bd473fa6f3fc21162c"),
        hex!("30a6de707aa2bc2fa0d302b6a321c63291f147a3c6c2f3172fbf484ce42761d5"),
        hex!("29847997b0d57a12b7fd2ac72618bba69cf28293a03d88c3bd0ee9ee1fee110d"),
        hex!("77bbf46b3cc8f5621d170b201bb2a7e3a4508e53b2ae17cf1d1b9add18314cc3"),
        hex!("83d32921e47c9a88db3ac56a1e6b8552c9732911a977927bd2e58b3add48683c"),
        hex!("064d2e79dc1f93fbdf8ebad4f95676c10ffc1696131731badf30b38f4f60b66d"),
        hex!("04cfeeb613c20b73496ea0402a31ba05733d7cea285676c5f540e98b5ff39930"),
        hex!("2413b790b449b5134f357e5afed5149073b21bb6808650f1da5c821bef9fb25a"),
        hex!("56b3f804e7d380264dd9d26b8f5af2fc5624b9c7c4751c16d288a28ee9d2e401"),
        hex!("a801bfafdc95b4f98196ada7d4d99ca22c2e3ca4f2a5b9704ad48ba0bacf6313"),
        hex!("1f90b49b9ff263fceb6bb86286a771697f99b7b8282270876c5b6aa04c28fa18"),
        hex!("3c4cb28da90f5a784cdbdd3c1c154cdd5a7b44b31882a5bb1ee7f3e9a14a77d8"),
        hex!("541431258d0e7b58145337cb491cd98d425e7fd77bbd81679a28ab5689a4ac5e"),
        hex!("dcf93f6a91df8ff87f4e17ec954a79ab3ebf330b87d9e3457b6f0eef1230abe4"),
        hex!("1e6b2d4e73051f97dc43ca3319e07c0f49bc1e493d56814537c6125c43359c7d"),
        hex!("9581c5e21a94884538e1212bb666df18bd353eb1c03c20bd473fa6f3fc21162c"),
        hex!("30a6de707aa2ac2fa0d302b6a321c63291f147a3c6c2f3172fbf484ce42761d5"),
        hex!("29847997b0d56a12b7fd2ac72618bba69cf28293a03d88c3bd0ee9ee1fee110d"),
        hex!("77bbf46b3cc8f5620d170b201bb2a7e3a4508e53b2ae17cf1d1b9add18314cc3"),
        hex!("83d32921e87c9a88db3ac56a1e6b8552c9732911a977927bd2e58b3add48683c"),
        hex!("064d2e79dc1f95fbdf8ebad4f95676c10ffc1696131731badf30b38f4f60b66d"),
        hex!("05cfeeb613c20b73496ea0402a36ba05733d7cea285676c5f540e98b5ff39930"),
    ];

    bytes_list.sort_unstable();

    let mut tree = SMT::default();
    for bytea in &bytes_list {
        let key: H256 = { (*bytea).into() };

        let value: H256 = { (*bytea).into() };
        tree.update(key, value, true).expect("update");
    }

    assert_eq!(
        *tree.root(),
        H256::from(hex!(
            "758DA3290AA238EB24AD1B1C672CC8C04EC04D288842E0A1D7CD01536AA2CBE7"
        ))
    );

    test_proof(
        tree,
        hex!("037989aac4a85a30998d29e5041f8c6cf398d370f08b48ce258cdc376e5b8c8c"),
    );
}

#[test]
fn fortuna_root_test() {
    #[derive(serde::Deserialize)]
    struct BlockData {
        current_hash: String,
    }

    let contents = std::fs::read("blocks.json").expect("Unable to read file");

    let blocks: Vec<BlockData> = serde_json::from_slice(&contents).expect("Unable to parse JSON");

    let hashes = blocks
        .into_iter()
        .map(|x| x.current_hash)
        .collect::<Vec<_>>();

    let mut tree = SMT::default();

    for hash in &hashes {
        let hash_bytes = hex::decode(hash).expect("Unable to decode hash");
        let first_25 = &hash_bytes[0..25];
        let last_7 = &hash_bytes[25..32];

        let key: [u8; 32] = last_7
            .iter()
            .chain(first_25.iter())
            .copied()
            .collect_vec()
            .try_into()
            .unwrap();
        let value = key;

        let key: H256 = { key.into() };
        let value: H256 = { value.into() };
        tree.update(key, value, true).expect("update");
    }

    test_proof(
        tree,
        hex!("c11ba1980eae54000000000000420dc24ab8c31f2c6ca2a791af8eaeb855a52b"),
    );
}

#[test]
fn test_contiguous() {
    let bytes_list: [[u8; 32]; 4] = [
        hex!("0000000000000000000000000000000000000000000000000000000000000001"),
        hex!("0000000000000000000000000000000000000000000000000000000000000002"),
        hex!("0000000000000000000000000000000000000000000000000000000000000003"),
        hex!("0000000000000000000000000000000000000000000000000000000000000004"),
    ];

    let mut tree = SMT::default();
    for bytea in &bytes_list {
        let key: H256 = { (*bytea).into() };

        let value: H256 = { (*bytea).into() };
        tree.update(key, value, true).expect("update");
    }

    assert_eq!(
        *tree.root(),
        H256::from(hex!(
            "d29a1db072a0b7f3320854eae1c4d99914a9679579f76486d9c48be352a56181"
        ))
    );

    test_proof(
        tree,
        hex!("0000000000000000000000000000000000000000000000000000000000000003"),
    );
}
