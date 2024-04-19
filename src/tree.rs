use crate::{
    error::{Error, Result},
    h256::H256,
    merge::{merge, MergeValue},
    merkle_proof::Side,
    traits::{Hasher, StoreReadOps, StoreWriteOps, Value},
};
use core::cmp::Ordering;
use core::marker::PhantomData;
use std::fmt::Debug;
/// The branch key
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct BranchKey {
    pub height: u8,
    pub node_key: H256,
}

impl BranchKey {
    pub fn new(height: u8, node_key: H256) -> BranchKey {
        BranchKey { height, node_key }
    }
}

impl PartialOrd for BranchKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for BranchKey {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.height.cmp(&other.height) {
            Ordering::Equal => self.node_key.cmp(&other.node_key),
            ordering => ordering,
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum ChildKey {
    Leaf(H256),
    Branch(BranchKey),
}

impl ChildKey {
    fn get_intersecting_height(&self, other_key: H256, max_height: u8) -> Option<u8> {
        match self {
            ChildKey::Leaf(key) => {
                for i in 0..max_height {
                    let parent_key_leaf = key.parent_path_by_height(i);

                    let other_parent_key = other_key.parent_path_by_height(i);

                    if parent_key_leaf == other_parent_key {
                        return Some(i);
                    }
                }
                None
            }
            ChildKey::Branch(key) => {
                for i in 1..max_height {
                    let parent_key_leaf = if key.height > i {
                        continue;
                    } else if (key.height + 1) / 8 == (i + 1) / 8 {
                        key.node_key
                            .parent_path_by_height(i - ((key.height + 1) % 8))
                    } else {
                        key.node_key.parent_path_by_height(i)
                    };

                    let other_parent_key = other_key.parent_path_by_height(i);

                    if parent_key_leaf == other_parent_key {
                        return Some(i);
                    }
                }
                None
            }
        }
    }
}

/// A branch in the SMT
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct BranchNode {
    pub left: (MergeValue, ChildKey),
    pub right: (MergeValue, ChildKey),
}

impl BranchNode {
    fn new(left: (MergeValue, ChildKey), right: (MergeValue, ChildKey)) -> Self {
        BranchNode { left, right }
    }
}

/// Sparse merkle tree
#[derive(Debug)]
pub struct SparseMerkleTree<H, V, S> {
    store: S,
    root: H256,
    phantom: PhantomData<(H, V)>,
}

impl<H: Hasher + Default, V: Value + Debug, S: StoreReadOps<V> + StoreWriteOps<V> + Default> Default
    for SparseMerkleTree<H, V, S>
{
    fn default() -> Self {
        let mut store = S::default();
        store.insert_leaf(H256::zero(), V::zero()).unwrap();
        store.insert_leaf(H256::max(), V::max()).unwrap();
        store
            .insert_branch(
                BranchKey::new(u8::MAX, H256::zero()),
                BranchNode::new(
                    (
                        MergeValue::from_h256(V::zero().to_h256::<H>()),
                        ChildKey::Leaf(H256::zero()),
                    ),
                    (
                        MergeValue::from_h256(V::max().to_h256::<H>()),
                        ChildKey::Leaf(H256::max()),
                    ),
                ),
            )
            .unwrap();
        let root_branch_key = BranchKey::new(u8::MAX, H256::zero());
        store
            .get_branch(&root_branch_key)
            .map(|branch_node| {
                branch_node
                    .map(|n| merge::<H>(&n.left.0, &n.right.0).hash())
                    .unwrap_or_default()
            })
            .map(|root| SparseMerkleTree::new(root, store))
            .unwrap()
    }
}

impl<H, V, S> SparseMerkleTree<H, V, S> {
    /// Build a merkle tree from root and store
    pub fn new(root: H256, store: S) -> SparseMerkleTree<H, V, S> {
        SparseMerkleTree {
            root,
            store,
            phantom: PhantomData,
        }
    }

    /// Merkle root
    pub fn root(&self) -> &H256 {
        &self.root
    }

    /// Check empty of the tree
    pub fn is_empty(&self) -> bool {
        self.root.is_zero()
    }

    /// Destroy current tree and retake store
    pub fn take_store(self) -> S {
        self.store
    }

    /// Get backend store
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Get mutable backend store
    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }
}

impl<H: Hasher + Default, V, S: StoreReadOps<V>> SparseMerkleTree<H, V, S> {
    /// Build a merkle tree from store, the root will be calculated automatically
    pub fn new_with_store(store: S) -> Result<SparseMerkleTree<H, V, S>> {
        let root_branch_key = BranchKey::new(u8::MAX, H256::zero());
        store
            .get_branch(&root_branch_key)
            .map(|branch_node| {
                branch_node
                    .map(|n| merge::<H>(&n.left.0, &n.right.0).hash())
                    .unwrap_or_default()
            })
            .map(|root| SparseMerkleTree::new(root, store))
    }
}

impl<H: Hasher + Default, V: Value + Debug, S: StoreReadOps<V> + StoreWriteOps<V>>
    SparseMerkleTree<H, V, S>
{
    fn recurse_tree(
        &mut self,
        current_node: MergeValue,
        current_key: H256,
        intersection_branch: ChildKey,
        current_height: u8,
        insertion: bool,
    ) -> Result<(MergeValue, ChildKey)> {
        match intersection_branch {
            ChildKey::Leaf(x) => {
                let parent_key = x.parent_path_by_height(current_height);
                let parent_branch_key = BranchKey::new(current_height, parent_key);

                let x_value =
                    MergeValue::from_h256(self.store.get_leaf(&x)?.unwrap().to_h256::<H>());

                if insertion {
                    if x.le(&current_key) {
                        let merge_value = merge::<H>(&x_value, &current_node);
                        self.store.insert_branch(
                            parent_branch_key.clone(),
                            BranchNode {
                                left: (x_value, intersection_branch.clone()),
                                right: (current_node, ChildKey::Leaf(current_key)),
                            },
                        )?;

                        Ok((merge_value, ChildKey::Branch(parent_branch_key)))
                    } else {
                        let merge_value = merge::<H>(&current_node, &x_value);
                        self.store.insert_branch(
                            parent_branch_key.clone(),
                            BranchNode {
                                left: (current_node, ChildKey::Leaf(current_key)),
                                right: (x_value, intersection_branch.clone()),
                            },
                        )?;

                        Ok((merge_value, ChildKey::Branch(parent_branch_key)))
                    }
                } else {
                    self.store.remove_branch(&parent_branch_key)?;
                    Ok((x_value, ChildKey::Leaf(x)))
                }
            }
            ChildKey::Branch(key) => {
                let parent_branch = self.store.get_branch(&key)?.unwrap();

                let left_inter_height = parent_branch
                    .left
                    .1
                    .get_intersecting_height(current_key, current_height);

                let right_inter_height = parent_branch
                    .right
                    .1
                    .get_intersecting_height(current_key, current_height);

                match (left_inter_height, right_inter_height) {
                    (Some(left_height), None) => {
                        let new_child = self.recurse_tree(
                            current_node,
                            current_key,
                            parent_branch.left.1.clone(),
                            left_height,
                            insertion,
                        )?;

                        let merge_value = merge::<H>(&new_child.0, &parent_branch.right.0);

                        self.store.insert_branch(
                            key.clone(),
                            BranchNode {
                                left: new_child,
                                right: parent_branch.right,
                            },
                        )?;

                        Ok((merge_value, ChildKey::Branch(key)))
                    }
                    (None, Some(right_height)) => {
                        let new_child = self.recurse_tree(
                            current_node,
                            current_key,
                            parent_branch.right.1.clone(),
                            right_height,
                            insertion,
                        )?;

                        let merge_value = merge::<H>(&parent_branch.left.0, &new_child.0);

                        self.store.insert_branch(
                            key.clone(),
                            BranchNode {
                                left: parent_branch.left,
                                right: new_child,
                            },
                        )?;

                        Ok((merge_value, ChildKey::Branch(key)))
                    }
                    (None, None) => {
                        let parent_key = current_key.parent_path_by_height(current_height);
                        let parent_branch_key = BranchKey::new(current_height, parent_key);
                        let sub_key = current_key.parent_path_by_height(current_height - 1);

                        let parent_merged_value =
                            merge::<H>(&parent_branch.left.0, &parent_branch.right.0);

                        if insertion {
                            if sub_key.is_right(current_height) {
                                let merge_value = merge::<H>(&parent_merged_value, &current_node);
                                self.store.insert_branch(
                                    parent_branch_key.clone(),
                                    BranchNode {
                                        left: (parent_merged_value, ChildKey::Branch(key.clone())),
                                        right: (current_node, ChildKey::Leaf(current_key)),
                                    },
                                )?;
                                Ok((merge_value, ChildKey::Branch(parent_branch_key)))
                            } else {
                                let merge_value = merge::<H>(&current_node, &parent_merged_value);
                                self.store.insert_branch(
                                    parent_branch_key.clone(),
                                    BranchNode {
                                        left: (current_node, ChildKey::Leaf(current_key)),
                                        right: (parent_merged_value, ChildKey::Branch(key.clone())),
                                    },
                                )?;
                                Ok((merge_value, ChildKey::Branch(parent_branch_key)))
                            }
                        } else {
                            self.store.remove_branch(&parent_branch_key)?;
                            Ok((parent_merged_value, ChildKey::Branch(key)))
                        }
                    }
                    (Some(a), Some(b)) => unreachable!("{a:#?} {b:#?}"),
                }
            }
        }
    }

    /// Update a leaf, return new merkle root
    /// set to zero value to delete a key
    pub fn update(&mut self, key: H256, value: V) -> Result<&H256> {
        // compute and store new leaf

        let node = MergeValue::from_h256(value.to_h256::<H>());

        // notice when value is zero the leaf is deleted, so we do not need to store it
        let insertion = if !node.is_zero() {
            self.store.insert_leaf(key, value)?;
            true
        } else {
            self.store.remove_leaf(&key)?;
            false
        };

        // recompute the tree from top to bottom
        let x: Vec<_> = self
            .store()
            .branches_map()
            .iter()
            .filter(|x| x.0.height == 255)
            .collect();

        assert!(x.len() == 1);

        let last_intersection_key = ChildKey::Branch(x[0].0.clone());

        let (root_key, _) =
            self.recurse_tree(node, key, last_intersection_key, u8::MAX, insertion)?;

        self.root = root_key.hash();
        Ok(&self.root)
    }
}

impl<H: Hasher + Default, V: Value, S: StoreReadOps<V>> SparseMerkleTree<H, V, S> {
    /// Get value of a leaf
    /// return zero value if leaf not exists
    pub fn get(&self, key: &H256) -> Result<V> {
        if self.is_empty() {
            return Ok(V::zero());
        }
        Ok(self.store.get_leaf(key)?.unwrap_or_else(V::zero))
    }

    /// Generate merkle proof
    #[allow(clippy::type_complexity)]
    pub fn modify_root_proof(
        &self,
        mut keys: Vec<H256>,
    ) -> Result<
        Vec<(
            Vec<Side>,
            Vec<MergeValue>,
            Vec<MergeValue>,
            Vec<MergeValue>,
            bool,
            H256,
        )>,
    > {
        if keys.is_empty() {
            return Err(Error::EmptyKeys);
        }

        // sort keys
        keys.sort_unstable();

        let mut final_vec = vec![];

        for key in keys {
            // recompute the tree from top to bottom
            let x: Vec<_> = self
                .store()
                .branches_map()
                .iter()
                .filter(|x| x.0.height == 255)
                .collect();

            assert!(x.len() == 1);

            let mut branch_key = x[0].0.clone();
            let mut proof = Vec::new();

            loop {
                let branch = self.store.get_branch(&branch_key)?.unwrap();

                let left_inter_height = branch
                    .left
                    .1
                    .get_intersecting_height(key, branch_key.height);

                let right_inter_height = branch
                    .right
                    .1
                    .get_intersecting_height(key, branch_key.height);

                match (left_inter_height, right_inter_height) {
                    (None, Some(_)) => {
                        proof.push((branch.left.1, Side::Left(branch.left.0)));
                        match branch.right.1 {
                            ChildKey::Leaf(x) => {
                                assert!(x == key);
                                break;
                            }
                            ChildKey::Branch(x) => {
                                branch_key = x;
                            }
                        }
                    }
                    (Some(_), None) => {
                        proof.push((branch.right.1, Side::Right(branch.right.0)));
                        match branch.left.1 {
                            ChildKey::Leaf(x) => {
                                assert!(x == key);
                                break;
                            }
                            ChildKey::Branch(x) => {
                                branch_key = x;
                            }
                        }
                    }
                    (Some(x), Some(y)) => unreachable!("{x:#?} {y:#?} impossible"),
                    (None, None) => unreachable!("also impossible"),
                }
            }

            let mut starting_side = proof.pop().unwrap();
            let started_left_side = matches!(starting_side.1, Side::Left(_));

            let mut left_vec = vec![];
            let mut right_vec = vec![];
            let mut continuing_side: Vec<MergeValue> = vec![];

            loop {
                match &starting_side.0 {
                    ChildKey::Leaf(x) => {
                        match starting_side.1 {
                            Side::Left(_) => {
                                left_vec.push(MergeValue::from_h256(*x));
                            }
                            Side::Right(_) => {
                                right_vec.push(MergeValue::from_h256(*x));
                            }
                        }
                        break;
                    }
                    ChildKey::Branch(bkey) => {
                        let next_child = self.store().get_branch(bkey)?.unwrap();
                        match &starting_side.1 {
                            Side::Left(_) => {
                                left_vec.push(next_child.left.0);
                                starting_side =
                                    (next_child.right.1, Side::Left(next_child.right.0));
                            }
                            Side::Right(_) => {
                                right_vec.push(next_child.right.0);
                                starting_side = (next_child.left.1, Side::Right(next_child.left.0));
                            }
                        }
                    }
                }
            }

            while let Some(thing) = proof.pop() {
                if (starting_side.1).is_same_side(&thing.1) {
                    continuing_side.push(thing.1.merge_value());
                } else {
                    proof.push(thing);
                    break;
                }
            }

            let mut other_side = proof.pop().unwrap();

            loop {
                match &other_side.0 {
                    ChildKey::Leaf(x) => {
                        match other_side.1 {
                            Side::Left(_) => {
                                left_vec.push(MergeValue::from_h256(*x));
                            }
                            Side::Right(_) => {
                                right_vec.push(MergeValue::from_h256(*x));
                            }
                        }
                        break;
                    }
                    ChildKey::Branch(bkey) => {
                        let next_child = self.store().get_branch(bkey)?.unwrap();
                        match &other_side.1 {
                            Side::Left(_) => {
                                left_vec.push(next_child.left.0);
                                other_side = (next_child.right.1, Side::Left(next_child.right.0));
                            }
                            Side::Right(_) => {
                                right_vec.push(next_child.right.0);
                                other_side = (next_child.left.1, Side::Right(next_child.left.0));
                            }
                        }
                    }
                }
            }

            left_vec.reverse();
            right_vec.reverse();

            final_vec.push((
                proof.iter().map(|x| x.1.clone()).rev().collect::<Vec<_>>(),
                left_vec,
                continuing_side,
                right_vec,
                started_left_side,
                key,
            ))
        }

        Ok(final_vec)
    }

    /// Generate merkle proof
    #[allow(clippy::type_complexity)]
    pub fn member_proof(&self, mut keys: Vec<H256>) -> Result<Vec<(Vec<Side>, H256)>> {
        if keys.is_empty() {
            return Err(Error::EmptyKeys);
        }

        // sort keys
        keys.sort_unstable();

        let mut final_vec = vec![];

        for key in keys {
            // recompute the tree from top to bottom
            let x: Vec<_> = self
                .store()
                .branches_map()
                .iter()
                .filter(|x| x.0.height == 255)
                .collect();

            assert!(x.len() == 1);

            let mut branch_key = x[0].0.clone();
            let mut proof = Vec::new();

            loop {
                let branch = self.store.get_branch(&branch_key)?.unwrap();

                let left_inter_height = branch
                    .left
                    .1
                    .get_intersecting_height(key, branch_key.height);

                let right_inter_height = branch
                    .right
                    .1
                    .get_intersecting_height(key, branch_key.height);

                match (left_inter_height, right_inter_height) {
                    (None, Some(_)) => {
                        proof.push((branch.left.1, Side::Left(branch.left.0)));
                        match branch.right.1 {
                            ChildKey::Leaf(x) => {
                                assert!(x == key);
                                break;
                            }
                            ChildKey::Branch(x) => {
                                branch_key = x;
                            }
                        }
                    }
                    (Some(_), None) => {
                        proof.push((branch.right.1, Side::Right(branch.right.0)));
                        match branch.left.1 {
                            ChildKey::Leaf(x) => {
                                assert!(x == key);
                                break;
                            }
                            ChildKey::Branch(x) => {
                                branch_key = x;
                            }
                        }
                    }
                    (Some(x), Some(y)) => unreachable!("{x:#?} {y:#?} impossible"),
                    (None, None) => unreachable!("also impossible"),
                }
            }

            final_vec.push((
                proof.iter().map(|x| x.1.clone()).rev().collect::<Vec<_>>(),
                key,
            ))
        }

        Ok(final_vec)
    }
}
