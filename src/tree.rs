use crate::{
    error::{Error, Result},
    h256::H256,
    merge::{merge, MergeValue},
    merkle_proof::MerkleProof,
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
                    let parent_key_leaf = if (key.height + 1) / 8 == i / 8 {
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
    ) -> Result<(MergeValue, ChildKey)> {
        match intersection_branch {
            ChildKey::Leaf(x) => {
                let parent_key = x.parent_path_by_height(current_height);
                let parent_branch_key = BranchKey::new(current_height, parent_key);

                let x_value =
                    MergeValue::from_h256(self.store.get_leaf(&x)?.unwrap().to_h256::<H>());

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
                    (Some(a), Some(b)) => unreachable!("{a:#?} {b:#?}"),
                    (Some(left_height), None) => {
                        let new_child = self.recurse_tree(
                            current_node,
                            current_key,
                            parent_branch.left.1.clone(),
                            left_height,
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
                    }
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
        if !node.is_zero() {
            self.store.insert_leaf(key, value)?;
        } else {
            self.store.remove_leaf(&key)?;
        }

        // recompute the tree from top to bottom
        let x: Vec<_> = self
            .store()
            .branches_map()
            .iter()
            .filter(|x| x.0.height == 255)
            .collect();

        assert!(x.len() == 1);

        let last_intersection_key = ChildKey::Branch(x[0].0.clone());

        let (root_key, _) = self.recurse_tree(node, key, last_intersection_key, u8::MAX)?;

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
    pub fn merkle_proof(&self, mut keys: Vec<H256>) -> Result<MerkleProof> {
        if keys.is_empty() {
            return Err(Error::EmptyKeys);
        }

        // sort keys
        keys.sort_unstable();

        todo!();

        // Collect leaf bitmaps
        // let mut leaves_bitmap: Vec<H256> = Default::default();
        // for current_key in &keys {
        //     let mut current_key = *current_key;
        //     let mut bitmap = H256::zero();
        //     for height in 0..=u8::MAX {
        //         let parent_key = current_key.parent_path(height);
        //         let parent_branch_key = BranchKey::new(height, parent_key);
        //         if let Some(parent_branch) = self.store.get_branch(&parent_branch_key)? {
        //             let sibling = if current_key.is_right(height) {
        //                 parent_branch.left
        //             } else {
        //                 parent_branch.right
        //             };
        //             if !sibling.is_zero() {
        //                 bitmap.set_bit(height);
        //             }
        //         } else {
        //             // The key is not in the tree (support non-inclusion proof)
        //         }
        //         current_key = parent_key;
        //     }
        //     leaves_bitmap.push(bitmap);
        // }

        // let mut proof: Vec<(H256, Vec<Side>)> = Default::default();
        // let mut stack_fork_height = [0u8; MAX_STACK_SIZE]; // store fork height
        // let mut stack_top = 0;
        // let mut leaf_index = 0;
        // while leaf_index < keys.len() {
        //     let bitmap = leaves_bitmap[leaf_index];
        //     proof.push((bitmap, Vec::new()));
        //     let mut leaf_key = keys[leaf_index];
        //     let fork_height = u8::MAX;

        //     for height in 0..=fork_height {
        //         if height == fork_height && leaf_index + 1 < keys.len() {
        //             // If it's not final round, we don't need to merge to root (height=255)
        //             break;
        //         }
        //         let parent_key = leaf_key.parent_path(height);
        //         let is_right = leaf_key.is_right(height);

        //         // has non-zero sibling
        //         if leaves_bitmap[leaf_index].get_bit(height) {
        //             let parent_branch_key = BranchKey::new(height, parent_key);
        //             if let Some(parent_branch) = self.store.get_branch(&parent_branch_key)? {
        //                 let sibling = if is_right {
        //                     parent_branch.left
        //                 } else {
        //                     parent_branch.right
        //                 };
        //                 if !sibling.is_zero() {
        //                     proof
        //                         .last_mut()
        //                         .expect("proof is not empty")
        //                         .1
        //                         .push(if is_right {
        //                             Side::Left(sibling)
        //                         } else {
        //                             Side::Right(sibling)
        //                         });
        //                 }
        //             } else {
        //                 // The key is not in the tree (support non-inclusion proof)
        //             }
        //         }
        //         leaf_key = parent_key;
        //     }
        //     debug_assert!(stack_top < MAX_STACK_SIZE);
        //     stack_fork_height[stack_top] = fork_height;
        //     stack_top += 1;
        //     leaf_index += 1;
        // }

        // Ok(MerkleProof::new(leaves_bitmap, proof))
    }
}
