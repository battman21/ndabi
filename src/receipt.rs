use std::fmt;
use std::mem::size_of;

use sha2::{Digest, Sha256};

pub const HASH_BYTES: usize = 32;
const MAX_CHANGED_ITEMS: usize = 16;
const MAX_STAGED_NODES: usize = 256;
const MAX_RECEIPT_NODES: usize = 2_048;
const STAGED_POSITION_ABSENT: u16 = u16::MAX;
const EMPTY_HASH: [u8; HASH_BYTES] = [0; HASH_BYTES];

pub type ReceiptHash = [u8; HASH_BYTES];

pub trait ReceiptItem {
    fn receipt_id(&self) -> u32;
    fn receipt_status(&self) -> u8;
    fn receipt_priority(&self) -> u8;
    fn receipt_title(&self) -> &str;
}

pub trait ReceiptUpdate {
    fn receipt_id(&self) -> u32;
    fn receipt_status(&self) -> u8;
    fn receipt_priority(&self) -> u8;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub revision: u64,
    pub semantic_root: ReceiptHash,
    pub view_root: ReceiptHash,
}

#[derive(Clone)]
pub struct ReceiptTree {
    semantic_nodes: Vec<ReceiptHash>,
    view_nodes: Vec<ReceiptHash>,
    leaf_base: usize,
    item_count: usize,
    revision: u64,
}

#[derive(Clone, Copy)]
struct StagedNode {
    index: usize,
    semantic: ReceiptHash,
    view: ReceiptHash,
}

const EMPTY_STAGED_NODE: StagedNode = StagedNode {
    index: usize::MAX,
    semantic: EMPTY_HASH,
    view: EMPTY_HASH,
};

pub struct ReceiptPlan {
    staged: [StagedNode; MAX_STAGED_NODES],
    staged_positions: [u16; MAX_RECEIPT_NODES],
    staged_len: usize,
    base_revision: u64,
    base_semantic_root: ReceiptHash,
    base_view_root: ReceiptHash,
    receipt: Receipt,
}

impl ReceiptTree {
    pub fn new<T: ReceiptItem>(revision: u64, items: &[T]) -> Result<Self, String> {
        if items.is_empty() {
            return Err("receipt tree needs at least one item".to_string());
        }
        let leaf_base = items.len().next_power_of_two();
        if leaf_base * 2 > MAX_RECEIPT_NODES {
            return Err("receipt tree exceeds the fixed node limit".to_string());
        }
        let mut tree = Self {
            semantic_nodes: vec![EMPTY_HASH; leaf_base * 2],
            view_nodes: vec![EMPTY_HASH; leaf_base * 2],
            leaf_base,
            item_count: items.len(),
            revision,
        };
        tree.rebuild(revision, items)?;
        Ok(tree)
    }

    pub fn rebuild<T: ReceiptItem>(
        &mut self,
        revision: u64,
        items: &[T],
    ) -> Result<Receipt, String> {
        if items.len() != self.item_count {
            return Err("receipt rebuild item count changed".to_string());
        }
        for (index, item) in items.iter().enumerate() {
            let expected_id = u32::try_from(index + 1)
                .map_err(|_| "receipt item identifier overflow".to_string())?;
            if item.receipt_id() != expected_id {
                return Err("receipt items are not in identifier order".to_string());
            }
            let node_index = self.leaf_base + index;
            self.semantic_nodes[node_index] = semantic_leaf(
                item.receipt_id(),
                item.receipt_status(),
                item.receipt_priority(),
                item.receipt_title(),
            );
            self.view_nodes[node_index] = view_leaf(
                item.receipt_id(),
                item.receipt_status(),
                item.receipt_priority(),
                item.receipt_title(),
            );
        }
        for index in self.item_count..self.leaf_base {
            let node_index = self.leaf_base + index;
            self.semantic_nodes[node_index] = empty_leaf(b"semantic-empty", index);
            self.view_nodes[node_index] = empty_leaf(b"view-empty", index);
        }
        for index in (1..self.leaf_base).rev() {
            self.semantic_nodes[index] = parent_hash(
                b"semantic-parent",
                &self.semantic_nodes[index * 2],
                &self.semantic_nodes[index * 2 + 1],
            );
            self.view_nodes[index] = parent_hash(
                b"view-parent",
                &self.view_nodes[index * 2],
                &self.view_nodes[index * 2 + 1],
            );
        }
        self.revision = revision;
        Ok(self.receipt())
    }

    pub fn receipt(&self) -> Receipt {
        receipt_from_roots(
            self.revision,
            self.item_count,
            &self.semantic_nodes[1],
            &self.view_nodes[1],
        )
    }

    pub fn plan<T: ReceiptItem, U: ReceiptUpdate>(
        &self,
        items: &[T],
        updates: &[U],
        next_revision: u64,
    ) -> Result<ReceiptPlan, String> {
        if items.len() != self.item_count {
            return Err("receipt plan item count changed".to_string());
        }
        if updates.len() > MAX_CHANGED_ITEMS {
            return Err("receipt plan exceeds the fixed update limit".to_string());
        }
        if next_revision != self.revision + 1 {
            return Err("receipt plan revision does not advance once".to_string());
        }

        let mut plan = ReceiptPlan {
            staged: [EMPTY_STAGED_NODE; MAX_STAGED_NODES],
            staged_positions: [STAGED_POSITION_ABSENT; MAX_RECEIPT_NODES],
            staged_len: 0,
            base_revision: self.revision,
            base_semantic_root: self.semantic_nodes[1],
            base_view_root: self.view_nodes[1],
            receipt: self.receipt(),
        };
        let mut current = [usize::MAX; MAX_CHANGED_ITEMS];
        let mut current_len = 0;
        for update in updates {
            let item_index = usize::try_from(update.receipt_id().saturating_sub(1))
                .map_err(|_| "receipt update identifier overflow".to_string())?;
            let item = items
                .get(item_index)
                .ok_or_else(|| "receipt update names an unknown item".to_string())?;
            if item.receipt_id() != update.receipt_id() {
                return Err("receipt update identifier does not match state".to_string());
            }
            let node_index = self.leaf_base + item_index;
            plan.insert(StagedNode {
                index: node_index,
                semantic: semantic_leaf(
                    item.receipt_id(),
                    update.receipt_status(),
                    update.receipt_priority(),
                    item.receipt_title(),
                ),
                view: view_leaf(
                    item.receipt_id(),
                    update.receipt_status(),
                    update.receipt_priority(),
                    item.receipt_title(),
                ),
            })?;
            insert_unique(&mut current, &mut current_len, node_index)?;
        }

        while current_len != 0 && current[0] > 1 {
            let mut parents = [usize::MAX; MAX_CHANGED_ITEMS];
            let mut parent_len = 0;
            for index in current.iter().take(current_len) {
                insert_unique(&mut parents, &mut parent_len, index / 2)?;
            }
            for parent in parents.iter().take(parent_len).copied() {
                let left = parent * 2;
                let right = left + 1;
                plan.insert(StagedNode {
                    index: parent,
                    semantic: parent_hash(
                        b"semantic-parent",
                        &plan.semantic(self, left),
                        &plan.semantic(self, right),
                    ),
                    view: parent_hash(
                        b"view-parent",
                        &plan.view(self, left),
                        &plan.view(self, right),
                    ),
                })?;
            }
            current = parents;
            current_len = parent_len;
        }

        let semantic_root = plan.semantic(self, 1);
        let view_root = plan.view(self, 1);
        plan.receipt =
            receipt_from_roots(next_revision, self.item_count, &semantic_root, &view_root);
        Ok(plan)
    }

    pub fn commit(&mut self, plan: &ReceiptPlan) -> Result<(), String> {
        if plan.base_revision != self.revision
            || plan.base_semantic_root != self.semantic_nodes[1]
            || plan.base_view_root != self.view_nodes[1]
        {
            return Err("receipt plan does not match the current tree".to_string());
        }
        if plan.receipt.revision != self.revision + 1 {
            return Err("receipt commit revision does not advance once".to_string());
        }
        for staged in plan.staged.iter().take(plan.staged_len) {
            self.semantic_nodes[staged.index] = staged.semantic;
            self.view_nodes[staged.index] = staged.view;
        }
        self.revision = plan.receipt.revision;
        Ok(())
    }

    pub fn retained_bytes(&self) -> usize {
        size_of::<Self>()
            + self.semantic_nodes.capacity() * size_of::<ReceiptHash>()
            + self.view_nodes.capacity() * size_of::<ReceiptHash>()
    }
}

impl ReceiptPlan {
    pub fn receipt(&self) -> Receipt {
        self.receipt
    }

    fn insert(&mut self, node: StagedNode) -> Result<(), String> {
        let position = *self
            .staged_positions
            .get(node.index)
            .ok_or_else(|| "receipt node exceeds the direct lookup limit".to_string())?;
        if position != STAGED_POSITION_ABSENT {
            self.staged[usize::from(position)] = node;
            return Ok(());
        }
        if self.staged_len == self.staged.len() {
            return Err("receipt plan exceeds the fixed node limit".to_string());
        }
        self.staged[self.staged_len] = node;
        self.staged_positions[node.index] = u16::try_from(self.staged_len)
            .map_err(|_| "receipt staged position overflow".to_string())?;
        self.staged_len += 1;
        Ok(())
    }

    fn semantic(&self, tree: &ReceiptTree, index: usize) -> ReceiptHash {
        let position = self.staged_positions[index];
        if position == STAGED_POSITION_ABSENT {
            tree.semantic_nodes[index]
        } else {
            self.staged[usize::from(position)].semantic
        }
    }

    fn view(&self, tree: &ReceiptTree, index: usize) -> ReceiptHash {
        let position = self.staged_positions[index];
        if position == STAGED_POSITION_ABSENT {
            tree.view_nodes[index]
        } else {
            self.staged[usize::from(position)].view
        }
    }
}

pub fn hash_hex(hash: &ReceiptHash) -> String {
    let mut output = String::with_capacity(HASH_BYTES * 2);
    for byte in hash {
        use std::fmt::Write;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

pub fn parse_hash(value: &str) -> Result<ReceiptHash, String> {
    if value.len() != HASH_BYTES * 2 {
        return Err("receipt hash has the wrong length".to_string());
    }
    let mut output = EMPTY_HASH;
    for (index, destination) in output.iter_mut().enumerate() {
        let start = index * 2;
        *destination =
            u8::from_str_radix(&value[start..start + 2], 16).map_err(|error| error.to_string())?;
    }
    Ok(output)
}

pub fn hash_fingerprint(hash: &ReceiptHash) -> u64 {
    u64::from_le_bytes(hash[..8].try_into().unwrap_or([0; 8]))
}

fn insert_unique(
    values: &mut [usize; MAX_CHANGED_ITEMS],
    len: &mut usize,
    value: usize,
) -> Result<(), String> {
    if values.iter().take(*len).any(|existing| *existing == value) {
        return Ok(());
    }
    if *len == values.len() {
        return Err("receipt parent set exceeds the fixed limit".to_string());
    }
    values[*len] = value;
    *len += 1;
    Ok(())
}

fn semantic_leaf(id: u32, status: u8, priority: u8, title: &str) -> ReceiptHash {
    let mut hasher = domain_hasher(b"semantic-leaf");
    hasher.update(id.to_le_bytes());
    hasher.update([status, priority]);
    hasher.update((title.len() as u64).to_le_bytes());
    hasher.update(title.as_bytes());
    finish(hasher)
}

fn view_leaf(id: u32, status: u8, priority: u8, title: &str) -> ReceiptHash {
    let mut hasher = domain_hasher(b"view-leaf");
    {
        let mut writer = HashWriter(&mut hasher);
        let _ = fmt::write(
            &mut writer,
            format_args!(
                "  <article data-task=\"{id}\"><h2>{title}</h2><p>Status {status}. Priority {priority}.</p></article>\n"
            ),
        );
    }
    finish(hasher)
}

fn empty_leaf(domain: &[u8], index: usize) -> ReceiptHash {
    let mut hasher = domain_hasher(domain);
    hasher.update((index as u64).to_le_bytes());
    finish(hasher)
}

fn parent_hash(domain: &[u8], left: &ReceiptHash, right: &ReceiptHash) -> ReceiptHash {
    let mut hasher = domain_hasher(domain);
    hasher.update(left);
    hasher.update(right);
    finish(hasher)
}

fn receipt_from_roots(
    revision: u64,
    item_count: usize,
    semantic_tree_root: &ReceiptHash,
    view_tree_root: &ReceiptHash,
) -> Receipt {
    Receipt {
        revision,
        semantic_root: complete_root(b"semantic-root", revision, item_count, semantic_tree_root),
        view_root: complete_root(b"view-root", revision, item_count, view_tree_root),
    }
}

fn complete_root(
    domain: &[u8],
    revision: u64,
    item_count: usize,
    tree_root: &ReceiptHash,
) -> ReceiptHash {
    let mut hasher = domain_hasher(domain);
    hasher.update(revision.to_le_bytes());
    hasher.update((item_count as u64).to_le_bytes());
    hasher.update(tree_root);
    finish(hasher)
}

fn domain_hasher(domain: &[u8]) -> Sha256 {
    let mut hasher = Sha256::new();
    hasher.update(b"ndabi-receipt-v1\0");
    hasher.update((domain.len() as u64).to_le_bytes());
    hasher.update(domain);
    hasher
}

fn finish(hasher: Sha256) -> ReceiptHash {
    hasher.finalize().into()
}

struct HashWriter<'a>(&'a mut Sha256);

impl fmt::Write for HashWriter<'_> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.0.update(value.as_bytes());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct Item {
        id: u32,
        status: u8,
        priority: u8,
        title: String,
    }

    #[derive(Clone, Copy)]
    struct Update {
        id: u32,
        status: u8,
        priority: u8,
    }

    impl ReceiptItem for Item {
        fn receipt_id(&self) -> u32 {
            self.id
        }

        fn receipt_status(&self) -> u8 {
            self.status
        }

        fn receipt_priority(&self) -> u8 {
            self.priority
        }

        fn receipt_title(&self) -> &str {
            &self.title
        }
    }

    impl ReceiptUpdate for Update {
        fn receipt_id(&self) -> u32 {
            self.id
        }

        fn receipt_status(&self) -> u8 {
            self.status
        }

        fn receipt_priority(&self) -> u8 {
            self.priority
        }
    }

    #[test]
    fn incremental_roots_equal_a_complete_rebuild() {
        let mut items = (1..=128)
            .map(|id| Item {
                id,
                status: (id % 3) as u8,
                priority: (id % 5) as u8,
                title: format!("Task {id}"),
            })
            .collect::<Vec<_>>();
        let updates = [
            Update {
                id: 1,
                status: 3,
                priority: 4,
            },
            Update {
                id: 64,
                status: 2,
                priority: 1,
            },
        ];
        let tree = ReceiptTree::new(7, &items).expect("base tree");
        let plan = tree.plan(&items, &updates, 8).expect("incremental plan");
        for update in updates {
            let item = &mut items[(update.id - 1) as usize];
            item.status = update.status;
            item.priority = update.priority;
        }
        let rebuilt = ReceiptTree::new(8, &items).expect("rebuilt tree");
        assert_eq!(plan.receipt(), rebuilt.receipt());
    }

    #[test]
    fn a_plan_cannot_commit_to_a_different_tree() {
        let items = (1..=8)
            .map(|id| Item {
                id,
                status: (id % 3) as u8,
                priority: (id % 5) as u8,
                title: format!("Task {id}"),
            })
            .collect::<Vec<_>>();
        let update = [Update {
            id: 1,
            status: 3,
            priority: 4,
        }];
        let tree = ReceiptTree::new(7, &items).expect("base tree");
        let plan = tree.plan(&items, &update, 8).expect("incremental plan");
        let mut different_items = items.clone();
        different_items[1].priority ^= 1;
        let mut different = ReceiptTree::new(7, &different_items).expect("different tree");
        assert_eq!(
            different
                .commit(&plan)
                .expect_err("foreign plan must refuse"),
            "receipt plan does not match the current tree"
        );
    }

    #[test]
    fn a_tree_above_the_fixed_application_limit_refuses() {
        let items = (1..=1_025)
            .map(|id| Item {
                id,
                status: 0,
                priority: 0,
                title: format!("Task {id}"),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            ReceiptTree::new(7, &items)
                .err()
                .expect("oversized tree must refuse"),
            "receipt tree exceeds the fixed node limit"
        );
    }
}
