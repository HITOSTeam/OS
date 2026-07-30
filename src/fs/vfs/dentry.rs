use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::RwLock;

use super::{DentryCachePolicy, VfsNode, VfsResult};

static NEXT_DENTRY_ID: AtomicUsize = AtomicUsize::new(1);

/// Dentry 存在于内存之中 是一种缓存类似的存在,见下面cache (区别于hard link)
/// A positive dentry.  The node identity is independent from the dentry
/// identity, which permits multiple hard-link names for one inode.
pub struct Dentry {
    id: u64,
    name: String,
    parent: Option<Arc<Dentry>>,
    node: Arc<dyn VfsNode>,
}

impl Dentry {
    /// generate root dentry no parent
    pub(super) fn root(node: Arc<dyn VfsNode>) -> Arc<Self> {
        Arc::new(Self {
            id: NEXT_DENTRY_ID.fetch_add(1, Ordering::Relaxed) as u64,
            name: String::new(),
            parent: None,
            node,
        })
    }

    // generate child dentry
    fn child(parent: &Arc<Dentry>, name: &str, node: Arc<dyn VfsNode>) -> Arc<Self> {
        Arc::new(Self {
            id: NEXT_DENTRY_ID.fetch_add(1, Ordering::Relaxed) as u64,
            name: name.to_string(),
            parent: Some(Arc::clone(parent)),
            node,
        })
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn node(&self) -> &Arc<dyn VfsNode> {
        &self.node
    }

    pub fn parent(&self) -> Option<Arc<Dentry>> {
        self.parent.clone()
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct DentryKey {
    parent_id: u64,
    name: String,
}

/// Cache only successful lookups.  There are no negative dentries, and
/// backends such as procfs can request revalidation on every lookup.
#[derive(Default)]
pub struct PositiveDentryCache {
    entries: RwLock<BTreeMap<DentryKey, Weak<Dentry>>>,
}

impl PositiveDentryCache {
    pub fn lookup(&self, parent: &Arc<Dentry>, name: &str) -> VfsResult<Arc<Dentry>> {
        let key = DentryKey {
            parent_id: parent.id(),
            name: name.to_string(),
        };
        if parent.node().dentry_cache_policy() == DentryCachePolicy::Stable
            && let Some(found) = self.entries.read().get(&key).and_then(Weak::upgrade)
        {
            return Ok(found);
        }

        /// Not stable we need to make sure the cached node is equal to the old one .
        let node = parent.node().lookup(name)?;
        if let Some(found) = self.entries.read().get(&key).and_then(Weak::upgrade)
            && found.node().filesystem_id() == node.filesystem_id()
            && found.node().node_id() == node.node_id()
        {
            return Ok(found);
        }

        // update cache
        let dentry = Dentry::child(parent, name, node);
        self.entries.write().insert(key, Arc::downgrade(&dentry));
        Ok(dentry)
    }

    /// remove the cache
    pub fn invalidate(&self, parent: &Arc<Dentry>, name: &str) {
        self.entries.write().remove(&DentryKey {
            parent_id: parent.id(),
            name: name.to_string(),
        });
    }

    pub fn invalidate_parent(&self, parent: &Arc<Dentry>) {
        self.entries
            .write()
            .retain(|key, _| key.parent_id != parent.id());
    }
}
