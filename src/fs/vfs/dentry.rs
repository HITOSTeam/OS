use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::RwLock;

use super::{DentryCachePolicy, VfsNode, VfsResult};

static NEXT_DENTRY_ID: AtomicUsize = AtomicUsize::new(1);

/// Bound positive dentries retained by one filesystem instance.
///
/// Linux sizes and reclaims the dcache according to memory pressure.  This
/// kernel does not yet have a general shrinker framework, so use a fixed
/// upper bound that keeps a useful build working set while preventing path
/// churn from consuming the entire 512-MiB kernel heap.
const DENTRY_CACHE_MAX_ENTRIES: usize = 32 * 1024;

/// Bound one foreground reclaim pass. Linux's dcache shrinker receives an
/// explicit `nr_to_scan`; keep the same latency property while this kernel
/// still uses a fixed-capacity cache rather than a memory-pressure shrinker.
const DENTRY_CLOCK_SCAN_BUDGET: usize = 64;

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
    pub(super) fn child(parent: &Arc<Dentry>, name: &str, node: Arc<dyn VfsNode>) -> Arc<Self> {
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
    parent_filesystem_id: u64,
    parent_node_id: u64,
    name: String,
}

impl DentryKey {
    fn new(parent: &Dentry, name: &str) -> Self {
        Self {
            // A freshly reconstructed dentry has a new dentry ID.  The
            // backing directory identity is stable, so keying by it lets a
            // later lookup replace an old entry instead of accumulating an
            // unreachable key for every path walk.
            parent_filesystem_id: parent.node().filesystem_id(),
            parent_node_id: parent.node().node_id(),
            name: name.to_string(),
        }
    }
}

struct CachedDentry {
    dentry: Arc<Dentry>,
    /// Set by shared-lock lookup and consumed by the reclaim clock.
    referenced: AtomicBool,
}

/// One bounded second-chance queue entry.
///
/// Store only the dentry ID rather than a `Weak<Dentry>`.  Invalidating the
/// map entry therefore releases the Arc allocation immediately; a stale
/// queue record contains metadata only and is discarded on the next sweep.
struct DentryClockEntry {
    key: DentryKey,
    dentry_id: u64,
}

#[derive(Default)]
struct PositiveDentryCacheInner {
    entries: BTreeMap<DentryKey, CachedDentry>,
    reclaim_clock: VecDeque<DentryClockEntry>,
}

/// Cache only successful lookups.  There are no negative dentries, and
/// backends such as procfs can request revalidation on every lookup.
pub struct PositiveDentryCache {
    inner: RwLock<PositiveDentryCacheInner>,
    capacity: usize,
}

impl Default for PositiveDentryCache {
    fn default() -> Self {
        Self {
            inner: RwLock::new(PositiveDentryCacheInner::default()),
            capacity: DENTRY_CACHE_MAX_ENTRIES,
        }
    }
}

impl PositiveDentryCache {
    #[cfg(test)]
    pub(super) fn with_capacity(capacity: usize) -> Self {
        assert!(capacity != 0, "dentry cache capacity must be non-zero");
        Self {
            inner: RwLock::new(PositiveDentryCacheInner::default()),
            capacity,
        }
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.inner.read().entries.len()
    }

    #[cfg(test)]
    pub(super) fn reclaim_one_for_test(&self) -> usize {
        let mut inner = self.inner.write();
        self.make_clock_room(&mut inner)
    }

    pub fn lookup(&self, parent: &Arc<Dentry>, name: &str) -> VfsResult<Arc<Dentry>> {
        crate::perf::record_dcache_lookup();
        let key = DentryKey::new(parent, name);
        if parent.node().dentry_cache_policy() == DentryCachePolicy::Stable
            && let Some(found) = self.cached_for_parent(&key, parent, None)
        {
            return Ok(found);
        }

        // For dynamic nodes, make sure the cached dentry still names the same node.
        crate::perf::record_dcache_backend_lookup();
        let node = match parent.node().lookup(name) {
            Ok(node) => node,
            Err(error) => {
                // Revalidated backends must not retain a positive entry after
                // the backend reports that the name has disappeared.
                if parent.node().dentry_cache_policy() == DentryCachePolicy::Revalidate {
                    self.remove_key(&key);
                }
                return Err(error);
            }
        };
        if let Some(found) = self.cached_for_parent(&key, parent, Some(&node)) {
            return Ok(found);
        }

        // Publish one strong cache reference.  A second lookup may have won
        // the race while the backend lookup ran, so recheck under the write
        // lock and preserve the already-published dentry identity when it
        // still names the same parent and node.
        let dentry = Dentry::child(parent, name, node);
        Ok(self.insert_or_reuse(key, dentry))
    }

    /// Invalidate one name after a successful namespace mutation.
    pub fn invalidate(&self, parent: &Arc<Dentry>, name: &str) {
        self.remove_key(&DentryKey::new(parent, name));
    }

    pub fn invalidate_parent(&self, parent: &Arc<Dentry>) {
        let parent_filesystem_id = parent.node().filesystem_id();
        let parent_node_id = parent.node().node_id();
        let mut inner = self.inner.write();
        let old_len = inner.entries.len();
        inner.entries.retain(|key, _| {
            key.parent_filesystem_id != parent_filesystem_id || key.parent_node_id != parent_node_id
        });
        crate::perf::record_dcache_invalidations(old_len.saturating_sub(inner.entries.len()));
    }

    fn cached_for_parent(
        &self,
        key: &DentryKey,
        parent: &Arc<Dentry>,
        expected_node: Option<&Arc<dyn VfsNode>>,
    ) -> Option<Arc<Dentry>> {
        let inner = self.inner.read();
        let cached = inner.entries.get(key)?;
        let cached_parent = cached.dentry.parent.as_ref()?;
        if !Arc::ptr_eq(cached_parent, parent) {
            // A rename or an earlier parent eviction may reconstruct the
            // same backing directory under a different dentry.  Reusing the
            // child would attach the result to its obsolete parent chain.
            return None;
        }
        if let Some(expected_node) = expected_node
            && (cached.dentry.node().filesystem_id() != expected_node.filesystem_id()
                || cached.dentry.node().node_id() != expected_node.node_id())
        {
            return None;
        }
        cached.referenced.store(true, Ordering::Relaxed);
        crate::perf::record_dcache_hit(expected_node.is_some());
        Some(Arc::clone(&cached.dentry))
    }

    fn insert_or_reuse(&self, key: DentryKey, dentry: Arc<Dentry>) -> Arc<Dentry> {
        let mut inner = self.inner.write();
        if let Some(cached) = inner.entries.get(&key)
            && cached.dentry.parent.as_ref().is_some_and(|cached_parent| {
                dentry
                    .parent
                    .as_ref()
                    .is_some_and(|parent| Arc::ptr_eq(cached_parent, parent))
            })
            && cached.dentry.node().filesystem_id() == dentry.node().filesystem_id()
            && cached.dentry.node().node_id() == dentry.node().node_id()
        {
            cached.referenced.store(true, Ordering::Relaxed);
            crate::perf::record_dcache_hit(true);
            return Arc::clone(&cached.dentry);
        }

        self.make_clock_room(&mut inner);
        let replacing = inner.entries.contains_key(&key);
        let dentry_id = dentry.id();
        inner.entries.insert(
            key.clone(),
            CachedDentry {
                dentry: Arc::clone(&dentry),
                // Its place at the tail already grants one trip around the
                // clock.  Only a later cache hit earns a second chance.
                referenced: AtomicBool::new(false),
            },
        );
        inner
            .reclaim_clock
            .push_back(DentryClockEntry { key, dentry_id });
        crate::perf::record_dcache_insert(replacing);
        dentry
    }

    fn make_clock_room(&self, inner: &mut PositiveDentryCacheInner) -> usize {
        if inner.reclaim_clock.len() < self.capacity {
            return 0;
        }

        debug_assert!(inner.reclaim_clock.len() <= self.capacity);
        // Keep one candidate out of the queue while scanning. This reserves
        // the metadata slot needed by the incoming entry and also gives a
        // deterministic victim if the bounded window contains no cold,
        // cache-only dentry.
        let mut fallback: Option<(DentryClockEntry, u8)> = None;
        let mut scans = 0usize;

        while scans < DENTRY_CLOCK_SCAN_BUDGET && !inner.reclaim_clock.is_empty() {
            let candidate = inner
                .reclaim_clock
                .pop_front()
                .expect("full dentry reclaim clock is not empty");
            scans += 1;
            crate::perf::record_dcache_clock_scan();

            let Some(cached) = inner.entries.get(&candidate.key) else {
                // Invalidation/replacement already released this entry. Drop
                // the stale clock record and preserve any held fallback.
                if let Some((held, _)) = fallback.take() {
                    inner.reclaim_clock.push_back(held);
                }
                return scans;
            };
            if cached.dentry.id() != candidate.dentry_id {
                if let Some((held, _)) = fallback.take() {
                    inner.reclaim_clock.push_back(held);
                }
                return scans;
            }

            // A cache-only dentry can actually release memory. A parent held
            // by cached children (or an externally referenced path) is kept
            // as a fallback only; evicting it first would free nothing and
            // invalidate the descendants' parent identity.
            let cache_only = Arc::strong_count(&cached.dentry) == 1;
            let was_referenced = cached.referenced.swap(false, Ordering::Relaxed);
            if cache_only && !was_referenced {
                let removed = inner.entries.remove(&candidate.key).is_some();
                debug_assert!(removed);
                if let Some((held, _)) = fallback.take() {
                    inner.reclaim_clock.push_back(held);
                }
                if removed {
                    crate::perf::record_dcache_eviction();
                }
                return scans;
            }

            // Prefer a referenced cache-only leaf over an unreferenced parent:
            // the former releases memory immediately and avoids tearing down
            // a live cached subtree. Within one rank, retain the oldest item.
            let rank = match (cache_only, was_referenced) {
                (true, true) => 0,
                (false, false) => 1,
                (false, true) => 2,
                (true, false) => unreachable!("cold cache-only entry was handled above"),
            };
            let replace_fallback = fallback
                .as_ref()
                .is_none_or(|(_, current_rank)| rank < *current_rank);
            if replace_fallback {
                if let Some((old, _)) = fallback.replace((candidate, rank)) {
                    inner.reclaim_clock.push_back(old);
                }
            } else {
                inner.reclaim_clock.push_back(candidate);
            }
        }

        // The hard cache/clock bound must still hold when every scanned item
        // is hot or externally referenced. The ranked fallback makes this
        // deterministic and leaf-preferring while keeping lock hold time
        // independent of the 32K cache capacity.
        let (candidate, _) = fallback.expect("full dentry clock has a current fallback");
        let removed = inner.entries.remove(&candidate.key).is_some();
        debug_assert!(removed);
        if removed {
            crate::perf::record_dcache_eviction();
        }
        scans
    }

    fn remove_key(&self, key: &DentryKey) {
        if self.inner.write().entries.remove(key).is_some() {
            crate::perf::record_dcache_invalidations(1);
        }
    }
}

impl Drop for PositiveDentryCache {
    fn drop(&mut self) {
        crate::perf::record_dcache_drop(self.inner.get_mut().entries.len());
    }
}
