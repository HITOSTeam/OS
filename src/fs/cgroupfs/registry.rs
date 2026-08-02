use super::*;

pub(crate) struct CgroupRegistry {
    pub(crate) hierarchies: BTreeMap<CgroupHierarchyKey, CgroupMountState>,
    object_mount_refs: BTreeMap<CgroupHierarchyKey, usize>,
    object_root_refs: BTreeMap<(CgroupHierarchyKey, u64), usize>,
}

impl CgroupRegistry {
    pub(crate) fn new() -> Self {
        Self {
            hierarchies: BTreeMap::new(),
            object_mount_refs: BTreeMap::new(),
            object_root_refs: BTreeMap::new(),
        }
    }

    fn ensure_hierarchy(&mut self, spec: &CgroupMountSpec) -> &mut CgroupMountState {
        self.hierarchies
            .entry(spec.hierarchy_key().clone())
            .or_insert_with(|| {
                let mut state = CgroupMountState::new(spec.kind());
                state.seed_root_membership();
                state
            })
    }

    /// Acquire one object-VFS view of a hierarchy.  The hierarchy state and
    /// superblock ID are shared by all mounts; only the exposed root dentry is
    /// specific to the captured cgroup namespace.
    pub(crate) fn acquire_object_mount(
        &mut self,
        spec: &CgroupMountSpec,
        requested_root: &str,
    ) -> (u64, u64) {
        let (filesystem_id, root_ino) = {
            let state = self.ensure_hierarchy(spec);
            let root = state
                .nodes
                .get(requested_root)
                .or_else(|| state.nodes.get("/"))
                .expect("cgroup hierarchy lost its root node");
            (state.filesystem_id, root.ino)
        };
        *self
            .object_mount_refs
            .entry(spec.hierarchy_key().clone())
            .or_insert(0) += 1;
        *self
            .object_root_refs
            .entry((spec.hierarchy_key().clone(), root_ino))
            .or_insert(0) += 1;
        (filesystem_id, root_ino)
    }

    pub(crate) fn release_object_mount(&mut self, key: &CgroupHierarchyKey, root_ino: u64) {
        decrement_ref(&mut self.object_root_refs, &(key.clone(), root_ino));
        decrement_ref(&mut self.object_mount_refs, key);
        if !self.object_mount_refs.contains_key(key) {
            self.hierarchies.remove(key);
        }
    }

    pub(crate) fn object_root_is_pinned(&self, key: &CgroupHierarchyKey, ino: u64) -> bool {
        self.object_root_refs.contains_key(&(key.clone(), ino))
    }

    pub(crate) fn preferred_proc_hierarchy(&self) -> Option<&CgroupMountState> {
        self.hierarchies
            .values()
            .find(|state| state.is_unified())
            .or_else(|| self.hierarchies.values().next())
    }
}

fn decrement_ref<K: Ord + Clone>(refs: &mut BTreeMap<K, usize>, key: &K) {
    let Some(count) = refs.get_mut(key) else {
        return;
    };
    *count = count.saturating_sub(1);
    if *count == 0 {
        refs.remove(key);
    }
}
