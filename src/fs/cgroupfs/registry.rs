use super::*;

pub(crate) struct CgroupRegistry {
    pub(crate) mounts: BTreeMap<String, CgroupHierarchyKey>,
    pub(crate) hierarchies: BTreeMap<CgroupHierarchyKey, CgroupMountState>,
}

impl CgroupRegistry {
    pub(crate) fn new() -> Self {
        Self {
            mounts: BTreeMap::new(),
            hierarchies: BTreeMap::new(),
        }
    }

    pub(crate) fn mount(&mut self, target: &str, spec: &CgroupMountSpec) -> isize {
        if self.mounts.contains_key(target) {
            return EBUSY;
        }
        self.hierarchies
            .entry(spec.hierarchy_key().clone())
            .or_insert_with(|| {
                let mut state = CgroupMountState::new(spec.kind());
                state.seed_root_membership();
                state
            });
        self.mounts
            .insert(String::from(target), spec.hierarchy_key().clone());
        0
    }

    pub(crate) fn umount(&mut self, target: &str) -> isize {
        let Some(key) = self.mounts.remove(target) else {
            return 0;
        };
        let hierarchy_still_mounted = self.mounts.values().any(|mounted_key| mounted_key == &key);
        if !hierarchy_still_mounted {
            self.hierarchies.remove(&key);
        }
        0
    }

    pub(crate) fn preferred_proc_hierarchy(&self) -> Option<&CgroupMountState> {
        self.hierarchies
            .values()
            .find(|state| state.is_unified())
            .or_else(|| self.hierarchies.values().next())
    }
}
