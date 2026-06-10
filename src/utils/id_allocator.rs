use alloc::vec::Vec;

#[derive(Clone)]
pub struct RecycleAllocator {
    current: usize,
    recycled: Vec<usize>,
}

impl RecycleAllocator {
    pub fn new() -> Self {
        RecycleAllocator {
            current: 0,
            recycled: Vec::new(),
        }
    }
    pub fn alloc(&mut self) -> usize {
        if let Some(id) = self.recycled.pop() {
            id
        } else {
            self.current += 1;
            self.current - 1
        }
    }
    pub fn dealloc(&mut self, id: usize) {
        assert!(id < self.current);
        assert!(
            !self.recycled.iter().any(|i| *i == id),
            "id {} has been deallocated!",
            id
        );
        self.recycled.push(id);
    }

    pub fn reserve(&mut self, id: usize) {
        if id >= self.current {
            self.current = id + 1;
            return;
        }
        if let Some(pos) = self.recycled.iter().position(|recycled| *recycled == id) {
            self.recycled.swap_remove(pos);
        }
    }
}
