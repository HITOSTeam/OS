use crate::println;
use core::cell::{Ref, RefCell, RefMut};
use core::panic::Location;
use core::str;
mod id_allocator;
pub use id_allocator::RecycleAllocator;
/// RefCellSafe 改良版：记录上一次借用位置并打印当前借用尝试位置
#[allow(dead_code)]
pub struct RefCellSafe<T> {
    refcell: RefCell<T>,
    last_borrow_loc: RefCell<Option<&'static Location<'static>>>,
    last_borrow_mut_loc: RefCell<Option<&'static Location<'static>>>,
}

unsafe impl<T> Sync for RefCellSafe<T> {}

#[allow(dead_code)]
impl<T> RefCellSafe<T> {
    pub const fn new(val: T) -> Self {
        Self {
            refcell: RefCell::new(val),
            last_borrow_loc: RefCell::new(None),
            last_borrow_mut_loc: RefCell::new(None),
        }
    }

    /// 不可变 borrow
    #[track_caller]
    pub fn borrow(&self) -> Ref<'_, T> {
        let caller = Location::caller();
        match self.refcell.try_borrow() {
            Ok(r) => {
                *self.last_borrow_loc.borrow_mut() = Some(caller);
                r
            }
            Err(_) => {
                let last_mut = *self.last_borrow_mut_loc.borrow();
                println!(
                    "[RefCellSafe] ❌ borrow() failed! This borrow at {}:{}",
                    caller.file(),
                    caller.line()
                );
                if let Some(last) = last_mut {
                    println!(
                        "[RefCellSafe] ❌ previous mutable borrow at {}:{}",
                        last.file(),
                        last.line()
                    );
                } else {
                    println!("[RefCellSafe] ❌ no previous mutable borrow recorded");
                }
                panic!("RefCellSafe borrow() failed");
            }
        }
    }

    /// 可变 borrow
    #[track_caller]
    pub fn borrow_mut(&self) -> RefMut<'_, T> {
        let caller = Location::caller();
        match self.refcell.try_borrow_mut() {
            Ok(rm) => {
                *self.last_borrow_mut_loc.borrow_mut() = Some(caller);
                rm
            }
            Err(_) => {
                let last_mut = *self.last_borrow_mut_loc.borrow();
                let last_borrow = *self.last_borrow_loc.borrow();
                println!(
                    "[RefCellSafe] ❌ borrow_mut() failed! This borrow at {}:{}",
                    caller.file(),
                    caller.line()
                );
                if let Some(last) = last_mut {
                    println!(
                        "[RefCellSafe] ❌ previous mutable borrow at {}:{}",
                        last.file(),
                        last.line()
                    );
                }
                if let Some(last) = last_borrow {
                    println!(
                        "[RefCellSafe] ❌ previous immutable borrow at {}:{}",
                        last.file(),
                        last.line()
                    );
                }
                panic!("RefCellSafe borrow_mut() failed");
            }
        }
    }
}

#[allow(dead_code)]
pub fn is_equal_two_string(string1: usize, string2: usize) -> bool {
    unsafe {
        let mut ptr1 = string1 as *const u8;
        let mut ptr2 = string2 as *const u8;
        // let mut indexer = 0;
        loop {
            let c1 = *ptr1;
            let c2 = *ptr2;
            if c1 == 0 && c2 == 0 {
                // println!("equal!");
                return true;
            }
            if c1 != c2 {
                // println!("not equal! becuase {} != {},at indexer {}", c1, c2, indexer);
                return false;
            }
            ptr1 = ptr1.add(1);
            ptr2 = ptr2.add(1);
            // indexer += 1;
        }
    }
}

#[allow(dead_code)]
pub fn get_app_data_by_name(name: usize, number_of_apps: usize, start_loc: usize) -> &'static [u8] {
    unsafe {
        let mut now_ptr = start_loc as *const usize;
        for _ in 0..number_of_apps {
            let app_start = *now_ptr;
            let app_end = *now_ptr.add(1);
            let app_name = *now_ptr.add(2);

            // println!(
            //     "App now name is  {}",
            //     str::from_utf8(core::slice::from_raw_parts(app_name as *const u8, 30)).unwrap()
            // );
            if is_equal_two_string(app_name, name) {
                let app_size = app_end - app_start;
                let app_slice = core::slice::from_raw_parts(app_start as *const u8, app_size);
                return app_slice;
            }

            now_ptr = now_ptr.add(3);
        }
        panic!(
            "App data not found for name: {}",
            str::from_utf8(core::slice::from_raw_parts(name as *const u8, 30)).unwrap()
        );
    }
}
