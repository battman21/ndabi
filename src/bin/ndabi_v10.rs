#[path = "../alloc.rs"]
mod alloc;
#[path = "../v10/mod.rs"]
mod v10;

use alloc::CountingAllocator;

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

fn main() {
    if let Err(error) = v10::runner::main() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
