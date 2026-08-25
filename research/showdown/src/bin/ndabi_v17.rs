#[path = "../alloc.rs"]
mod alloc;
#[path = "../v17/mod.rs"]
mod v17;

use alloc::CountingAllocator;

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

fn main() {
    if let Err(error) = v17::runner::main() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
