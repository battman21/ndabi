#[path = "../alloc.rs"]
mod alloc;
#[path = "../v18/mod.rs"]
mod v18;

use alloc::CountingAllocator;

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

fn main() {
    if let Err(error) = v18::runner::main() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
