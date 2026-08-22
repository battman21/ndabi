#[path = "../alloc.rs"]
mod alloc;
#[path = "../v14/mod.rs"]
mod v14;

use alloc::CountingAllocator;

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

fn main() {
    if let Err(error) = v14::runner::main() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
