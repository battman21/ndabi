#[path = "../alloc.rs"]
mod alloc;
#[path = "../v19/mod.rs"]
mod v19;

use alloc::CountingAllocator;

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

fn main() {
    if let Err(error) = v19::runner::main() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
