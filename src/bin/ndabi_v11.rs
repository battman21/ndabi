#[path = "../alloc.rs"]
mod alloc;
#[path = "../v11/mod.rs"]
mod v11;

use alloc::CountingAllocator;

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

fn main() {
    if let Err(error) = v11::runner::main() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
