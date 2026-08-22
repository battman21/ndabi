#[path = "../alloc.rs"]
mod alloc;
#[path = "../v22/mod.rs"]
mod v22;

use alloc::CountingAllocator;

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

fn main() {
    if let Err(error) = v22::run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
