#[path = "../alloc.rs"]
mod alloc;
#[path = "../v25/mod.rs"]
mod v25;

use alloc::CountingAllocator;

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

fn main() {
    if let Err(error) = v25::run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
