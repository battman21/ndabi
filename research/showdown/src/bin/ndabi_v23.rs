#[path = "../alloc.rs"]
mod alloc;
#[path = "../v23/mod.rs"]
mod v23;

use alloc::CountingAllocator;

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

fn main() {
    if let Err(error) = v23::run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
