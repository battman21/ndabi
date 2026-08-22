use ndabi_showdown::alloc::CountingAllocator;

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

#[path = "../v31/mod.rs"]
mod v31;

fn main() {
    if let Err(error) = v31::run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
