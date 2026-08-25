use ndabi_showdown::alloc::CountingAllocator;

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

#[path = "../v28/mod.rs"]
mod v28;

fn main() {
    if let Err(error) = v28::run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
