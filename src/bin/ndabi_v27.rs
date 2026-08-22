use ndabi_showdown::alloc::CountingAllocator;

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

#[path = "../v27/mod.rs"]
mod v27;

fn main() {
    if let Err(error) = v27::run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
