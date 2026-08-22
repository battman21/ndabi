use ndabi_showdown::alloc::CountingAllocator;

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

#[path = "../v40/mod.rs"]
mod v40;

fn main() {
    if let Err(error) = v40::run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
