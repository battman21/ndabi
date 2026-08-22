use ndabi_showdown::alloc::CountingAllocator;

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

#[path = "../v33/mod.rs"]
mod v33;

fn main() {
    if let Err(error) = v33::run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
