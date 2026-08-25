use ndabi_showdown::alloc::CountingAllocator;

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

#[path = "../v30/mod.rs"]
mod v30;

fn main() {
    if let Err(error) = v30::run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
