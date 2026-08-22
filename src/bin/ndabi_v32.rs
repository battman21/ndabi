use ndabi_showdown::alloc::CountingAllocator;

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

#[path = "../v32/mod.rs"]
mod v32;

fn main() {
    if let Err(error) = v32::run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
