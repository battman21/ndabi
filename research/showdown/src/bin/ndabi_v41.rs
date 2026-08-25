#[path = "../v41/mod.rs"]
mod v41;

#[global_allocator]
static GLOBAL: ndabi_showdown::alloc::CountingAllocator = ndabi_showdown::alloc::CountingAllocator;

fn main() {
    if let Err(error) = v41::run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
