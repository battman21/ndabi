#[path = "../v42/mod.rs"]
mod v42;

#[global_allocator]
static GLOBAL: ndabi_showdown::alloc::CountingAllocator = ndabi_showdown::alloc::CountingAllocator;

fn main() {
    if let Err(error) = v42::run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
