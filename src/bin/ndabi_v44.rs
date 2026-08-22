#[global_allocator]
static GLOBAL: ndabi_showdown::alloc::CountingAllocator = ndabi_showdown::alloc::CountingAllocator;

fn main() {
    if let Err(error) = ndabi_showdown::v44::run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
