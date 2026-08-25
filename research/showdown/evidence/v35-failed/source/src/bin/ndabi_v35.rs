use ndabi_showdown::alloc::CountingAllocator;

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

#[path = "../v34/mod.rs"]
mod v34;

fn main() {
    let executable = std::env::args().next().unwrap_or_default();
    let result = if executable.ends_with("ndabi_v34") {
        v34::run()
    } else {
        v34::run_v35()
    };
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
