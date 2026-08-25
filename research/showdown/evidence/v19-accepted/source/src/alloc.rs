use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

pub struct CountingAllocator;

static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static ALLOCATED_BYTES: AtomicU64 = AtomicU64::new(0);
static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
static PEAK_LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            record_allocation(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let replacement = unsafe { System.realloc(pointer, layout, new_size) };
        if !replacement.is_null() {
            LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
            record_allocation(new_size);
        }
        replacement
    }
}

fn record_allocation(bytes: usize) {
    ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
    ALLOCATED_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
    let live = LIVE_BYTES.fetch_add(bytes, Ordering::Relaxed) + bytes;
    let mut peak = PEAK_LIVE_BYTES.load(Ordering::Relaxed);
    while live > peak {
        match PEAK_LIVE_BYTES.compare_exchange_weak(
            peak,
            live,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(observed) => peak = observed,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct AllocationStart {
    allocations: u64,
    allocated_bytes: u64,
    live_bytes: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct AllocationDelta {
    pub allocations: u64,
    pub allocated_bytes: u64,
    pub peak_additional_live_bytes: u64,
}

pub fn begin_measurement() -> AllocationStart {
    let live_bytes = LIVE_BYTES.load(Ordering::SeqCst);
    PEAK_LIVE_BYTES.store(live_bytes, Ordering::SeqCst);
    AllocationStart {
        allocations: ALLOCATIONS.load(Ordering::SeqCst),
        allocated_bytes: ALLOCATED_BYTES.load(Ordering::SeqCst),
        live_bytes,
    }
}

pub fn end_measurement(start: AllocationStart) -> AllocationDelta {
    AllocationDelta {
        allocations: ALLOCATIONS
            .load(Ordering::SeqCst)
            .saturating_sub(start.allocations),
        allocated_bytes: ALLOCATED_BYTES
            .load(Ordering::SeqCst)
            .saturating_sub(start.allocated_bytes),
        peak_additional_live_bytes: PEAK_LIVE_BYTES
            .load(Ordering::SeqCst)
            .saturating_sub(start.live_bytes) as u64,
    }
}
