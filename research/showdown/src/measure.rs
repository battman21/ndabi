use std::hint::black_box;
use std::mem::MaybeUninit;
use std::time::Instant;

use serde::Serialize;

use crate::alloc::{begin_measurement, end_measurement};

const DIAGNOSTIC_BATCH_SIZE: u64 = 16;

#[derive(Clone, Copy, Debug)]
pub struct Observation {
    pub response_bytes: usize,
    pub semantic_digest: u64,
    pub view_digest: u64,
    pub rendered_bytes: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct ArmMeasurement {
    pub id: String,
    pub label: String,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub median_ns: u64,
    pub median_ci95_low_ns: u64,
    pub median_ci95_high_ns: u64,
    pub p95_ns: u64,
    pub p95_ci95_low_ns: u64,
    pub p95_ci95_high_ns: u64,
    pub p99_ns: u64,
    pub p999_ns: u64,
    pub sample_count: u64,
    pub operations_per_second: f64,
    pub allocations_per_operation: f64,
    pub allocated_bytes_per_operation: f64,
    pub peak_additional_live_bytes: u64,
    pub median_thread_cpu_ns: u64,
    pub retained_rust_bytes: u64,
    pub rendered_bytes: u64,
    pub semantic_digest: String,
    pub view_digest: String,
    pub deterministic_encoding: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct PhaseMeasurement {
    pub id: String,
    pub label: String,
    pub admission_median_ns: u64,
    pub admission_median_thread_cpu_ns: u64,
    pub execution_median_ns: u64,
    pub execution_median_thread_cpu_ns: u64,
    pub result_median_ns: u64,
    pub result_median_thread_cpu_ns: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct RetainedMemoryBreakdown {
    pub id: String,
    pub label: String,
    pub request_capacity_bytes: u64,
    pub response_capacity_bytes: u64,
    pub rendered_capacity_bytes: u64,
    pub receipt_tree_bytes: u64,
    pub state_bytes: u64,
    pub engine_handle_bytes: u64,
    pub total_bytes: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct OperationTiming {
    pub wall_ns: u64,
    pub thread_cpu_ns: u64,
}

pub struct ArmBatch {
    representative: Observation,
    samples: Vec<u64>,
    cpu_samples: Vec<u64>,
    total_seconds: f64,
    allocations: u64,
    allocated_bytes: u64,
    peak_additional_live_bytes: u64,
}

impl ArmBatch {
    pub fn p95_ns(&self) -> u64 {
        let mut samples = self.samples.clone();
        samples.sort_unstable();
        percentile(&samples, 0.95)
    }
}

pub fn measure_batch<F>(
    iterations: usize,
    warmup: usize,
    mut operation: F,
) -> Result<ArmBatch, String>
where
    F: FnMut() -> Result<Observation, String>,
{
    measure_batch_prepared(&mut (), iterations, warmup, |_| Ok(()), |_| operation())
}

pub fn measure_batch_prepared<S, P, F>(
    state: &mut S,
    iterations: usize,
    warmup: usize,
    mut prepare: P,
    mut operation: F,
) -> Result<ArmBatch, String>
where
    P: FnMut(&mut S) -> Result<(), String>,
    F: FnMut(&mut S) -> Result<Observation, String>,
{
    for _ in 0..warmup {
        prepare(state)?;
        black_box(operation(state)?);
    }

    prepare(state)?;
    let representative = operation(state)?;
    let mut samples = Vec::with_capacity(iterations);
    let mut cpu_samples = Vec::with_capacity(iterations);
    let mut total_seconds = 0.0;
    let mut allocation_count = 0u64;
    let mut allocated_bytes = 0u64;
    let mut peak_additional_live_bytes = 0u64;
    for _ in 0..iterations {
        prepare(state)?;
        let allocation_start = begin_measurement();
        let cpu_start = thread_cpu_ns()?;
        let started = Instant::now();
        let observation = operation(state)?;
        let elapsed = started.elapsed();
        let cpu_elapsed = thread_cpu_ns()?.saturating_sub(cpu_start);
        let allocations = end_measurement(allocation_start);
        samples.push(u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX));
        cpu_samples.push(cpu_elapsed);
        total_seconds += elapsed.as_secs_f64();
        allocation_count = allocation_count.saturating_add(allocations.allocations);
        allocated_bytes = allocated_bytes.saturating_add(allocations.allocated_bytes);
        peak_additional_live_bytes =
            peak_additional_live_bytes.max(allocations.peak_additional_live_bytes);
        black_box(observation);
    }

    Ok(ArmBatch {
        representative,
        samples,
        cpu_samples,
        total_seconds,
        allocations: allocation_count,
        allocated_bytes,
        peak_additional_live_bytes,
    })
}

pub fn finish_arm(
    id: &str,
    label: &str,
    request_bytes: usize,
    retained_rust_bytes: usize,
    deterministic_encoding: bool,
    batches: Vec<ArmBatch>,
) -> Result<ArmMeasurement, String> {
    let representative = batches
        .first()
        .ok_or_else(|| "benchmark arm has no measurement batch".to_string())?
        .representative;
    if batches.iter().any(|batch| batch.p95_ns() == 0) {
        return Err("a benchmark batch has no measurable p95 latency".to_string());
    }
    if batches.iter().any(|batch| {
        batch.representative.response_bytes != representative.response_bytes
            || batch.representative.semantic_digest != representative.semantic_digest
            || batch.representative.view_digest != representative.view_digest
            || batch.representative.rendered_bytes != representative.rendered_bytes
    }) {
        return Err("benchmark batches produced different representative results".to_string());
    }
    let total_seconds = batches.iter().map(|batch| batch.total_seconds).sum::<f64>();
    let allocations = batches.iter().map(|batch| batch.allocations).sum::<u64>();
    let allocated_bytes = batches
        .iter()
        .map(|batch| batch.allocated_bytes)
        .sum::<u64>();
    let peak_additional_live_bytes = batches
        .iter()
        .map(|batch| batch.peak_additional_live_bytes)
        .max()
        .unwrap_or(0);
    let mut samples = Vec::new();
    let mut cpu_samples = Vec::new();
    for batch in batches {
        samples.extend(batch.samples);
        cpu_samples.extend(batch.cpu_samples);
    }
    samples.sort_unstable();
    cpu_samples.sort_unstable();
    let median_ns = percentile(&samples, 0.50);
    let p95_ns = percentile(&samples, 0.95);
    let p99_ns = percentile(&samples, 0.99);
    let p999_ns = percentile(&samples, 0.999);
    let intervals = bootstrap_intervals(&samples, stable_seed(id));
    let divisor = samples.len() as f64;

    Ok(ArmMeasurement {
        id: id.to_string(),
        label: label.to_string(),
        request_bytes: request_bytes as u64,
        response_bytes: representative.response_bytes as u64,
        median_ns,
        median_ci95_low_ns: intervals.0,
        median_ci95_high_ns: intervals.1,
        p95_ns,
        p95_ci95_low_ns: intervals.2,
        p95_ci95_high_ns: intervals.3,
        p99_ns,
        p999_ns,
        sample_count: samples.len() as u64,
        operations_per_second: divisor / total_seconds,
        allocations_per_operation: allocations as f64 / divisor,
        allocated_bytes_per_operation: allocated_bytes as f64 / divisor,
        peak_additional_live_bytes,
        median_thread_cpu_ns: percentile(&cpu_samples, 0.50),
        retained_rust_bytes: retained_rust_bytes as u64,
        rendered_bytes: representative.rendered_bytes as u64,
        semantic_digest: format!("{:016x}", representative.semantic_digest),
        view_digest: format!("{:016x}", representative.view_digest),
        deterministic_encoding,
    })
}

pub fn thread_cpu_ns() -> Result<u64, String> {
    let mut value = MaybeUninit::<libc::timespec>::uninit();
    let status = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, value.as_mut_ptr()) };
    if status != 0 {
        return Err("the operating system refused the thread CPU clock".to_string());
    }
    let value = unsafe { value.assume_init() };
    let seconds = u64::try_from(value.tv_sec)
        .map_err(|_| "the thread CPU clock returned negative seconds".to_string())?;
    let nanoseconds = u64::try_from(value.tv_nsec)
        .map_err(|_| "the thread CPU clock returned negative nanoseconds".to_string())?;
    Ok(seconds
        .saturating_mul(1_000_000_000)
        .saturating_add(nanoseconds))
}

pub fn median_operation_timing<F>(
    iterations: usize,
    warmup: usize,
    mut operation: F,
) -> Result<OperationTiming, String>
where
    F: FnMut() -> Result<(), String>,
{
    for _ in 0..warmup {
        operation()?;
    }
    let mut wall_samples = Vec::with_capacity(iterations);
    let mut cpu_samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let cpu_started = thread_cpu_ns()?;
        let started = Instant::now();
        for _ in 0..DIAGNOSTIC_BATCH_SIZE {
            operation()?;
        }
        let elapsed = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let cpu_elapsed = thread_cpu_ns()?.saturating_sub(cpu_started);
        wall_samples.push(elapsed / DIAGNOSTIC_BATCH_SIZE);
        cpu_samples.push(cpu_elapsed / DIAGNOSTIC_BATCH_SIZE);
    }
    wall_samples.sort_unstable();
    cpu_samples.sort_unstable();
    Ok(OperationTiming {
        wall_ns: percentile(&wall_samples, 0.50),
        thread_cpu_ns: percentile(&cpu_samples, 0.50),
    })
}

fn bootstrap_intervals(sorted_samples: &[u64], seed: u64) -> (u64, u64, u64, u64) {
    const RESAMPLES: usize = 400;
    if sorted_samples.is_empty() {
        return (0, 0, 0, 0);
    }
    let mut generator = XorShift64::new(seed);
    let mut sample = vec![0u64; sorted_samples.len()];
    let mut medians = Vec::with_capacity(RESAMPLES);
    let mut p95s = Vec::with_capacity(RESAMPLES);
    for _ in 0..RESAMPLES {
        for value in &mut sample {
            *value = sorted_samples[generator.index(sorted_samples.len())];
        }
        sample.sort_unstable();
        medians.push(percentile(&sample, 0.50));
        p95s.push(percentile(&sample, 0.95));
    }
    medians.sort_unstable();
    p95s.sort_unstable();
    (
        percentile(&medians, 0.025),
        percentile(&medians, 0.975),
        percentile(&p95s, 0.025),
        percentile(&p95s, 0.975),
    )
}

fn stable_seed(id: &str) -> u64 {
    id.bytes().fold(0x9e37_79b9_7f4a_7c15, |seed, byte| {
        seed.rotate_left(7) ^ u64::from(byte)
    })
}

struct XorShift64(u64);

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self(if seed == 0 { 1 } else { seed })
    }

    fn index(&mut self, upper: usize) -> usize {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        (value as usize) % upper
    }
}

fn percentile(sorted: &[u64], percentile: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = ((sorted.len() - 1) as f64 * percentile).ceil() as usize;
    sorted[rank.min(sorted.len() - 1)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_uses_a_bounded_nearest_rank() {
        let values = [1, 2, 3, 4, 5];
        assert_eq!(percentile(&values, 0.50), 3);
        assert_eq!(percentile(&values, 0.95), 5);
    }

    #[test]
    fn bootstrap_intervals_are_deterministic_and_bounded() {
        let values = (1..=100).collect::<Vec<_>>();
        let first = bootstrap_intervals(&values, 7);
        let second = bootstrap_intervals(&values, 7);
        assert_eq!(first, second);
        assert!(first.0 <= 50 && first.1 >= 50);
        assert!(first.2 <= 95 && first.3 >= 95);
    }
}
