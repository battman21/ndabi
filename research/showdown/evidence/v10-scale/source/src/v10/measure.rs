use std::hint::black_box;
use std::time::Instant;

use serde::Serialize;

use crate::alloc::{begin_measurement, end_measurement};

#[derive(Clone, Copy, Debug, Default)]
pub struct Observation {
    pub request_bytes: usize,
    pub response_bytes: usize,
    pub semantic_fingerprint: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct BatchSample {
    pub elapsed_ns: u64,
    pub allocations: u64,
    pub allocated_bytes: u64,
    pub peak_additional_live_bytes: u64,
    pub observation: Observation,
}

#[derive(Clone, Debug, Serialize)]
pub struct Measurement {
    pub id: &'static str,
    pub batches: usize,
    pub operations_per_batch: usize,
    pub operations: u64,
    pub median_batch_ns: u64,
    pub p95_batch_ns: u64,
    pub p99_batch_ns: u64,
    pub median_ns_per_operation: f64,
    pub p95_ns_per_operation: f64,
    pub operations_per_second: f64,
    pub allocations_per_operation: f64,
    pub allocated_bytes_per_operation: f64,
    pub peak_additional_live_bytes: u64,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub semantic_fingerprint: String,
}

pub fn warm<S, F>(
    state: &mut S,
    batches: usize,
    operations_per_batch: usize,
    mut operation: F,
) -> Result<(), String>
where
    F: FnMut(&mut S) -> Result<Observation, String>,
{
    for _ in 0..batches {
        for _ in 0..operations_per_batch {
            black_box(operation(state)?);
        }
    }
    Ok(())
}

pub fn measure_one<S, F>(
    state: &mut S,
    operations_per_batch: usize,
    mut operation: F,
) -> Result<BatchSample, String>
where
    F: FnMut(&mut S) -> Result<Observation, String>,
{
    let allocation_start = begin_measurement();
    let started = Instant::now();
    let mut observation = Observation::default();
    for _ in 0..operations_per_batch {
        observation = operation(state)?;
        black_box(observation);
    }
    let elapsed = started.elapsed();
    let allocations = end_measurement(allocation_start);
    Ok(BatchSample {
        elapsed_ns: u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX),
        allocations: allocations.allocations,
        allocated_bytes: allocations.allocated_bytes,
        peak_additional_live_bytes: allocations.peak_additional_live_bytes,
        observation,
    })
}

pub fn empty_samples(batches: usize, operations_per_batch: usize) -> Vec<u64> {
    let mut samples = Vec::with_capacity(batches);
    let mut value = 1u64;
    for _ in 0..batches {
        let started = Instant::now();
        for index in 0..operations_per_batch {
            value = black_box(value.wrapping_add(index as u64).rotate_left(1));
        }
        samples.push(u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX));
    }
    black_box(value);
    samples
}

pub fn finish(
    id: &'static str,
    operations_per_batch: usize,
    samples: &[BatchSample],
) -> Result<Measurement, String> {
    let first = samples
        .first()
        .ok_or_else(|| "the arm has no measurement batches".to_string())?;
    if samples.iter().any(|sample| {
        sample.observation.request_bytes != first.observation.request_bytes
            || sample.observation.response_bytes != first.observation.response_bytes
            || sample.observation.semantic_fingerprint != first.observation.semantic_fingerprint
    }) {
        return Err("the measured operation identity changed between batches".to_string());
    }
    let mut elapsed = samples
        .iter()
        .map(|sample| sample.elapsed_ns)
        .collect::<Vec<_>>();
    elapsed.sort_unstable();
    let total_ns = elapsed.iter().map(|value| *value as u128).sum::<u128>();
    let operations = samples
        .len()
        .checked_mul(operations_per_batch)
        .ok_or_else(|| "the operation count overflowed".to_string())?;
    let operations_u64 =
        u64::try_from(operations).map_err(|_| "the operation count overflowed".to_string())?;
    let divisor = operations as f64;
    let median_batch_ns = percentile(&elapsed, 0.50);
    let p95_batch_ns = percentile(&elapsed, 0.95);
    Ok(Measurement {
        id,
        batches: samples.len(),
        operations_per_batch,
        operations: operations_u64,
        median_batch_ns,
        p95_batch_ns,
        p99_batch_ns: percentile(&elapsed, 0.99),
        median_ns_per_operation: median_batch_ns as f64 / operations_per_batch as f64,
        p95_ns_per_operation: p95_batch_ns as f64 / operations_per_batch as f64,
        operations_per_second: divisor / (total_ns as f64 / 1_000_000_000.0),
        allocations_per_operation: samples.iter().map(|sample| sample.allocations).sum::<u64>()
            as f64
            / divisor,
        allocated_bytes_per_operation: samples
            .iter()
            .map(|sample| sample.allocated_bytes)
            .sum::<u64>() as f64
            / divisor,
        peak_additional_live_bytes: samples
            .iter()
            .map(|sample| sample.peak_additional_live_bytes)
            .max()
            .unwrap_or(0),
        request_bytes: first.observation.request_bytes as u64,
        response_bytes: first.observation.response_bytes as u64,
        semantic_fingerprint: format!("{:016x}", first.observation.semantic_fingerprint),
    })
}

pub fn percentile(sorted: &[u64], percentile: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let index = ((sorted.len() - 1) as f64 * percentile).ceil() as usize;
    sorted[index]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_timer_covers_the_complete_batch() {
        let mut state = 0u64;
        let sample = measure_one(&mut state, 100, |value| {
            *value += 1;
            Ok(Observation {
                semantic_fingerprint: *value % 2,
                ..Observation::default()
            })
        })
        .expect("measurement");
        assert_eq!(state, 100);
        assert!(sample.elapsed_ns > 0);
    }

    #[test]
    fn percentile_uses_the_upper_observation() {
        assert_eq!(percentile(&[1, 2, 3, 4, 5], 0.95), 5);
    }
}
