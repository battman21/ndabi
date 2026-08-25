use std::cell::Cell;
use std::hint::black_box;
use std::time::Instant;

use ndabi_protocol::{
    digest_label, Authority, AuthorityContext, Backend, BackendIdentity, BoundedOutput,
    CapabilityManifest, ClientSession, ExecutionLimits, MemoryReplayStore, Operation, PlanRegistry,
    ProtocolError, RegisteredBackend, RegisteredPlan, ServerSession, CAPABILITY_QUERY,
};
use ndabi_showdown::alloc::{begin_measurement, end_measurement, CountingAllocator};
use serde::Serialize;

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

const ROUNDS: usize = 31;
const OPERATIONS_PER_ROUND: usize = 5_000;
const NOW: u64 = 1_000_000;
const DEADLINE: u64 = 2_000_000;
const AUTHORITY_EXPIRY: u64 = 3_000_000;
const MAXIMUM_REGISTRY_RATIO: f64 = 1.10;
const MAXIMUM_WALL_CPU_RATIO: f64 = 1.10;
const MINIMUM_QUALIFIED_ROUNDS: usize = 25;

#[derive(Clone, Copy)]
struct FixedClock;

impl ndabi_protocol::Clock for FixedClock {
    fn now_unix_us(&self) -> Result<u64, ProtocolError> {
        Ok(NOW)
    }
}

struct FixedBackend {
    identity: BackendIdentity,
    operation: Operation,
    calls: Cell<u64>,
}

impl Backend for FixedBackend {
    fn identity(&self) -> BackendIdentity {
        self.identity
    }

    fn execute(
        &mut self,
        operation: Operation,
        _limits: ExecutionLimits,
        output: &mut BoundedOutput,
    ) -> Result<(), ProtocolError> {
        if operation != self.operation {
            return Err(ProtocolError::BackendRefused);
        }
        self.calls.set(self.calls.get().saturating_add(1));
        output.write(&operation.first.to_le_bytes())?;
        output.complete_row()
    }
}

#[derive(Clone, Copy, Serialize)]
struct RoundMeasurement {
    wall_ns_per_operation: f64,
    cpu_ns_per_operation: f64,
    allocations_per_operation: f64,
    allocated_bytes_per_operation: f64,
}

#[derive(Serialize)]
struct ArmSummary {
    rounds: usize,
    operations_per_round: usize,
    median_wall_ns_per_operation: f64,
    p95_wall_ns_per_operation: f64,
    median_cpu_ns_per_operation: f64,
    p95_cpu_ns_per_operation: f64,
    median_allocations_per_operation: f64,
    median_allocated_bytes_per_operation: f64,
}

#[derive(Serialize)]
struct Report {
    schema: &'static str,
    mode: &'static str,
    qualified_rounds: usize,
    discarded_rounds: usize,
    direct: ArmSummary,
    registered: ArmSummary,
    median_wall_ratio: f64,
    p95_wall_ratio: f64,
    median_cpu_ratio: f64,
    p95_cpu_ratio: f64,
    allocation_ratio: f64,
    allocated_byte_ratio: f64,
    maximum_registry_ratio: f64,
    maximum_wall_cpu_ratio: f64,
    hard_gate_passed: bool,
    caveats: [&'static str; 3],
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mode = std::env::args().nth(1);
    let qualified = match mode.as_deref() {
        None => false,
        Some("--qualified" | "--qualified-v03") => true,
        Some(_) => return Err("use no argument, --qualified, or --qualified-v03".into()),
    };
    let operation = Operation::new(1, 2, 3, 4, 5, 6)?;
    let registry = registry()?;
    let authority = authority(&registry)?;
    let frames = frames(&authority, operation)?;
    warm(&registry, &authority, operation, &frames[..1_000])?;

    let mut direct = Vec::with_capacity(ROUNDS);
    let mut registered = Vec::with_capacity(ROUNDS);
    for round in 0..ROUNDS {
        if round % 2 == 0 {
            direct.push(measure_direct(&authority, operation, &frames)?);
            registered.push(measure_registered(
                &registry, &authority, operation, &frames,
            )?);
        } else {
            registered.push(measure_registered(
                &registry, &authority, operation, &frames,
            )?);
            direct.push(measure_direct(&authority, operation, &frames)?);
        }
    }

    let total_rounds = direct.len();
    let (direct, registered): (Vec<_>, Vec<_>) = direct
        .into_iter()
        .zip(registered)
        .filter(|(direct, registered)| {
            !qualified
                || (wall_cpu_ratio(*direct) <= MAXIMUM_WALL_CPU_RATIO
                    && wall_cpu_ratio(*registered) <= MAXIMUM_WALL_CPU_RATIO)
        })
        .unzip();
    let qualified_rounds = direct.len();
    let discarded_rounds = total_rounds - qualified_rounds;
    if direct.is_empty() {
        return Err("the registry campaign retained no qualified round".into());
    }
    let direct = summarise(direct);
    let registered = summarise(registered);
    let median_wall_ratio = ratio(
        registered.median_wall_ns_per_operation,
        direct.median_wall_ns_per_operation,
    );
    let p95_wall_ratio = ratio(
        registered.p95_wall_ns_per_operation,
        direct.p95_wall_ns_per_operation,
    );
    let median_cpu_ratio = ratio(
        registered.median_cpu_ns_per_operation,
        direct.median_cpu_ns_per_operation,
    );
    let p95_cpu_ratio = ratio(
        registered.p95_cpu_ns_per_operation,
        direct.p95_cpu_ns_per_operation,
    );
    let allocation_ratio = ratio(
        registered.median_allocations_per_operation,
        direct.median_allocations_per_operation,
    );
    let allocated_byte_ratio = ratio(
        registered.median_allocated_bytes_per_operation,
        direct.median_allocated_bytes_per_operation,
    );
    let hard_gate_passed = median_wall_ratio <= MAXIMUM_REGISTRY_RATIO
        && p95_wall_ratio <= MAXIMUM_REGISTRY_RATIO
        && median_cpu_ratio <= MAXIMUM_REGISTRY_RATIO
        && p95_cpu_ratio <= MAXIMUM_REGISTRY_RATIO
        && allocation_ratio <= 1.0
        && allocated_byte_ratio <= 1.0
        && (!qualified || qualified_rounds >= MINIMUM_QUALIFIED_ROUNDS);
    let report = Report {
        schema: match mode.as_deref() {
            Some("--qualified-v03") => "ndabi.registry.incremental-cost.v0.3",
            Some("--qualified") => "ndabi.registry.incremental-cost.v0.2",
            _ => "ndabi.registry.incremental-cost.v0.1",
        },
        mode: match mode.as_deref() {
            Some("--qualified-v03") => "qualified-single-plan-fast-path",
            Some("--qualified") => "qualified",
            _ => "unqualified",
        },
        qualified_rounds,
        discarded_rounds,
        direct,
        registered,
        median_wall_ratio,
        p95_wall_ratio,
        median_cpu_ratio,
        p95_cpu_ratio,
        allocation_ratio,
        allocated_byte_ratio,
        maximum_registry_ratio: MAXIMUM_REGISTRY_RATIO,
        maximum_wall_cpu_ratio: MAXIMUM_WALL_CPU_RATIO,
        hard_gate_passed,
        caveats: [
            "This campaign measures one local fixed backend.",
            "It excludes database, network, and production custody costs.",
            "It measures Rust allocations through the process allocator.",
        ],
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    if hard_gate_passed {
        Ok(())
    } else {
        Err("the sealed registry exceeded its frozen incremental-cost gate".into())
    }
}

fn registry() -> Result<PlanRegistry, ProtocolError> {
    let plan = RegisteredPlan::new_read(
        1,
        2,
        3,
        1,
        64,
        4,
        CAPABILITY_QUERY,
        digest_label(b"parameters", b"first:i64,second:i64,third:u32"),
        digest_label(b"implementation", b"fixed-backend-v1"),
    )?;
    PlanRegistry::new(
        7,
        8,
        digest_label(b"schema", b"fixed-schema-v1"),
        digest_label(b"policy", b"fixed-policy-v1"),
        CapabilityManifest::new(CAPABILITY_QUERY)?,
        [plan],
    )
}

fn authority(registry: &PlanRegistry) -> Result<Authority, ProtocolError> {
    let context = AuthorityContext::new(
        [9; 16],
        [10; 16],
        11,
        digest_label(b"capability", b"read-fixed"),
        registry.identity(),
    )?;
    Authority::new_read([12; 32], 13, 14, AUTHORITY_EXPIRY, context)
}

fn frames(
    authority: &Authority,
    operation: Operation,
) -> Result<Vec<[u8; ndabi_protocol::FRAME_BYTES]>, ProtocolError> {
    let mut client = ClientSession::new(authority.clone());
    (0..OPERATIONS_PER_ROUND)
        .map(|_| client.encode(operation, 64, 4, DEADLINE))
        .collect()
}

fn warm(
    registry: &PlanRegistry,
    authority: &Authority,
    operation: Operation,
    frames: &[[u8; ndabi_protocol::FRAME_BYTES]],
) -> Result<(), ProtocolError> {
    measure_direct(authority, operation, frames)?;
    measure_registered(registry, authority, operation, frames)?;
    Ok(())
}

fn measure_direct(
    authority: &Authority,
    operation: Operation,
    frames: &[[u8; ndabi_protocol::FRAME_BYTES]],
) -> Result<RoundMeasurement, ProtocolError> {
    let mut backend = FixedBackend {
        identity: authority_backend(authority, operation)?,
        operation,
        calls: Cell::new(0),
    };
    measure(authority, frames, &mut backend)
}

fn measure_registered(
    registry: &PlanRegistry,
    authority: &Authority,
    operation: Operation,
    frames: &[[u8; ndabi_protocol::FRAME_BYTES]],
) -> Result<RoundMeasurement, ProtocolError> {
    let backend = FixedBackend {
        identity: registry.identity(),
        operation,
        calls: Cell::new(0),
    };
    let mut backend = RegisteredBackend::new(registry, backend)?;
    measure(authority, frames, &mut backend)
}

fn authority_backend(
    _authority: &Authority,
    _operation: Operation,
) -> Result<BackendIdentity, ProtocolError> {
    Ok(registry()?.identity())
}

fn measure<B: Backend>(
    authority: &Authority,
    frames: &[[u8; ndabi_protocol::FRAME_BYTES]],
    backend: &mut B,
) -> Result<RoundMeasurement, ProtocolError> {
    let server = ServerSession::new(authority.clone(), 64, 4)?;
    let mut replay = MemoryReplayStore::default();
    let allocation_start = begin_measurement();
    let cpu_start = thread_cpu_ns()?;
    let wall_start = Instant::now();
    let mut digest = 0_u8;
    for frame in frames {
        let execution = server.execute(frame, backend, &mut replay, &FixedClock)?;
        digest ^= execution.bytes[0];
        black_box(&execution.receipt);
    }
    let wall_ns = wall_start.elapsed().as_nanos() as f64;
    let cpu_ns = thread_cpu_ns()?.saturating_sub(cpu_start) as f64;
    let allocations = end_measurement(allocation_start);
    black_box(digest);
    let operations = frames.len() as f64;
    Ok(RoundMeasurement {
        wall_ns_per_operation: wall_ns / operations,
        cpu_ns_per_operation: cpu_ns / operations,
        allocations_per_operation: allocations.allocations as f64 / operations,
        allocated_bytes_per_operation: allocations.allocated_bytes as f64 / operations,
    })
}

fn summarise(samples: Vec<RoundMeasurement>) -> ArmSummary {
    ArmSummary {
        rounds: samples.len(),
        operations_per_round: OPERATIONS_PER_ROUND,
        median_wall_ns_per_operation: percentile(
            &samples,
            |sample| sample.wall_ns_per_operation,
            0.50,
        ),
        p95_wall_ns_per_operation: percentile(
            &samples,
            |sample| sample.wall_ns_per_operation,
            0.95,
        ),
        median_cpu_ns_per_operation: percentile(
            &samples,
            |sample| sample.cpu_ns_per_operation,
            0.50,
        ),
        p95_cpu_ns_per_operation: percentile(&samples, |sample| sample.cpu_ns_per_operation, 0.95),
        median_allocations_per_operation: percentile(
            &samples,
            |sample| sample.allocations_per_operation,
            0.50,
        ),
        median_allocated_bytes_per_operation: percentile(
            &samples,
            |sample| sample.allocated_bytes_per_operation,
            0.50,
        ),
    }
}

fn percentile(
    samples: &[RoundMeasurement],
    field: impl Fn(&RoundMeasurement) -> f64,
    percentile: f64,
) -> f64 {
    let mut values = samples.iter().map(field).collect::<Vec<_>>();
    values.sort_by(f64::total_cmp);
    let index = ((values.len() - 1) as f64 * percentile).ceil() as usize;
    values[index]
}

fn ratio(candidate: f64, control: f64) -> f64 {
    if control == 0.0 {
        if candidate == 0.0 {
            1.0
        } else {
            f64::INFINITY
        }
    } else {
        candidate / control
    }
}

fn wall_cpu_ratio(measurement: RoundMeasurement) -> f64 {
    ratio(
        measurement.wall_ns_per_operation,
        measurement.cpu_ns_per_operation,
    )
}

fn thread_cpu_ns() -> Result<u64, ProtocolError> {
    let mut timespec = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut timespec) } != 0
        || timespec.tv_sec < 0
        || timespec.tv_nsec < 0
    {
        return Err(ProtocolError::ClockFailed);
    }
    let seconds = u64::try_from(timespec.tv_sec).map_err(|_| ProtocolError::ClockFailed)?;
    let nanoseconds = u64::try_from(timespec.tv_nsec).map_err(|_| ProtocolError::ClockFailed)?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(ProtocolError::ClockFailed)
}
