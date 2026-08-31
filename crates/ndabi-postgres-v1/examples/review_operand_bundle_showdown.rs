use std::error::Error;
use std::hint::black_box;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[cfg(feature = "allocation-counting")]
use std::alloc::{GlobalAlloc, Layout, System};
#[cfg(feature = "allocation-counting")]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[cfg(not(target_os = "macos"))]
use std::time::Duration;

use ndabi_postgres_v1::{
    digest_label, single_session_replay_store, AuthorityContext, OperationBinding,
    ReviewBatchGraphBackend, ReviewBatchGraphProfile, ReviewBatchItem, ReviewOperandBundleBackend,
    ReviewOperandBundleProfile, ServerSession, WireClientSession, REVIEW_BATCH_GRAPH_OPCODE,
};
use ndabi_protocol::{Authority, Clock, OperandBundleStore, ProtocolError};
use postgres::{Client, NoTls, Row, Statement};

const REVIEW_BATCH_SQL: &str = "WITH inputs AS (SELECT start_id,item_count,minimum_score,ordinality::bigint AS ordinal FROM unnest($1::bigint[],$2::bigint[],$3::integer[]) WITH ORDINALITY AS input(start_id,item_count,minimum_score,ordinality)) SELECT ordinal,selected.row_count,selected.score_sum FROM inputs CROSS JOIN LATERAL (SELECT COUNT(*)::bigint AS row_count,COALESCE(SUM(score),0)::bigint AS score_sum FROM (SELECT score FROM items WHERE id >= inputs.start_id AND id < inputs.start_id + inputs.item_count AND score >= inputs.minimum_score ORDER BY id LIMIT inputs.item_count) AS bounded) AS selected ORDER BY ordinal";
const VARIANT_COUNT: usize = 16;
type ReviewInput = (i64, u32, i32);
type ReviewVariants = Vec<Vec<ReviewInput>>;

#[cfg(feature = "allocation-counting")]
struct CountingAllocator;

#[cfg(feature = "allocation-counting")]
static COUNT_ALLOCATIONS: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "allocation-counting")]
static ALLOCATION_COUNT: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "allocation-counting")]
static ALLOCATED_BYTES: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "allocation-counting")]
#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

#[cfg(feature = "allocation-counting")]
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        record_allocation(pointer, layout.size());
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        record_allocation(pointer, layout.size());
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_pointer = unsafe { System.realloc(pointer, layout, new_size) };
        record_allocation(new_pointer, new_size);
        new_pointer
    }
}

#[cfg(feature = "allocation-counting")]
fn record_allocation(pointer: *mut u8, bytes: usize) {
    if !pointer.is_null() && COUNT_ALLOCATIONS.load(Ordering::Relaxed) {
        ALLOCATION_COUNT.fetch_add(1, Ordering::Relaxed);
        ALLOCATED_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
    }
}

#[derive(Clone, Copy)]
enum Arm {
    FusedNative,
    NdabiGraph,
    NdabiBundle,
}

impl Arm {
    fn parse(value: &str) -> Result<Self, Box<dyn Error>> {
        match value {
            "fused_native" => Ok(Self::FusedNative),
            "ndabi_graph" => Ok(Self::NdabiGraph),
            "ndabi_bundle" => Ok(Self::NdabiBundle),
            _ => Err("the measured arm is invalid".into()),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::FusedNative => "fused_native",
            Self::NdabiGraph => "ndabi_graph",
            Self::NdabiBundle => "ndabi_bundle",
        }
    }
}

struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_us(&self) -> Result<u64, ProtocolError> {
        unix_us().map_err(|_| ProtocolError::ClockFailed)
    }
}

struct NativeFused {
    client: Client,
    statement: Statement,
    starts: Vec<i64>,
    counts: Vec<i64>,
    thresholds: Vec<i32>,
}

impl NativeFused {
    fn new(mut client: Client, capacity: usize) -> Result<Self, Box<dyn Error>> {
        client.batch_execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")?;
        client.query_one(
            "SELECT set_config('statement_timeout', $1, false)",
            &[&"5000ms"],
        )?;
        let statement = client.prepare(REVIEW_BATCH_SQL)?;
        Ok(Self {
            client,
            statement,
            starts: Vec::with_capacity(capacity),
            counts: Vec::with_capacity(capacity),
            thresholds: Vec::with_capacity(capacity),
        })
    }

    fn execute(&mut self, inputs: &[ReviewInput]) -> Result<Vec<u8>, Box<dyn Error>> {
        self.starts.clear();
        self.counts.clear();
        self.thresholds.clear();
        for (start, count, threshold) in inputs {
            self.starts.push(*start);
            self.counts.push(i64::from(*count));
            self.thresholds.push(*threshold);
        }
        let rows = self.client.query(
            &self.statement,
            &[&self.starts, &self.counts, &self.thresholds],
        )?;
        encode_rows(&rows)
    }
}

#[derive(Clone, Copy)]
struct Summary {
    mean_ns: u64,
    p50_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
}

impl Summary {
    fn new(samples: &[u64]) -> Result<Self, Box<dyn Error>> {
        if samples.is_empty() {
            return Err("the sample set is empty".into());
        }
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        let sum = samples.iter().try_fold(0_u128, |sum, value| {
            sum.checked_add(u128::from(*value))
                .ok_or("sample sum overflow")
        })?;
        Ok(Self {
            mean_ns: u64::try_from(sum / samples.len() as u128)?,
            p50_ns: percentile(&sorted, 50),
            p95_ns: percentile(&sorted, 95),
            p99_ns: percentile(&sorted, 99),
        })
    }

    fn json(self) -> String {
        format!(
            "{{\"mean_ns\":{},\"p50_ns\":{},\"p95_ns\":{},\"p99_ns\":{}}}",
            self.mean_ns, self.p50_ns, self.p95_ns, self.p99_ns
        )
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let arguments = std::env::args().collect::<Vec<_>>();
    let connection = std::env::var("NDABI_TEST_READER_CONNECTION")
        .ok()
        .or_else(|| arguments.get(1).cloned())
        .ok_or("a PostgreSQL reader connection is required")?;
    let arm = Arm::parse(
        arguments
            .get(2)
            .map(String::as_str)
            .unwrap_or("ndabi_bundle"),
    )?;
    let item_count = arguments
        .get(3)
        .map(|value| value.parse::<u32>())
        .transpose()?
        .unwrap_or(1_024);
    let iterations = arguments
        .get(4)
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(4_096);
    let warmup = arguments
        .get(5)
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(64);
    if item_count == 0 || item_count > 1_024 || iterations < 100 || warmup == 0 {
        return Err("use 1 to 1,024 items, at least 100 iterations, and one warm-up".into());
    }

    let variants = make_variants(item_count)?;
    let static_items = variants.first().ok_or("the variants are absent")?;
    let graph_profile = ReviewBatchGraphProfile::new(
        REVIEW_BATCH_SQL,
        OperationBinding::new(109, 113).map_err(boxed_protocol)?,
    )
    .map_err(boxed_protocol)?;
    let graph_registry = graph_profile
        .graph_registry(
            digest_label(b"schema", b"items-v1"),
            digest_label(b"policy", b"read-only-v1"),
        )
        .map_err(boxed_protocol)?;
    let deadline = unix_us()?
        .checked_add(3_600_000_000)
        .ok_or("deadline overflow")?;
    let graph_authority = authority(131, 137, deadline, graph_registry.identity())?;
    let mut graph_client = WireClientSession::new(graph_authority.clone());
    let graph_server = ServerSession::new(graph_authority, result_budget(item_count)?, item_count)
        .map_err(boxed_protocol)?;
    let graph_postgres = Client::connect(&connection, NoTls)?;
    let mut graph_backend = ReviewBatchGraphBackend::new_registered(
        graph_postgres,
        graph_profile,
        &graph_registry,
        5_000,
    )
    .map_err(boxed_protocol)?;
    let mut graph_replay = single_session_replay_store();
    let mut graph_result = Vec::with_capacity(result_budget(item_count)? as usize);
    let graph_parameters = variants
        .iter()
        .map(|inputs| {
            let items = review_items(inputs)?;
            graph_profile.parameters(&items).map_err(boxed_protocol)
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let mut graph_frames = graph_parameters
        .iter()
        .map(|parameters| {
            graph_client
                .prepare_graph_frame(
                    graph_profile.operation().map_err(boxed_protocol)?,
                    parameters,
                    result_budget(item_count)?,
                    item_count,
                )
                .map_err(boxed_protocol)
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;

    let bundle_profile = ReviewOperandBundleProfile::new(
        REVIEW_BATCH_SQL,
        OperationBinding::new(149, 151).map_err(boxed_protocol)?,
    )
    .map_err(boxed_protocol)?;
    let bundle_registry = bundle_profile
        .graph_registry(
            digest_label(b"schema", b"items-v1"),
            digest_label(b"policy", b"read-only-v1"),
        )
        .map_err(boxed_protocol)?;
    let bundle_authority = authority(163, 167, deadline, bundle_registry.identity())?;
    let layout = bundle_profile.operand_layout().map_err(boxed_protocol)?;
    let bundle_items = review_items(static_items)?;
    let bundle = bundle_profile
        .bundle(&bundle_items)
        .map_err(boxed_protocol)?;
    let mut bundle_client = WireClientSession::new(bundle_authority.clone());
    let registration = bundle_client
        .encode_operand_bundle_registration(
            bundle_profile.operation().map_err(boxed_protocol)?,
            &layout,
            173,
            deadline,
            &bundle.operand_values(),
        )
        .map_err(boxed_protocol)?;
    let bundle_server = ServerSession::new(
        bundle_authority.clone(),
        result_budget(item_count)?,
        item_count,
    )
    .map_err(boxed_protocol)?;
    let mut bundle_store =
        OperandBundleStore::new(&bundle_authority, 1, 65_536, 32_768).map_err(boxed_protocol)?;
    let mut bundle_replay = single_session_replay_store();
    let accepted = bundle_server
        .register_operand_bundle(
            &registration,
            &bundle_registry,
            &layout,
            &mut bundle_store,
            &mut bundle_replay,
            &SystemClock,
        )
        .map_err(boxed_protocol)?;
    let bundle_postgres = Client::connect(&connection, NoTls)?;
    let mut bundle_backend = ReviewOperandBundleBackend::new_registered(
        bundle_postgres,
        bundle_profile,
        &bundle_registry,
        5_000,
    )
    .map_err(boxed_protocol)?;
    let thresholds = variants
        .iter()
        .map(|inputs| {
            bundle_profile
                .thresholds(
                    &inputs
                        .iter()
                        .map(|(_, _, threshold)| *threshold)
                        .collect::<Vec<_>>(),
                )
                .map_err(boxed_protocol)
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let mut bundle_frames = thresholds
        .iter()
        .map(|threshold| {
            bundle_client
                .prepare_bundled_graph_frame(
                    bundle_profile.operation().map_err(boxed_protocol)?,
                    &layout,
                    accepted.bundle_handle,
                    &threshold.operand_values(),
                    result_budget(item_count)?,
                    item_count,
                )
                .map_err(boxed_protocol)
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let bundle_request_bytes = bundle_frames[0].as_bytes().len();
    let mut bundle_result = Vec::with_capacity(result_budget(item_count)? as usize);

    let mut native = NativeFused::new(Client::connect(&connection, NoTls)?, item_count as usize)?;
    let expected = variants
        .iter()
        .map(|inputs| native.execute(inputs))
        .collect::<Result<Vec<_>, _>>()?;

    for iteration in 0..warmup {
        execute_arm(
            arm,
            iteration % VARIANT_COUNT,
            &variants,
            &expected,
            &mut native,
            &mut graph_client,
            deadline,
            &mut graph_frames,
            &graph_server,
            &mut graph_backend,
            &mut graph_replay,
            &mut graph_result,
            &mut bundle_client,
            &layout,
            accepted.bundle_digest,
            &mut bundle_frames,
            &bundle_server,
            &bundle_registry,
            &mut bundle_store,
            &mut bundle_backend,
            &mut bundle_replay,
            &mut bundle_result,
        )?;
    }

    let allocation = measure_allocations(|| {
        execute_arm(
            arm,
            0,
            &variants,
            &expected,
            &mut native,
            &mut graph_client,
            deadline,
            &mut graph_frames,
            &graph_server,
            &mut graph_backend,
            &mut graph_replay,
            &mut graph_result,
            &mut bundle_client,
            &layout,
            accepted.bundle_digest,
            &mut bundle_frames,
            &bundle_server,
            &bundle_registry,
            &mut bundle_store,
            &mut bundle_backend,
            &mut bundle_replay,
            &mut bundle_result,
        )
    })?;

    let mut wall = Vec::with_capacity(iterations);
    let mut cpu = Vec::with_capacity(iterations);
    for iteration in 0..iterations {
        let variant = iteration % VARIANT_COUNT;
        let cpu_start = thread_cpu_ns()?;
        let start = Instant::now();
        execute_arm(
            arm,
            variant,
            &variants,
            &expected,
            &mut native,
            &mut graph_client,
            deadline,
            &mut graph_frames,
            &graph_server,
            &mut graph_backend,
            &mut graph_replay,
            &mut graph_result,
            &mut bundle_client,
            &layout,
            accepted.bundle_digest,
            &mut bundle_frames,
            &bundle_server,
            &bundle_registry,
            &mut bundle_store,
            &mut bundle_backend,
            &mut bundle_replay,
            &mut bundle_result,
        )?;
        wall.push(u64::try_from(start.elapsed().as_nanos())?);
        cpu.push(
            thread_cpu_ns()?
                .checked_sub(cpu_start)
                .ok_or("CPU clock moved backwards")?,
        );
    }

    let graph_request_bytes = graph_frames[0].as_bytes().len();
    let request_reduction =
        100.0 * (1.0 - bundle_request_bytes as f64 / graph_request_bytes as f64);
    println!(
        concat!(
            "{{\"schema\":\"ndabi-operand-bundle-showdown-v0.1\",",
            "\"arm\":\"{}\",\"item_count\":{},\"iterations\":{},\"warmup\":{},",
            "\"variant_count\":{},\"registration_bytes\":{},\"graph_request_bytes\":{},",
            "\"bundle_request_bytes\":{},\"request_reduction_percent\":{:.6},",
            "\"wall\":{},\"client_thread_cpu\":{},\"allocation\":{},\"bundle_decodes\":{},",
            "\"bundle_data_queries\":{},\"exact_results\":true,\"receipt_verified\":true}}"
        ),
        arm.name(),
        item_count,
        iterations,
        warmup,
        VARIANT_COUNT,
        registration.len(),
        graph_request_bytes,
        bundle_request_bytes,
        request_reduction,
        Summary::new(&wall)?.json(),
        Summary::new(&cpu)?.json(),
        allocation,
        bundle_backend.bundle_decodes(),
        bundle_backend.data_queries(),
    );
    Ok(())
}

#[cfg(feature = "allocation-counting")]
fn measure_allocations<F>(operation: F) -> Result<String, Box<dyn Error>>
where
    F: FnOnce() -> Result<(), Box<dyn Error>>,
{
    ALLOCATION_COUNT.store(0, Ordering::Relaxed);
    ALLOCATED_BYTES.store(0, Ordering::Relaxed);
    COUNT_ALLOCATIONS.store(true, Ordering::SeqCst);
    let result = operation();
    COUNT_ALLOCATIONS.store(false, Ordering::SeqCst);
    result?;
    Ok(format!(
        "{{\"allocations\":{},\"allocated_bytes\":{}}}",
        ALLOCATION_COUNT.load(Ordering::Relaxed),
        ALLOCATED_BYTES.load(Ordering::Relaxed),
    ))
}

#[cfg(not(feature = "allocation-counting"))]
fn measure_allocations<F>(operation: F) -> Result<String, Box<dyn Error>>
where
    F: FnOnce() -> Result<(), Box<dyn Error>>,
{
    operation()?;
    Ok("null".to_string())
}

#[allow(clippy::too_many_arguments)]
fn execute_arm(
    arm: Arm,
    variant: usize,
    variants: &[Vec<ReviewInput>],
    expected: &[Vec<u8>],
    native: &mut NativeFused,
    graph_client: &mut WireClientSession,
    deadline: u64,
    graph_frames: &mut [ndabi_postgres_v1::PreparedGraphFrame],
    graph_server: &ServerSession,
    graph_backend: &mut ReviewBatchGraphBackend,
    graph_replay: &mut ndabi_protocol::SingleSessionReplayStore,
    graph_result: &mut Vec<u8>,
    bundle_client: &mut WireClientSession,
    layout: &ndabi_protocol::OperandLayout,
    bundle_digest: [u8; 32],
    bundle_frames: &mut [ndabi_postgres_v1::PreparedBundledGraphFrame],
    bundle_server: &ServerSession,
    bundle_registry: &ndabi_protocol::GraphRegistry,
    bundle_store: &mut OperandBundleStore,
    bundle_backend: &mut ReviewOperandBundleBackend,
    bundle_replay: &mut ndabi_protocol::SingleSessionReplayStore,
    bundle_result: &mut Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    let result_matches = match arm {
        Arm::FusedNative => native.execute(&variants[variant])? == expected[variant],
        Arm::NdabiGraph => {
            let frame = graph_client
                .encode_prepared_graph(&mut graph_frames[variant], deadline)
                .map_err(boxed_protocol)?;
            let execution = graph_server
                .execute_graph_reusing(
                    frame,
                    graph_backend,
                    graph_replay,
                    &SystemClock,
                    graph_result,
                )
                .map_err(boxed_protocol)?;
            graph_client
                .verify_execution_receipt(
                    frame,
                    execution.rows,
                    execution.bytes,
                    &execution.receipt,
                )
                .map_err(boxed_protocol)?;
            black_box(execution.receipt);
            execution.bytes == expected[variant]
        }
        Arm::NdabiBundle => {
            let frame = bundle_client
                .encode_prepared_bundled_graph(&mut bundle_frames[variant], deadline)
                .map_err(boxed_protocol)?;
            let execution = bundle_server
                .execute_bundled_graph_reusing(
                    frame,
                    bundle_registry,
                    layout,
                    bundle_store,
                    bundle_backend,
                    bundle_replay,
                    &SystemClock,
                    bundle_result,
                )
                .map_err(boxed_protocol)?;
            bundle_client
                .verify_bundled_execution_receipt(
                    frame,
                    bundle_digest,
                    layout.digest(),
                    execution.rows,
                    execution.bytes,
                    &execution.receipt,
                )
                .map_err(boxed_protocol)?;
            black_box(execution.receipt);
            execution.bytes == expected[variant]
        }
    };
    if !result_matches {
        return Err("the measured result differs from fused native".into());
    }
    Ok(())
}

fn make_variants(item_count: u32) -> Result<ReviewVariants, Box<dyn Error>> {
    (0..VARIANT_COUNT)
        .map(|variant| {
            (0..item_count)
                .map(|index| {
                    let start = 1_i64 + i64::from((index * 7) % 900_000);
                    let threshold = i32::try_from((start + 32 + variant as i64 * 13) % 10_000)?;
                    Ok((start, 64, threshold))
                })
                .collect::<Result<Vec<_>, Box<dyn Error>>>()
        })
        .collect()
}

fn review_items(inputs: &[ReviewInput]) -> Result<Vec<ReviewBatchItem>, Box<dyn Error>> {
    inputs
        .iter()
        .map(|(start, count, threshold)| {
            ReviewBatchItem::new(*start, *count, *threshold).map_err(boxed_protocol)
        })
        .collect()
}

fn authority(
    session: u64,
    generation: u64,
    deadline: u64,
    identity: ndabi_protocol::BackendIdentity,
) -> Result<Authority, Box<dyn Error>> {
    let context = AuthorityContext::new(
        [11; 16],
        [13; 16],
        127,
        digest_label(b"capability", b"review-bundle-showdown-v1"),
        identity,
    )
    .map_err(boxed_protocol)?;
    Authority::new_read([17; 32], session, generation, deadline, context).map_err(boxed_protocol)
}

fn result_budget(item_count: u32) -> Result<u32, Box<dyn Error>> {
    ReviewBatchGraphProfile::maximum_result_bytes(item_count).map_err(boxed_protocol)
}

fn encode_rows(rows: &[Row]) -> Result<Vec<u8>, Box<dyn Error>> {
    let item_count = u32::try_from(rows.len())?;
    let mut output = Vec::with_capacity(6 + rows.len() * 16);
    output.extend_from_slice(&REVIEW_BATCH_GRAPH_OPCODE.to_le_bytes());
    output.extend_from_slice(&item_count.to_le_bytes());
    for row in rows {
        let ordinal: i64 = row.try_get(0)?;
        let row_count: i64 = row.try_get(1)?;
        let score_sum: i64 = row.try_get(2)?;
        output.extend_from_slice(&u32::try_from(ordinal)?.to_le_bytes());
        output.extend_from_slice(&u32::try_from(row_count)?.to_le_bytes());
        output.extend_from_slice(&score_sum.to_le_bytes());
    }
    Ok(output)
}

fn percentile(sorted: &[u64], percentile: usize) -> u64 {
    let index = (sorted.len() * percentile).div_ceil(100).saturating_sub(1);
    sorted[index.min(sorted.len() - 1)]
}

fn unix_us() -> Result<u64, Box<dyn Error>> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros(),
    )?)
}

#[cfg(target_os = "macos")]
fn thread_cpu_ns() -> Result<u64, Box<dyn Error>> {
    unsafe extern "C" {
        fn mach_thread_self() -> u32;
        fn thread_info(target: u32, flavour: u32, info: *mut i32, count: *mut u32) -> i32;
        fn mach_port_deallocate(task: u32, name: u32) -> i32;
        fn mach_task_self() -> u32;
    }
    const THREAD_BASIC_INFO: u32 = 3;
    const THREAD_BASIC_INFO_COUNT: u32 = 10;
    let mut info = [0_i32; THREAD_BASIC_INFO_COUNT as usize];
    let mut count = THREAD_BASIC_INFO_COUNT;
    let thread = unsafe { mach_thread_self() };
    let status = unsafe { thread_info(thread, THREAD_BASIC_INFO, info.as_mut_ptr(), &mut count) };
    let _ = unsafe { mach_port_deallocate(mach_task_self(), thread) };
    if status != 0 || count < THREAD_BASIC_INFO_COUNT {
        return Err("the thread CPU clock failed".into());
    }
    let seconds = u64::try_from(info[0])? + u64::try_from(info[2])?;
    let microseconds = u64::try_from(info[1])? + u64::try_from(info[3])?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(microseconds * 1_000))
        .ok_or_else(|| "the thread CPU clock overflowed".into())
}

#[cfg(not(target_os = "macos"))]
fn thread_cpu_ns() -> Result<u64, Box<dyn Error>> {
    let started = Instant::now();
    std::thread::sleep(Duration::ZERO);
    u64::try_from(started.elapsed().as_nanos()).map_err(Into::into)
}

fn boxed_protocol(error: ProtocolError) -> Box<dyn Error> {
    Box::new(error)
}
