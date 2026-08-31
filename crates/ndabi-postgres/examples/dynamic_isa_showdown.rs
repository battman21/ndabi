use std::error::Error;
use std::hint::black_box;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[cfg(feature = "allocation-counting")]
use std::alloc::{GlobalAlloc, Layout, System};
#[cfg(feature = "allocation-counting")]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use ndabi_isa::{
    capability_digest, verify_operands, verify_program, Comparison, Field, OperandBuilder,
    ParameterDescriptor, ParameterValue, ProgramBuilder, Relation, ScalarType, Schema,
    SortDirection, SortTerm, VerifiedOperands, VerifiedProgram, VerifyLimits,
};
use ndabi_postgres::isa::{
    DynamicPostgresBackend, FieldBinding, PostgresCatalogue, RelationBinding,
};
use ndabi_protocol::{
    digest_label, Authority, AuthorityContext, BackendIdentity, ClientSession, Clock,
    DynamicProgramStore, GovernedDynamicClientSession, MemoryReplayStore, ProtocolError,
    ServerSession,
};
use postgres::{Client, NoTls, Row};

const READ: u64 = 1;
const VARIANT_COUNT: usize = 16;
const RESULT_BUDGET: u32 = 128 * 1024;
const ROW_BUDGET: u32 = 1_024;

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
    GovernedNative,
    DynamicFull,
    DynamicCached,
}

impl Arm {
    fn parse(value: &str) -> Result<Self, Box<dyn Error>> {
        match value {
            "governed_native" => Ok(Self::GovernedNative),
            "dynamic_full" => Ok(Self::DynamicFull),
            "dynamic_cached" => Ok(Self::DynamicCached),
            _ => Err("the measured arm is invalid".into()),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::GovernedNative => "governed_native",
            Self::DynamicFull => "dynamic_full",
            Self::DynamicCached => "dynamic_cached",
        }
    }
}

struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_us(&self) -> Result<u64, ProtocolError> {
        unix_us().map_err(|_| ProtocolError::ClockFailed)
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
                .ok_or("the sample sum overflowed")
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

struct Measurement {
    wall: Summary,
    cpu: Summary,
    allocation: String,
    throughput_ops_s: f64,
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
            .unwrap_or("dynamic_cached"),
    )?;
    let result_rows = arguments
        .get(3)
        .map(|value| value.parse::<u32>())
        .transpose()?
        .unwrap_or(32);
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
    if result_rows == 0 || result_rows > ROW_BUDGET || iterations < 100 || warmup == 0 {
        return Err("use 1 to 1,024 rows, at least 100 iterations, and one warm-up".into());
    }

    let schema = schema()?;
    let program_bytes = program(&schema)?;
    let program = verify_program(&program_bytes, &schema, READ, VerifyLimits::default())?;
    let operand_blocks = operand_blocks(&program, result_rows)?;
    let operands = verified_operands(&operand_blocks, &program)?;
    let expected = expected_results(&connection, &schema, &program, &operands)?;
    let expected_fingerprint = result_fingerprint(&expected);
    let full_request_bytes = request_size(
        &schema,
        &program,
        &operands[0],
        Arm::DynamicFull,
        &connection,
    )?;
    let cached_request_bytes = request_size(
        &schema,
        &program,
        &operands[0],
        Arm::DynamicCached,
        &connection,
    )?;
    let measurement = match arm {
        Arm::GovernedNative => measure_governed(
            &connection,
            &schema,
            &program,
            &operands,
            &expected,
            iterations,
            warmup,
        )?,
        Arm::DynamicFull => measure_full(
            &connection,
            &schema,
            &program,
            &operands,
            &expected,
            iterations,
            warmup,
        )?,
        Arm::DynamicCached => measure_cached(
            &connection,
            &schema,
            &program,
            &operands,
            &expected,
            iterations,
            warmup,
        )?,
    };
    let request_reduction = 100.0 * (1.0 - cached_request_bytes as f64 / full_request_bytes as f64);
    println!(
        concat!(
            "{{\"schema\":\"ndabi-dynamic-isa-showdown-v0.1\",",
            "\"arm\":\"{}\",\"result_rows\":{},\"iterations\":{},\"warmup\":{},",
            "\"variant_count\":{},\"program_bytes\":{},\"full_request_bytes\":{},",
            "\"cached_request_bytes\":{},\"request_reduction_percent\":{:.6},",
            "\"result_fingerprint\":\"{:016x}\",\"wall\":{},",
            "\"client_thread_cpu\":{},\"allocation\":{},\"throughput_ops_s\":{:.6},",
            "\"exact_results\":true,\"receipt_verified\":true}}"
        ),
        arm.name(),
        result_rows,
        iterations,
        warmup,
        VARIANT_COUNT,
        program.bytes().len(),
        full_request_bytes,
        cached_request_bytes,
        request_reduction,
        expected_fingerprint,
        measurement.wall.json(),
        measurement.cpu.json(),
        measurement.allocation,
        measurement.throughput_ops_s,
    );
    Ok(())
}

fn schema() -> Result<Schema, Box<dyn Error>> {
    Ok(Schema::new(vec![Relation::new(
        11,
        READ,
        vec![
            Field::new(101, ScalarType::I64, false, READ)?,
            Field::new(102, ScalarType::Bytes, false, READ)?,
        ],
    )?])?)
}

fn catalogue(schema: &Schema) -> Result<PostgresCatalogue, Box<dyn Error>> {
    Ok(PostgresCatalogue::new(
        schema,
        vec![RelationBinding::new(
            11,
            "public",
            "items",
            vec![
                FieldBinding::new(101, "id")?,
                FieldBinding::new(102, "payload")?,
            ],
        )?],
    )?)
}

fn program(schema: &Schema) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut builder = ProgramBuilder::new(schema.digest(), 16)?;
    let minimum = builder.parameter(ParameterDescriptor::new(ScalarType::I64, 8)?)?;
    let limit = builder.parameter(ParameterDescriptor::new(ScalarType::U64, 8)?)?;
    let scan = builder.scan(11)?;
    let filtered = builder.filter(scan, 101, Comparison::GreaterOrEqual, minimum)?;
    let projected = builder.project(filtered, &[101, 102])?;
    let sorted = builder.sort(
        projected,
        &[SortTerm {
            field: 101,
            direction: SortDirection::Ascending,
        }],
    )?;
    let limited = builder.limit(sorted, limit)?;
    builder.return_result(limited)?;
    Ok(builder.finish()?)
}

fn operand_blocks(
    program: &VerifiedProgram<'_>,
    result_rows: u32,
) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    (0..VARIANT_COUNT)
        .map(|variant| {
            let mut builder = OperandBuilder::new(program);
            builder.push(ParameterValue::I64(1 + variant as i64 * 997))?;
            builder.push(ParameterValue::U64(u64::from(result_rows)))?;
            Ok(builder.finish()?)
        })
        .collect()
}

fn verified_operands<'a>(
    blocks: &'a [Vec<u8>],
    program: &VerifiedProgram<'_>,
) -> Result<Vec<VerifiedOperands<'a>>, Box<dyn Error>> {
    blocks
        .iter()
        .map(|block| verify_operands(block, program).map_err(Into::into))
        .collect()
}

fn backend(
    connection: &str,
    schema: &Schema,
    identity: BackendIdentity,
) -> Result<DynamicPostgresBackend, Box<dyn Error>> {
    Ok(DynamicPostgresBackend::new(
        Client::connect(connection, NoTls)?,
        identity,
        schema.clone(),
        catalogue(schema)?,
        READ,
        [1; 16],
        [2; 16],
    )?)
}

fn authority(schema: &Schema, session: u64, expires: u64) -> Result<Authority, Box<dyn Error>> {
    let identity = BackendIdentity::new(
        41,
        43,
        schema.digest(),
        digest_label(b"policy", b"dynamic-campaign-read-only"),
        digest_label(b"profile", b"dynamic-postgres-v1"),
    )?;
    let context = AuthorityContext::new([1; 16], [2; 16], 3, capability_digest(READ), identity)?;
    Ok(Authority::new_read([4; 32], session, 6, expires, context)?)
}

fn expected_results(
    connection: &str,
    _schema: &Schema,
    program: &VerifiedProgram<'_>,
    operands: &[VerifiedOperands<'_>],
) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let mut client = Client::connect(connection, NoTls)?;
    client.batch_execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")?;
    let statement = client
        .prepare("SELECT id,payload FROM public.items WHERE id >= $1 ORDER BY id ASC LIMIT $2")?;
    operands
        .iter()
        .map(|operand| {
            let ParameterValue::I64(minimum) = operand.value(0)? else {
                return Err("the minimum operand type is invalid".into());
            };
            let ParameterValue::U64(limit) = operand.value(1)? else {
                return Err("the limit operand type is invalid".into());
            };
            let limit = i64::try_from(limit)?;
            let rows = client.query(&statement, &[&minimum, &limit])?;
            native_result(&rows, program.digest())
        })
        .collect()
}

fn native_result(rows: &[Row], program_digest: [u8; 32]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut output = vec![0_u8; 64];
    output[0..4].copy_from_slice(b"NDIR");
    output[4] = 1;
    output[12..16].copy_from_slice(&u32::try_from(rows.len())?.to_le_bytes());
    output[16..18].copy_from_slice(&2_u16.to_le_bytes());
    output[32..64].copy_from_slice(&program_digest);
    for (field, scalar_type) in [(101_u32, ScalarType::I64), (102_u32, ScalarType::Bytes)] {
        output.extend_from_slice(&field.to_le_bytes());
        output.push(scalar_type as u8);
        output.extend_from_slice(&[0; 3]);
    }
    for row in rows {
        let id: i64 = row.try_get(0)?;
        let payload: Vec<u8> = row.try_get(1)?;
        output.push(0b11);
        output.extend_from_slice(&id.to_le_bytes());
        output.extend_from_slice(&u32::try_from(payload.len())?.to_le_bytes());
        output.extend_from_slice(&payload);
    }
    let length = u32::try_from(output.len())?;
    output[8..12].copy_from_slice(&length.to_le_bytes());
    Ok(output)
}

fn request_size(
    schema: &Schema,
    program: &VerifiedProgram<'_>,
    operands: &VerifiedOperands<'_>,
    arm: Arm,
    connection: &str,
) -> Result<usize, Box<dyn Error>> {
    let expires = unix_us()?
        .checked_add(7_200_000_000)
        .ok_or("expiry overflow")?;
    let deadline = expires
        .checked_sub(3_600_000_000)
        .ok_or("deadline underflow")?;
    let authority = authority(schema, 201 + arm as u64, expires)?;
    let mut client = ClientSession::new(authority.clone());
    match arm {
        Arm::DynamicFull => Ok(client
            .encode_dynamic(program, operands, RESULT_BUDGET, ROW_BUDGET, deadline)?
            .len()),
        Arm::DynamicCached => {
            let backend = backend(connection, schema, authority.context().backend())?;
            let server = ServerSession::new(authority, RESULT_BUDGET, ROW_BUDGET)?;
            let mut replay = MemoryReplayStore::default();
            let mut store = DynamicProgramStore::new(16, 4_096, 65_536)?;
            let registration = client.encode_dynamic_program_registration(program, deadline)?;
            let accepted = server.register_dynamic_program(
                &registration,
                &mut store,
                &backend,
                &mut replay,
                &SystemClock,
            )?;
            let handle = client.verify_dynamic_program_accepted(&registration, &accepted)?;
            Ok(client
                .encode_cached_dynamic(handle, operands, RESULT_BUDGET, ROW_BUDGET, deadline)?
                .len())
        }
        Arm::GovernedNative => Ok(0),
    }
}

fn measure_governed(
    connection: &str,
    schema: &Schema,
    program: &VerifiedProgram<'_>,
    operands: &[VerifiedOperands<'_>],
    expected: &[Vec<u8>],
    iterations: usize,
    warmup: usize,
) -> Result<Measurement, Box<dyn Error>> {
    let expires = unix_us()?
        .checked_add(7_200_000_000)
        .ok_or("expiry overflow")?;
    let deadline = expires
        .checked_sub(3_600_000_000)
        .ok_or("deadline underflow")?;
    let authority = authority(schema, 301, expires)?;
    let mut backend = backend(connection, schema, authority.context().backend())?;
    let server = ServerSession::new(authority.clone(), RESULT_BUDGET, ROW_BUDGET)?;
    let mut client = GovernedDynamicClientSession::new(authority);
    let mut replay = MemoryReplayStore::default();
    let requests = (0..iterations + warmup + 1)
        .map(|index| {
            client.prepare(
                program,
                &operands[index % VARIANT_COUNT],
                RESULT_BUDGET,
                ROW_BUDGET,
                deadline,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut index = 0;
    measure(iterations, warmup, expected, |variant| {
        let request = &requests[index];
        index += 1;
        let execution =
            server.execute_governed_dynamic(request, &mut backend, &mut replay, &SystemClock)?;
        client.verify_receipt(
            request,
            execution.rows,
            &execution.bytes,
            &execution.receipt,
        )?;
        black_box(execution.receipt);
        debug_assert_eq!(variant, (index - 1) % VARIANT_COUNT);
        Ok(execution.bytes)
    })
}

fn measure_full(
    connection: &str,
    schema: &Schema,
    program: &VerifiedProgram<'_>,
    operands: &[VerifiedOperands<'_>],
    expected: &[Vec<u8>],
    iterations: usize,
    warmup: usize,
) -> Result<Measurement, Box<dyn Error>> {
    let expires = unix_us()?
        .checked_add(7_200_000_000)
        .ok_or("expiry overflow")?;
    let deadline = expires
        .checked_sub(3_600_000_000)
        .ok_or("deadline underflow")?;
    let authority = authority(schema, 401, expires)?;
    let mut backend = backend(connection, schema, authority.context().backend())?;
    let server = ServerSession::new(authority.clone(), RESULT_BUDGET, ROW_BUDGET)?;
    let mut client = ClientSession::new(authority);
    let mut replay = MemoryReplayStore::default();
    let frames = prepare_full_frames(
        &mut client,
        program,
        operands,
        iterations + warmup + 1,
        deadline,
    )?;
    let mut index = 0;
    measure(iterations, warmup, expected, |variant| {
        let frame = &frames[index];
        index += 1;
        let execution = server.execute_dynamic(frame, &mut backend, &mut replay, &SystemClock)?;
        client.verify_execution_receipt(
            frame,
            execution.rows,
            &execution.bytes,
            &execution.receipt,
        )?;
        black_box(execution.receipt);
        debug_assert_eq!(variant, (index - 1) % VARIANT_COUNT);
        Ok(execution.bytes)
    })
}

fn measure_cached(
    connection: &str,
    schema: &Schema,
    program: &VerifiedProgram<'_>,
    operands: &[VerifiedOperands<'_>],
    expected: &[Vec<u8>],
    iterations: usize,
    warmup: usize,
) -> Result<Measurement, Box<dyn Error>> {
    let expires = unix_us()?
        .checked_add(7_200_000_000)
        .ok_or("expiry overflow")?;
    let deadline = expires
        .checked_sub(3_600_000_000)
        .ok_or("deadline underflow")?;
    let authority = authority(schema, 501, expires)?;
    let mut backend = backend(connection, schema, authority.context().backend())?;
    let server = ServerSession::new(authority.clone(), RESULT_BUDGET, ROW_BUDGET)?;
    let mut client = ClientSession::new(authority);
    let mut replay = MemoryReplayStore::default();
    let mut store = DynamicProgramStore::new(16, 4_096, 65_536)?;
    let registration = client.encode_dynamic_program_registration(program, deadline)?;
    let accepted = server.register_dynamic_program(
        &registration,
        &mut store,
        &backend,
        &mut replay,
        &SystemClock,
    )?;
    let handle = client.verify_dynamic_program_accepted(&registration, &accepted)?;
    let frames = prepare_cached_frames(
        &mut client,
        handle,
        operands,
        iterations + warmup + 1,
        deadline,
    )?;
    let mut index = 0;
    measure(iterations, warmup, expected, |variant| {
        let frame = &frames[index];
        index += 1;
        let execution = server.execute_cached_dynamic(
            frame,
            &mut store,
            &mut backend,
            &mut replay,
            &SystemClock,
        )?;
        client.verify_cached_dynamic_receipt(
            frame,
            execution.rows,
            &execution.bytes,
            &execution.receipt,
        )?;
        black_box(execution.receipt);
        debug_assert_eq!(variant, (index - 1) % VARIANT_COUNT);
        Ok(execution.bytes)
    })
}

fn prepare_full_frames(
    client: &mut ClientSession,
    program: &VerifiedProgram<'_>,
    operands: &[VerifiedOperands<'_>],
    count: usize,
    deadline: u64,
) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    (0..count)
        .map(|index| {
            Ok(client.encode_dynamic(
                program,
                &operands[index % VARIANT_COUNT],
                RESULT_BUDGET,
                ROW_BUDGET,
                deadline,
            )?)
        })
        .collect()
}

fn prepare_cached_frames(
    client: &mut ClientSession,
    handle: ndabi_protocol::VerifiedDynamicProgramHandle,
    operands: &[VerifiedOperands<'_>],
    count: usize,
    deadline: u64,
) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    (0..count)
        .map(|index| {
            Ok(client.encode_cached_dynamic(
                handle,
                &operands[index % VARIANT_COUNT],
                RESULT_BUDGET,
                ROW_BUDGET,
                deadline,
            )?)
        })
        .collect()
}

fn measure<F>(
    iterations: usize,
    warmup: usize,
    expected: &[Vec<u8>],
    mut operation: F,
) -> Result<Measurement, Box<dyn Error>>
where
    F: FnMut(usize) -> Result<Vec<u8>, Box<dyn Error>>,
{
    for index in 0..warmup {
        require_exact(
            operation(index % VARIANT_COUNT)?,
            &expected[index % VARIANT_COUNT],
        )?;
    }
    let allocation = measure_allocations(|| {
        require_exact(
            operation(warmup % VARIANT_COUNT)?,
            &expected[warmup % VARIANT_COUNT],
        )
    })?;
    let mut wall = Vec::with_capacity(iterations);
    let mut cpu = Vec::with_capacity(iterations);
    for index in 0..iterations {
        let variant = (warmup + 1 + index) % VARIANT_COUNT;
        let cpu_start = thread_cpu_ns()?;
        let start = Instant::now();
        require_exact(operation(variant)?, &expected[variant])?;
        wall.push(u64::try_from(start.elapsed().as_nanos())?);
        cpu.push(
            thread_cpu_ns()?
                .checked_sub(cpu_start)
                .ok_or("the CPU clock moved backwards")?,
        );
    }
    let wall_total = wall.iter().try_fold(0_u128, |total, sample| {
        total
            .checked_add(u128::from(*sample))
            .ok_or("the wall sample sum overflowed")
    })?;
    let throughput_ops_s = iterations as f64 * 1_000_000_000.0 / wall_total as f64;
    Ok(Measurement {
        wall: Summary::new(&wall)?,
        cpu: Summary::new(&cpu)?,
        allocation,
        throughput_ops_s,
    })
}

fn require_exact(candidate: Vec<u8>, expected: &[u8]) -> Result<(), Box<dyn Error>> {
    if candidate != expected {
        return Err("the measured result differs from the typed control".into());
    }
    black_box(candidate);
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

fn result_fingerprint(results: &[Vec<u8>]) -> u64 {
    results
        .iter()
        .flatten()
        .fold(0xcbf29ce484222325, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
        })
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

fn thread_cpu_ns() -> Result<u64, Box<dyn Error>> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: The pointer is valid for one writable timespec.
    if unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut value) } != 0
        || value.tv_sec < 0
        || value.tv_nsec < 0
    {
        return Err("the thread CPU clock failed".into());
    }
    let seconds = u64::try_from(value.tv_sec)?;
    let nanoseconds = u64::try_from(value.tv_nsec)?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|total| total.checked_add(nanoseconds))
        .ok_or_else(|| "the thread CPU clock overflowed".into())
}
