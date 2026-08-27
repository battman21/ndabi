use std::error::Error;
use std::fmt::Write as _;
use std::hint::black_box;
use std::io::{BufRead, Write as IoWrite};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(feature = "allocation-counting")]
use std::alloc::{GlobalAlloc, Layout, System};
#[cfg(feature = "allocation-counting")]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use ndabi_postgres_v1::{
    digest_label, single_session_replay_store, AuthorityContext, OperationBinding,
    ReviewBatchGraphBackend, ReviewBatchGraphProfile, ReviewBatchItem, ServerSession,
    WireClientSession, REVIEW_BATCH_GRAPH_OPCODE,
};
use ndabi_protocol::{Authority, Clock, ProtocolError};
use postgres::{Client, NoTls, Row, Statement};

const REVIEW_BATCH_SQL: &str = "WITH inputs AS (SELECT start_id,item_count,minimum_score,ordinality::bigint AS ordinal FROM unnest($1::bigint[],$2::bigint[],$3::integer[]) WITH ORDINALITY AS input(start_id,item_count,minimum_score,ordinality)) SELECT ordinal,selected.row_count,selected.score_sum FROM inputs CROSS JOIN LATERAL (SELECT COUNT(*)::bigint AS row_count,COALESCE(SUM(score),0)::bigint AS score_sum FROM (SELECT score FROM items WHERE id >= inputs.start_id AND id < inputs.start_id + inputs.item_count AND score >= inputs.minimum_score ORDER BY id LIMIT inputs.item_count) AS bounded) AS selected ORDER BY ordinal";
const REVIEW_ONE_SQL: &str = "SELECT COUNT(*)::bigint,COALESCE(SUM(score),0)::bigint FROM (SELECT score FROM items WHERE id >= $1 AND id < $1 + $2 AND score >= $3 ORDER BY id LIMIT $2) AS bounded";
type ReviewInput = (i64, u32, i32);

#[derive(Clone, Copy)]
enum MeasuredArm {
    RepeatedNative,
    FusedNative,
    NdabiGraph,
}

impl MeasuredArm {
    fn parse(value: &str) -> Result<Self, Box<dyn Error>> {
        match value {
            "repeated_native" => Ok(Self::RepeatedNative),
            "fused_native" => Ok(Self::FusedNative),
            "ndabi_graph" => Ok(Self::NdabiGraph),
            _ => Err("the measured arm is invalid".into()),
        }
    }

    fn index(self) -> usize {
        match self {
            Self::RepeatedNative => 0,
            Self::FusedNative => 1,
            Self::NdabiGraph => 2,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::RepeatedNative => "repeated_native",
            Self::FusedNative => "fused_native",
            Self::NdabiGraph => "ndabi_graph",
        }
    }
}

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

struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_us(&self) -> Result<u64, ProtocolError> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ProtocolError::ClockFailed)?;
        u64::try_from(elapsed.as_micros()).map_err(|_| ProtocolError::ClockFailed)
    }
}

struct NativeRepeated {
    client: Client,
    statement: Statement,
}

impl NativeRepeated {
    fn new(mut client: Client) -> Result<Self, Box<dyn Error>> {
        configure_session(&mut client)?;
        let statement = client.prepare(REVIEW_ONE_SQL)?;
        Ok(Self { client, statement })
    }

    fn execute(&mut self, inputs: &[ReviewInput]) -> Result<Vec<u8>, Box<dyn Error>> {
        let item_count = u32::try_from(inputs.len())?;
        let mut output = Vec::with_capacity(6 + inputs.len() * 16);
        output.extend_from_slice(&REVIEW_BATCH_GRAPH_OPCODE.to_le_bytes());
        output.extend_from_slice(&item_count.to_le_bytes());
        for (index, (start, count, minimum_score)) in inputs.iter().enumerate() {
            let count_i64 = i64::from(*count);
            let row = self
                .client
                .query_one(&self.statement, &[start, &count_i64, minimum_score])?;
            let rows: i64 = row.try_get(0)?;
            let score_sum: i64 = row.try_get(1)?;
            output.extend_from_slice(&u32::try_from(index + 1)?.to_le_bytes());
            output.extend_from_slice(&u32::try_from(rows)?.to_le_bytes());
            output.extend_from_slice(&score_sum.to_le_bytes());
        }
        Ok(output)
    }
}

struct NativeFused {
    client: Client,
    statement: Statement,
    starts: Vec<i64>,
    counts: Vec<i64>,
    minimum_scores: Vec<i32>,
}

impl NativeFused {
    fn new(mut client: Client, capacity: usize) -> Result<Self, Box<dyn Error>> {
        configure_session(&mut client)?;
        let statement = client.prepare(REVIEW_BATCH_SQL)?;
        Ok(Self {
            client,
            statement,
            starts: Vec::with_capacity(capacity),
            counts: Vec::with_capacity(capacity),
            minimum_scores: Vec::with_capacity(capacity),
        })
    }

    fn execute(&mut self, inputs: &[ReviewInput]) -> Result<Vec<u8>, Box<dyn Error>> {
        self.starts.clear();
        self.counts.clear();
        self.minimum_scores.clear();
        for (start, count, minimum_score) in inputs {
            self.starts.push(*start);
            self.counts.push(i64::from(*count));
            self.minimum_scores.push(*minimum_score);
        }
        let rows = self.client.query(
            &self.statement,
            &[&self.starts, &self.counts, &self.minimum_scores],
        )?;
        encode_fused_rows(&rows)
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
    let connection = arguments
        .get(1)
        .cloned()
        .ok_or("a PostgreSQL reader connection is required")?;
    let item_count = arguments
        .get(2)
        .map(|value| value.parse::<u32>())
        .transpose()?
        .unwrap_or(128);
    let iterations = arguments
        .get(3)
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(100);
    let warmup = arguments
        .get(4)
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(10);
    let mut raw_samples = false;
    let mut coordinated = false;
    let mut measured_arm = None;
    let mut worker_id = 0_u64;
    let mut worker_id_set = false;
    for option in arguments.get(5..).unwrap_or_default() {
        match option.as_str() {
            "--raw" if !raw_samples => raw_samples = true,
            "--coordinated" if !coordinated => coordinated = true,
            value if value.starts_with("--arm=") && measured_arm.is_none() => {
                measured_arm = Some(MeasuredArm::parse(&value[6..])?);
            }
            value if value.starts_with("--worker-id=") && !worker_id_set => {
                worker_id = value[12..].parse()?;
                worker_id_set = true;
            }
            _ => return Err("an unknown or duplicate benchmark option was supplied".into()),
        }
    }
    if coordinated && measured_arm.is_none() {
        return Err("coordinated execution requires one measured arm".into());
    }
    if coordinated && (!worker_id_set || worker_id == 0) {
        return Err("coordinated execution requires a positive worker identifier".into());
    }
    if item_count == 0 || item_count > 1_024 || iterations < 100 || warmup == 0 {
        return Err("use 1 to 1,024 items, at least 100 iterations, and one warm-up".into());
    }

    let inputs = make_inputs(item_count)?;
    let items = inputs
        .iter()
        .map(|(start, count, minimum_score)| {
            ReviewBatchItem::new(*start, *count, *minimum_score).map_err(boxed_protocol)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let profile = ReviewBatchGraphProfile::new(
        REVIEW_BATCH_SQL,
        OperationBinding::new(109, 113).map_err(boxed_protocol)?,
    )
    .map_err(boxed_protocol)?;
    let registry = profile
        .graph_registry(
            digest_label(b"schema", b"items-v1"),
            digest_label(b"policy", b"read-only-v1"),
        )
        .map_err(boxed_protocol)?;
    let context = AuthorityContext::new(
        [11; 16],
        [13; 16],
        127,
        digest_label(b"capability", b"review-batch-v1"),
        registry.identity(),
    )
    .map_err(boxed_protocol)?;
    let now = unix_us()?;
    let deadline = now.checked_add(3_600_000_000).ok_or("deadline overflow")?;
    let session = 131_u64
        .checked_add(worker_id)
        .ok_or("the worker session identifier overflowed")?;
    let mut authority_seed = [17; 32];
    authority_seed[0..8].copy_from_slice(&worker_id.to_le_bytes());
    let authority = Authority::new_read(authority_seed, session, 137, deadline, context)
        .map_err(boxed_protocol)?;
    let parameters = profile.parameters(&items).map_err(boxed_protocol)?;
    let result_budget =
        ReviewBatchGraphProfile::maximum_result_bytes(item_count).map_err(boxed_protocol)?;
    let operation = profile.operation().map_err(boxed_protocol)?;
    let mut wire_client = WireClientSession::new(authority.clone());
    let server =
        ServerSession::new(authority, result_budget, item_count).map_err(boxed_protocol)?;
    let graph_client = Client::connect(&connection, NoTls)?;
    let mut graph_backend =
        ReviewBatchGraphBackend::new_registered(graph_client, profile, &registry, 5_000)
            .map_err(boxed_protocol)?;
    let mut replay = single_session_replay_store();
    let clock = SystemClock;
    let mut native = NativeRepeated::new(Client::connect(&connection, NoTls)?)?;
    let mut fused = NativeFused::new(
        Client::connect(&connection, NoTls)?,
        usize::try_from(item_count)?,
    )?;
    let request_bytes =
        ndabi_protocol::graph_frame_bytes(parameters.len()).map_err(boxed_protocol)?;
    let mut graph_frame = vec![0_u8; request_bytes];
    let mut graph_result = Vec::with_capacity(result_budget as usize);

    for _ in 0..warmup {
        let expected = native.execute(&inputs)?;
        let fused_result = fused.execute(&inputs)?;
        wire_client
            .encode_graph_into(
                operation,
                &parameters,
                result_budget,
                item_count,
                deadline,
                &mut graph_frame,
            )
            .map_err(boxed_protocol)?;
        let graph = server
            .execute_graph_reusing(
                &graph_frame,
                &mut graph_backend,
                &mut replay,
                &clock,
                &mut graph_result,
            )
            .map_err(boxed_protocol)?;
        wire_client
            .verify_execution_receipt(&graph_frame, graph.rows, graph.bytes, &graph.receipt)
            .map_err(boxed_protocol)?;
        if expected != fused_result || expected.as_slice() != graph.bytes {
            return Err("warm-up result equality failed".into());
        }
        black_box(graph.receipt);
    }
    let canonical_result = native.execute(&inputs)?;
    let concise_json_request_bytes = concise_json_request(&graph_frame, &inputs)?.len();
    let request_compression_percent =
        100.0 * (1.0 - request_bytes as f64 / concise_json_request_bytes as f64);

    if coordinated {
        let mut stderr = std::io::stderr().lock();
        stderr.write_all(b"NDABI_WORKER_READY\n")?;
        stderr.flush()?;
        let mut command = String::new();
        std::io::stdin().lock().read_line(&mut command)?;
        if command != "GO\n" {
            return Err("the coordinated start command is invalid".into());
        }
    }

    let mut repeated_ns = Vec::with_capacity(iterations);
    let mut fused_ns = Vec::with_capacity(iterations);
    let mut graph_ns = Vec::with_capacity(iterations);
    let mut repeated_cpu_ns = Vec::with_capacity(iterations);
    let mut fused_cpu_ns = Vec::with_capacity(iterations);
    let mut graph_cpu_ns = Vec::with_capacity(iterations);
    for iteration in 0..iterations {
        let arm_count = if measured_arm.is_some() { 1 } else { 3 };
        for offset in 0..arm_count {
            let arm = measured_arm
                .map(MeasuredArm::index)
                .unwrap_or((iteration + offset) % 3);
            let cpu_started = thread_cpu_ns()?;
            let started = Instant::now();
            let result_matches = match arm {
                0 => native.execute(&inputs)? == canonical_result,
                1 => fused.execute(&inputs)? == canonical_result,
                2 => {
                    wire_client
                        .encode_graph_into(
                            operation,
                            &parameters,
                            result_budget,
                            item_count,
                            deadline,
                            &mut graph_frame,
                        )
                        .map_err(boxed_protocol)?;
                    let execution = server
                        .execute_graph_reusing(
                            &graph_frame,
                            &mut graph_backend,
                            &mut replay,
                            &clock,
                            &mut graph_result,
                        )
                        .map_err(boxed_protocol)?;
                    wire_client
                        .verify_execution_receipt(
                            &graph_frame,
                            execution.rows,
                            execution.bytes,
                            &execution.receipt,
                        )
                        .map_err(boxed_protocol)?;
                    black_box(execution.receipt);
                    execution.bytes == canonical_result
                }
                _ => unreachable!(),
            };
            let elapsed = duration_ns(started.elapsed())?;
            let cpu_elapsed = thread_cpu_ns()?
                .checked_sub(cpu_started)
                .ok_or("thread CPU clock moved backwards")?;
            match arm {
                0 => {
                    repeated_ns.push(elapsed);
                    repeated_cpu_ns.push(cpu_elapsed);
                }
                1 => {
                    fused_ns.push(elapsed);
                    fused_cpu_ns.push(cpu_elapsed);
                }
                2 => {
                    graph_ns.push(elapsed);
                    graph_cpu_ns.push(cpu_elapsed);
                }
                _ => unreachable!(),
            }
            if !result_matches {
                return Err(
                    format!("result equality failed at iteration {iteration}, arm {arm}").into(),
                );
            }
        }
    }

    let repeated_summary = Summary::optional(&repeated_ns)?;
    let fused_summary = Summary::optional(&fused_ns)?;
    let graph_summary = Summary::optional(&graph_ns)?;
    let repeated_cpu = Summary::optional(&repeated_cpu_ns)?;
    let fused_cpu = Summary::optional(&fused_cpu_ns)?;
    let graph_cpu = Summary::optional(&graph_cpu_ns)?;
    let allocation_json = allocation_diagnostics(
        &mut native,
        &mut fused,
        &inputs,
        &canonical_result,
        &mut wire_client,
        operation,
        &parameters,
        result_budget,
        item_count,
        deadline,
        &mut graph_frame,
        &server,
        &mut graph_backend,
        &mut replay,
        &clock,
        &mut graph_result,
    )?;
    let raw_samples_json = if raw_samples {
        format!(
            concat!(
                "{{\"wall_ns\":{{\"repeated_native\":{},\"fused_native\":{},\"ndabi_graph\":{}}},",
                "\"client_thread_cpu_ns\":{{\"repeated_native\":{},\"fused_native\":{},\"ndabi_graph\":{}}}}}"
            ),
            u64_json(&repeated_ns),
            u64_json(&fused_ns),
            u64_json(&graph_ns),
            u64_json(&repeated_cpu_ns),
            u64_json(&fused_cpu_ns),
            u64_json(&graph_cpu_ns),
        )
    } else {
        "null".to_string()
    };
    println!(
        concat!(
            "{{\n",
            "  \"schema\": \"ndabi-postgresql-review-batch-graph-showdown-v0.1\",\n",
            "  \"measured_arm\": \"{}\",\n",
            "  \"coordinated\": {},\n",
            "  \"worker_id\": {},\n",
            "  \"item_count\": {},\n",
            "  \"iterations\": {},\n",
            "  \"warmup\": {},\n",
            "  \"request_bytes\": {},\n",
            "  \"concise_json_request_bytes\": {},\n",
            "  \"request_compression_percent\": {:.6},\n",
            "  \"result_bytes\": {},\n",
            "  \"data_queries_per_workflow\": {{\"repeated_native\": {}, \"fused_native\": 1, \"ndabi_graph\": 1}},\n",
            "  \"repeated_native\": {},\n",
            "  \"fused_native\": {},\n",
            "  \"ndabi_graph\": {},\n",
            "  \"client_thread_cpu\": {{\"repeated_native\": {}, \"fused_native\": {}, \"ndabi_graph\": {}}},\n",
            "  \"allocation_diagnostic\": {},\n",
            "  \"raw_samples\": {},\n",
            "  \"arm_rotation\": \"iteration-plus-offset-modulo-three\",\n",
            "  \"repeated_vs_ndabi_p95_speedup\": {},\n",
            "  \"repeated_vs_ndabi_mean_speedup\": {},\n",
            "  \"ndabi_vs_fused_p95_ratio\": {},\n",
            "  \"ndabi_vs_fused_mean_ratio\": {},\n",
            "  \"exact_results\": true,\n",
            "  \"receipt_verified\": true\n",
            "}}"
        ),
        measured_arm.map(MeasuredArm::name).unwrap_or("all"),
        coordinated,
        worker_id,
        item_count,
        iterations,
        warmup,
        request_bytes,
        concise_json_request_bytes,
        request_compression_percent,
        result_budget,
        item_count,
        optional_summary_json(repeated_summary.as_ref()),
        optional_summary_json(fused_summary.as_ref()),
        optional_summary_json(graph_summary.as_ref()),
        optional_summary_json(repeated_cpu.as_ref()),
        optional_summary_json(fused_cpu.as_ref()),
        optional_summary_json(graph_cpu.as_ref()),
        allocation_json,
        raw_samples_json,
        optional_ratio(
            repeated_summary.as_ref().map(|value| value.p95_ns),
            graph_summary.as_ref().map(|value| value.p95_ns),
        ),
        optional_ratio(
            repeated_summary.as_ref().map(|value| value.mean_ns),
            graph_summary.as_ref().map(|value| value.mean_ns),
        ),
        optional_ratio(
            graph_summary.as_ref().map(|value| value.p95_ns),
            fused_summary.as_ref().map(|value| value.p95_ns),
        ),
        optional_ratio(
            graph_summary.as_ref().map(|value| value.mean_ns),
            fused_summary.as_ref().map(|value| value.mean_ns),
        ),
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[cfg(feature = "allocation-counting")]
fn allocation_diagnostics(
    native: &mut NativeRepeated,
    fused: &mut NativeFused,
    inputs: &[ReviewInput],
    canonical_result: &[u8],
    wire_client: &mut WireClientSession,
    operation: ndabi_protocol::GraphOperation,
    parameters: &[u8],
    result_budget: u32,
    item_count: u32,
    deadline: u64,
    graph_frame: &mut [u8],
    server: &ServerSession,
    graph_backend: &mut ReviewBatchGraphBackend,
    replay: &mut ndabi_protocol::SingleSessionReplayStore,
    clock: &SystemClock,
    graph_result: &mut Vec<u8>,
) -> Result<String, Box<dyn Error>> {
    let repeated = measure_allocations(|| {
        if native.execute(inputs)? != canonical_result {
            return Err("repeated allocation result drift".into());
        }
        Ok(())
    })?;
    let fused = measure_allocations(|| {
        if fused.execute(inputs)? != canonical_result {
            return Err("fused allocation result drift".into());
        }
        Ok(())
    })?;
    let graph = measure_allocations(|| {
        wire_client
            .encode_graph_into(
                operation,
                parameters,
                result_budget,
                item_count,
                deadline,
                graph_frame,
            )
            .map_err(boxed_protocol)?;
        let execution = server
            .execute_graph_reusing(graph_frame, graph_backend, replay, clock, graph_result)
            .map_err(boxed_protocol)?;
        wire_client
            .verify_execution_receipt(
                graph_frame,
                execution.rows,
                execution.bytes,
                &execution.receipt,
            )
            .map_err(boxed_protocol)?;
        if execution.bytes != canonical_result {
            return Err("graph allocation result drift".into());
        }
        Ok(())
    })?;
    Ok(format!(
        "{{\"repeated_native\":{},\"fused_native\":{},\"ndabi_graph\":{}}}",
        repeated.json(),
        fused.json(),
        graph.json(),
    ))
}

#[allow(clippy::too_many_arguments)]
#[cfg(not(feature = "allocation-counting"))]
fn allocation_diagnostics(
    _native: &mut NativeRepeated,
    _fused: &mut NativeFused,
    _inputs: &[ReviewInput],
    _canonical_result: &[u8],
    _wire_client: &mut WireClientSession,
    _operation: ndabi_protocol::GraphOperation,
    _parameters: &[u8],
    _result_budget: u32,
    _item_count: u32,
    _deadline: u64,
    _graph_frame: &mut [u8],
    _server: &ServerSession,
    _graph_backend: &mut ReviewBatchGraphBackend,
    _replay: &mut ndabi_protocol::SingleSessionReplayStore,
    _clock: &SystemClock,
    _graph_result: &mut Vec<u8>,
) -> Result<String, Box<dyn Error>> {
    Ok("null".to_string())
}

fn encode_fused_rows(rows: &[Row]) -> Result<Vec<u8>, Box<dyn Error>> {
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

fn concise_json_request(frame: &[u8], inputs: &[ReviewInput]) -> Result<String, Box<dyn Error>> {
    if frame.len() < 160 {
        return Err("the graph frame is too short for a JSON comparison".into());
    }
    let tag_offset = frame.len() - 32;
    let mut output = format!(
        concat!(
            "{{\"magic\":\"NDAB\",\"version_major\":{},\"version_minor\":{},",
            "\"message\":{},\"access\":{},\"flags\":{},\"opcode\":{},",
            "\"frame_bytes\":{},\"session\":{},\"generation\":{},\"nonce\":{},",
            "\"deadline_unix_us\":{},\"result_budget\":{},\"row_budget\":{},",
            "\"graph_handle\":{},\"result_shape\":{},\"parameter_bytes\":{},",
            "\"context_digest\":\"{}\",\"items\":["
        ),
        frame[4],
        frame[5],
        frame[6],
        frame[7],
        read_u16(frame, 8)?,
        read_u16(frame, 10)?,
        read_u32(frame, 12)?,
        read_u64(frame, 16)?,
        read_u64(frame, 24)?,
        read_u64(frame, 32)?,
        read_u64(frame, 40)?,
        read_u32(frame, 48)?,
        read_u32(frame, 52)?,
        read_u32(frame, 56)?,
        read_u32(frame, 60)?,
        read_u32(frame, 64)?,
        hex(&frame[96..128]),
    );
    for (index, (start, count, minimum_score)) in inputs.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        write!(
            output,
            "{{\"start\":{start},\"count\":{count},\"minimum_score\":{minimum_score}}}"
        )?;
    }
    write!(
        output,
        "],\"authentication_tag\":\"{}\"}}",
        hex(&frame[tag_offset..]),
    )?;
    Ok(output)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, Box<dyn Error>> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or("the u16 field is outside the frame")?
            .try_into()?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, Box<dyn Error>> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or("the u32 field is outside the frame")?
            .try_into()?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, Box<dyn Error>> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or("the u64 field is outside the frame")?
            .try_into()?,
    ))
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(output, "{byte:02x}").expect("a string write cannot fail");
    }
    output
}

fn make_inputs(item_count: u32) -> Result<Vec<ReviewInput>, Box<dyn Error>> {
    (0..item_count)
        .map(|index| {
            let start = 1_i64 + i64::from((index * 7) % 9_000);
            let minimum_score = i32::try_from(start + 32)?;
            Ok((start, 64, minimum_score))
        })
        .collect()
}

fn configure_session(client: &mut Client) -> Result<(), Box<dyn Error>> {
    client.batch_execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")?;
    client.query_one(
        "SELECT set_config('statement_timeout', $1, false)",
        &[&"5000ms"],
    )?;
    Ok(())
}

#[cfg(feature = "allocation-counting")]
struct AllocationSample {
    allocations: u64,
    bytes: u64,
}

#[cfg(feature = "allocation-counting")]
impl AllocationSample {
    fn json(&self) -> String {
        format!(
            "{{\"allocations\":{},\"allocated_bytes\":{}}}",
            self.allocations, self.bytes,
        )
    }
}

#[cfg(feature = "allocation-counting")]
fn measure_allocations(
    work: impl FnOnce() -> Result<(), Box<dyn Error>>,
) -> Result<AllocationSample, Box<dyn Error>> {
    ALLOCATION_COUNT.store(0, Ordering::Relaxed);
    ALLOCATED_BYTES.store(0, Ordering::Relaxed);
    COUNT_ALLOCATIONS.store(true, Ordering::Release);
    let result = work();
    COUNT_ALLOCATIONS.store(false, Ordering::Release);
    let sample = AllocationSample {
        allocations: ALLOCATION_COUNT.load(Ordering::Relaxed),
        bytes: ALLOCATED_BYTES.load(Ordering::Relaxed),
    };
    result?;
    Ok(sample)
}

struct Summary {
    mean_ns: u64,
    p50_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
}

impl Summary {
    fn optional(values: &[u64]) -> Result<Option<Self>, Box<dyn Error>> {
        if values.is_empty() {
            Ok(None)
        } else {
            Self::new(values).map(Some)
        }
    }

    fn new(values: &[u64]) -> Result<Self, Box<dyn Error>> {
        if values.is_empty() {
            return Err("an empty timing sample is invalid".into());
        }
        let mut values = values.to_vec();
        values.sort_unstable();
        let total = values
            .iter()
            .try_fold(0_u128, |sum, value| sum.checked_add(u128::from(*value)));
        let mean_ns = u64::try_from(total.ok_or("timing sum overflow")? / values.len() as u128)?;
        Ok(Self {
            mean_ns,
            p50_ns: percentile(&values, 50),
            p95_ns: percentile(&values, 95),
            p99_ns: percentile(&values, 99),
        })
    }

    fn json(&self) -> String {
        format!(
            "{{\"mean_ns\":{},\"p50_ns\":{},\"p95_ns\":{},\"p99_ns\":{},\"throughput_per_second\":{:.3}}}",
            self.mean_ns,
            self.p50_ns,
            self.p95_ns,
            self.p99_ns,
            1_000_000_000_f64 / self.mean_ns as f64,
        )
    }
}

fn optional_summary_json(summary: Option<&Summary>) -> String {
    summary
        .map(Summary::json)
        .unwrap_or_else(|| "null".to_string())
}

fn optional_ratio(numerator: Option<u64>, denominator: Option<u64>) -> String {
    match (numerator, denominator) {
        (Some(numerator), Some(denominator)) if denominator != 0 => {
            format!("{:.6}", numerator as f64 / denominator as f64)
        }
        _ => "null".to_string(),
    }
}

fn u64_json(values: &[u64]) -> String {
    let mut output = String::with_capacity(values.len() * 12 + 2);
    output.push('[');
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        write!(output, "{value}").expect("a string write cannot fail");
    }
    output.push(']');
    output
}

fn percentile(values: &[u64], percentile: usize) -> u64 {
    let index = (values.len() - 1) * percentile / 100;
    values[index]
}

fn unix_us() -> Result<u64, Box<dyn Error>> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros(),
    )?)
}

fn duration_ns(duration: Duration) -> Result<u64, Box<dyn Error>> {
    Ok(u64::try_from(duration.as_nanos())?)
}

fn thread_cpu_ns() -> Result<u64, Box<dyn Error>> {
    let mut value = std::mem::MaybeUninit::<libc::timespec>::zeroed();
    let result = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, value.as_mut_ptr()) };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let value = unsafe { value.assume_init() };
    let seconds = u64::try_from(value.tv_sec)?;
    let nanoseconds = u64::try_from(value.tv_nsec)?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|total| total.checked_add(nanoseconds))
        .ok_or_else(|| "thread CPU time overflow".into())
}

fn boxed_protocol(error: ProtocolError) -> Box<dyn Error> {
    Box::new(error)
}
