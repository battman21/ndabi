use std::error::Error;
use std::hint::black_box;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ndabi_postgres_v1::{
    digest_label, memory_replay_store, AuthorityContext, OperationBinding, ReviewGraphBackend,
    ReviewGraphProfile, ServerSession, WireClientSession, REVIEW_GRAPH_OPCODE,
};
use ndabi_protocol::{Authority, Clock, ProtocolError};
use postgres::{Client, NoTls, Row, Statement};

const REVIEW_SQL: &str = "WITH selected AS MATERIALIZED (SELECT id,bucket,owner,score,payload FROM items WHERE id >= $1 AND id < $1 + $2 AND score >= $3 ORDER BY id LIMIT $2) SELECT id,bucket,owner,score,payload,(SUM(score) OVER ())::bigint FROM selected ORDER BY id";
const SELECT_IDS_SQL: &str =
    "SELECT id FROM items WHERE id >= $1 AND id < $1 + $2 ORDER BY id LIMIT $2";
const SELECT_ROWS_SQL: &str = "SELECT id,bucket,owner,score,payload FROM items WHERE id = ANY($1) AND score >= $2 ORDER BY id";
const SUM_SQL: &str =
    "SELECT COALESCE(SUM(score),0)::bigint FROM items WHERE id = ANY($1) AND score >= $2";
const START: i64 = 10;
const COUNT: u32 = 100;
const MINIMUM_SCORE: i32 = 50;
const RESULT_BUDGET: u32 = 14 + COUNT * 84;

struct FixedClock(u64);

impl Clock for FixedClock {
    fn now_unix_us(&self) -> Result<u64, ProtocolError> {
        Ok(self.0)
    }
}

struct NativeFused {
    client: Client,
    statement: Statement,
}

impl NativeFused {
    fn new(mut client: Client) -> Result<Self, Box<dyn Error>> {
        configure_session(&mut client)?;
        let statement = client.prepare(REVIEW_SQL)?;
        Ok(Self { client, statement })
    }

    fn execute(&mut self) -> Result<Vec<u8>, Box<dyn Error>> {
        let count = i64::from(COUNT);
        let rows = self
            .client
            .query(&self.statement, &[&START, &count, &MINIMUM_SCORE])?;
        encode_fused_rows(&rows).map_err(Into::into)
    }
}

struct NativeSequential {
    client: Client,
    select_ids: Statement,
    select_rows: Statement,
    sum: Statement,
}

impl NativeSequential {
    fn new(mut client: Client) -> Result<Self, Box<dyn Error>> {
        configure_session(&mut client)?;
        let select_ids = client.prepare(SELECT_IDS_SQL)?;
        let select_rows = client.prepare(SELECT_ROWS_SQL)?;
        let sum = client.prepare(SUM_SQL)?;
        Ok(Self {
            client,
            select_ids,
            select_rows,
            sum,
        })
    }

    fn execute(&mut self) -> Result<Vec<u8>, Box<dyn Error>> {
        let count = i64::from(COUNT);
        let ids = self
            .client
            .query(&self.select_ids, &[&START, &count])?
            .into_iter()
            .map(|row| row.try_get(0))
            .collect::<Result<Vec<i64>, _>>()?;
        let rows = self
            .client
            .query(&self.select_rows, &[&ids, &MINIMUM_SCORE])?;
        let score_sum: i64 = self
            .client
            .query_one(&self.sum, &[&ids, &MINIMUM_SCORE])?
            .try_get(0)?;
        encode_rows(&rows, score_sum).map_err(Into::into)
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let connection = std::env::args()
        .nth(1)
        .ok_or("a PostgreSQL reader connection is required")?;
    let iterations = std::env::args()
        .nth(2)
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(1_000);
    let warmup = std::env::args()
        .nth(3)
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(100);
    if iterations < 100 || warmup == 0 {
        return Err("use at least 100 iterations and one warm-up".into());
    }

    let profile = ReviewGraphProfile::new(
        REVIEW_SQL,
        OperationBinding::new(71, 73).map_err(boxed_protocol)?,
    )
    .map_err(boxed_protocol)?;
    let registry = profile
        .graph_registry(
            digest_label(b"schema", b"items-v1"),
            digest_label(b"policy", b"read-only-v1"),
        )
        .map_err(boxed_protocol)?;
    let context = AuthorityContext::new(
        [1; 16],
        [2; 16],
        79,
        digest_label(b"capability", b"review-v1"),
        registry.identity(),
    )
    .map_err(boxed_protocol)?;
    let now = unix_us()?;
    let deadline = now.checked_add(3_600_000_000).ok_or("deadline overflow")?;
    let authority =
        Authority::new_read([3; 32], 83, 89, deadline, context).map_err(boxed_protocol)?;
    let parameters = profile
        .parameters(START, COUNT, MINIMUM_SCORE)
        .map_err(boxed_protocol)?;
    let operation = profile.operation().map_err(boxed_protocol)?;
    let mut wire_client = WireClientSession::new(authority.clone());
    let server = ServerSession::new(authority, RESULT_BUDGET, COUNT).map_err(boxed_protocol)?;
    let graph_client = Client::connect(&connection, NoTls)?;
    let mut graph_backend =
        ReviewGraphBackend::new_registered(graph_client, profile, &registry, 5_000)
            .map_err(boxed_protocol)?;
    let mut replay = memory_replay_store();
    let clock = FixedClock(now);
    let mut native_fused = NativeFused::new(Client::connect(&connection, NoTls)?)?;
    let mut native_sequential = NativeSequential::new(Client::connect(&connection, NoTls)?)?;

    for _ in 0..warmup {
        let expected = native_fused.execute()?;
        let sequential = native_sequential.execute()?;
        let frame = wire_client
            .encode_graph(operation, &parameters, RESULT_BUDGET, COUNT, deadline)
            .map_err(boxed_protocol)?;
        let graph = server
            .execute_graph(&frame, &mut graph_backend, &mut replay, &clock)
            .map_err(boxed_protocol)?;
        wire_client
            .verify_execution_receipt(&frame, graph.rows, &graph.bytes, &graph.receipt)
            .map_err(boxed_protocol)?;
        if expected != sequential || expected != graph.bytes {
            return Err("warm-up result equality failed".into());
        }
        black_box(graph.receipt);
    }

    let mut fused_ns = Vec::with_capacity(iterations);
    let mut sequential_ns = Vec::with_capacity(iterations);
    let mut graph_ns = Vec::with_capacity(iterations);
    for iteration in 0..iterations {
        let mut outputs = [Vec::new(), Vec::new(), Vec::new()];
        for offset in 0..3 {
            let arm = (iteration + offset) % 3;
            let started = Instant::now();
            match arm {
                0 => outputs[0] = native_fused.execute()?,
                1 => outputs[1] = native_sequential.execute()?,
                2 => {
                    let frame = wire_client
                        .encode_graph(operation, &parameters, RESULT_BUDGET, COUNT, deadline)
                        .map_err(boxed_protocol)?;
                    let execution = server
                        .execute_graph(&frame, &mut graph_backend, &mut replay, &clock)
                        .map_err(boxed_protocol)?;
                    wire_client
                        .verify_execution_receipt(
                            &frame,
                            execution.rows,
                            &execution.bytes,
                            &execution.receipt,
                        )
                        .map_err(boxed_protocol)?;
                    black_box(execution.receipt);
                    outputs[2] = execution.bytes;
                }
                _ => unreachable!(),
            }
            let elapsed = duration_ns(started.elapsed())?;
            match arm {
                0 => fused_ns.push(elapsed),
                1 => sequential_ns.push(elapsed),
                2 => graph_ns.push(elapsed),
                _ => unreachable!(),
            }
        }
        if outputs[0] != outputs[1] || outputs[0] != outputs[2] {
            return Err(format!("result equality failed at iteration {iteration}").into());
        }
        black_box(outputs);
    }

    let fused = Summary::new(&mut fused_ns)?;
    let sequential = Summary::new(&mut sequential_ns)?;
    let graph = Summary::new(&mut graph_ns)?;
    println!(
        concat!(
            "{{\n",
            "  \"schema\": \"ndabi-postgresql-review-graph-showdown-v0.1\",\n",
            "  \"iterations\": {},\n",
            "  \"warmup\": {},\n",
            "  \"request_bytes\": {},\n",
            "  \"result_bytes\": {},\n",
            "  \"data_queries\": {{\"fused_native\": 1, \"sequential_native\": 3, \"ndabi_graph\": 1}},\n",
            "  \"fused_native\": {},\n",
            "  \"sequential_native\": {},\n",
            "  \"ndabi_graph\": {},\n",
            "  \"ndabi_vs_fused_p95_ratio\": {:.6},\n",
            "  \"sequential_vs_ndabi_p95_speedup\": {:.6},\n",
            "  \"exact_results\": true,\n",
            "  \"receipt_verified\": true\n",
            "}}"
        ),
        iterations,
        warmup,
        ndabi_protocol::graph_frame_bytes(parameters.len()).map_err(boxed_protocol)?,
        14 + 60 * 84,
        fused.json(),
        sequential.json(),
        graph.json(),
        graph.p95_ns as f64 / fused.p95_ns as f64,
        sequential.p95_ns as f64 / graph.p95_ns as f64,
    );
    Ok(())
}

fn configure_session(client: &mut Client) -> Result<(), Box<dyn Error>> {
    client.batch_execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")?;
    client.query_one(
        "SELECT set_config('statement_timeout', $1, false)",
        &[&"5000ms"],
    )?;
    Ok(())
}

fn encode_fused_rows(rows: &[Row]) -> Result<Vec<u8>, ProtocolError> {
    let score_sum = rows.first().map_or(Ok(0_i64), |row| {
        row.try_get(5).map_err(|_| ProtocolError::BackendRefused)
    })?;
    for row in rows {
        let candidate: i64 = row.try_get(5).map_err(|_| ProtocolError::BackendRefused)?;
        if candidate != score_sum {
            return Err(ProtocolError::BackendRefused);
        }
    }
    encode_rows(rows, score_sum)
}

fn encode_rows(rows: &[Row], score_sum: i64) -> Result<Vec<u8>, ProtocolError> {
    let row_count = u32::try_from(rows.len()).map_err(|_| ProtocolError::RowBudgetExceeded)?;
    let mut output = Vec::with_capacity(14 + rows.len() * 84);
    output.extend_from_slice(&REVIEW_GRAPH_OPCODE.to_le_bytes());
    output.extend_from_slice(&row_count.to_le_bytes());
    output.extend_from_slice(&score_sum.to_le_bytes());
    let mut previous = None;
    for row in rows {
        let id: i64 = row.try_get(0).map_err(|_| ProtocolError::BackendRefused)?;
        let bucket: i32 = row.try_get(1).map_err(|_| ProtocolError::BackendRefused)?;
        let owner: i32 = row.try_get(2).map_err(|_| ProtocolError::BackendRefused)?;
        let score: i32 = row.try_get(3).map_err(|_| ProtocolError::BackendRefused)?;
        let payload: Vec<u8> = row.try_get(4).map_err(|_| ProtocolError::BackendRefused)?;
        if payload.len() != 64 || previous.is_some_and(|value| value >= id) {
            return Err(ProtocolError::BackendRefused);
        }
        output.extend_from_slice(&id.to_le_bytes());
        output.extend_from_slice(&bucket.to_le_bytes());
        output.extend_from_slice(&owner.to_le_bytes());
        output.extend_from_slice(&score.to_le_bytes());
        output.extend_from_slice(&payload);
        previous = Some(id);
    }
    Ok(output)
}

struct Summary {
    mean_ns: u64,
    p50_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
}

impl Summary {
    fn new(values: &mut [u64]) -> Result<Self, Box<dyn Error>> {
        if values.is_empty() {
            return Err("an empty timing sample is invalid".into());
        }
        values.sort_unstable();
        let total = values
            .iter()
            .try_fold(0_u128, |sum, value| sum.checked_add(u128::from(*value)));
        let mean_ns = u64::try_from(total.ok_or("timing sum overflow")? / values.len() as u128)?;
        Ok(Self {
            mean_ns,
            p50_ns: percentile(values, 50),
            p95_ns: percentile(values, 95),
            p99_ns: percentile(values, 99),
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

fn boxed_protocol(error: ProtocolError) -> Box<dyn Error> {
    Box::new(error)
}
