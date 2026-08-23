//! Compare one admitted NDABI user session with persistent PostgREST requests.

use std::fmt::Write;
use std::hint::black_box;
use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use ndabi_postgres_v1::{
    digest_label, memory_replay_store, AuthorityContext, OperationBinding, RangeProfile,
    WireClientSession, FRAME_BYTES,
};
use ndabi_protocol::{
    encode_transport, transport_frame_bytes, Authority, BackendIdentity, MemoryReplayStore,
    ProtocolError, ServerSession, SystemClock, TransportConfig, TransportConnection,
    TransportDirection, TransportFields, TransportKind, TransportRole,
};
use ndabi_showdown::alloc::{begin_measurement, end_measurement, AllocationDelta};
use ndabi_supabase_session_v1::SessionUserRangeBackend;
use ndabi_supabase_v1::{AdmittedIdentity, JwtVerifier};
use postgres::{Client, NoTls};
use reqwest::blocking::Client as HttpClient;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[global_allocator]
static GLOBAL: ndabi_showdown::alloc::CountingAllocator = ndabi_showdown::alloc::CountingAllocator;

const SQL: &str =
    "SELECT id,bucket,owner,score,payload FROM supabase_items WHERE id = ANY($1) ORDER BY id";
const COUNTS: [u32; 3] = [1, 32, 128];
const STARTS: [i64; 3] = [1_000, 10_000, 100_000];
const SAMPLES: usize = 63;
const WARMUPS: usize = 7;
const MAXIMUM_FRAME_BYTES: u32 = 32_768;
const MAXIMUM_CHUNK_BYTES: u32 = 16_384;

#[derive(Clone, Copy)]
enum Arm {
    Postgrest = 0,
    Ndabi = 1,
}

impl Arm {
    fn id(self) -> &'static str {
        match self {
            Self::Postgrest => "postgrest-user-jwt",
            Self::Ndabi => "ndabi-dedicated-session",
        }
    }
}

#[derive(Serialize)]
struct Report {
    campaign: &'static str,
    samples: usize,
    warmups: usize,
    jwt_admission_ns: u64,
    session_expires_unix_s: u64,
    identity_digest: String,
    cases: Vec<CaseReport>,
    passed: bool,
}

#[derive(Serialize)]
struct CaseReport {
    rows: u32,
    transport_negotiation_ns: u64,
    ndabi_request_bytes: usize,
    postgrest_request_lower_bound_bytes: usize,
    minimum_request_reduction: f64,
    result_bytes: usize,
    result_sha256: String,
    measurements: Vec<Measurement>,
    ndabi_data_queries: u64,
    expected_data_queries: u64,
    ndabi_postgrest_p50_distance: f64,
    ndabi_postgrest_cpu_distance: f64,
    passed: bool,
}

#[derive(Serialize)]
struct Measurement {
    arm: &'static str,
    p50_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    p50_cpu_ns: u64,
    mean_allocations: f64,
    mean_allocated_bytes: f64,
    peak_additional_live_bytes: u64,
    raw_ns: Vec<u64>,
    raw_cpu_ns: Vec<u64>,
}

#[derive(Deserialize)]
struct RestRow {
    id: i64,
    bucket: i32,
    owner: i32,
    score: i32,
    payload: String,
}

struct Sample {
    wall_ns: u64,
    cpu_ns: u64,
    allocation: AllocationDelta,
}

struct NdabiState {
    authority: Authority,
    profile: RangeProfile,
    wire_client: WireClientSession,
    wire_server: ServerSession,
    transport_client: TransportConnection,
    transport_server: TransportConnection,
    backend: SessionUserRangeBackend,
    replay: MemoryReplayStore,
    result_frame: Vec<u8>,
    transport_negotiation_ns: u64,
}

struct RestState {
    client: HttpClient,
    endpoint: String,
    token: Zeroizing<String>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.first().map(String::as_str) == Some("--admit-only") {
        return admit_only(&arguments[1..]);
    }
    if arguments.first().map(String::as_str) == Some("--ndabi-probe") {
        return ndabi_probe(&arguments[1..]);
    }
    if arguments.len() != 7 {
        return Err(
            "connection, endpoint, token path, public-key path, key identifier, issuer, and audience are required"
                .to_string(),
        );
    }
    let connection = &arguments[0];
    let endpoint = &arguments[1];
    let token = read_secret(&arguments[2])?;
    let public_key = std::fs::read(&arguments[3]).map_err(|_| "the public key cannot be read")?;
    let verifier = JwtVerifier::new_es256(
        &public_key,
        &arguments[4],
        &arguments[5],
        &arguments[6],
        300,
    )
    .map_err(|error| error.to_string())?;
    let admission_started = Instant::now();
    let user = verifier.admit(&token).map_err(|error| error.to_string())?;
    let jwt_admission_ns = elapsed_ns(admission_started)?;
    let profile = profile()?;
    let identity = identity(profile)?;
    let mut cases = Vec::with_capacity(COUNTS.len());
    for (index, rows) in COUNTS.into_iter().enumerate() {
        cases.push(measure_case(
            connection,
            endpoint,
            &token,
            &user,
            profile,
            identity,
            STARTS[index],
            rows,
            index,
        )?);
    }
    let passed = cases.iter().all(|case| case.passed);
    serde_json::to_writer(
        std::io::stdout(),
        &Report {
            campaign: "NDABI Supabase dedicated-session campaign v6.7",
            samples: SAMPLES,
            warmups: WARMUPS,
            jwt_admission_ns,
            session_expires_unix_s: user.session_expires_unix_s(),
            identity_digest: hex(&user.identity_digest()),
            cases,
            passed,
        },
    )
    .map_err(|error| error.to_string())?;
    println!();
    if passed {
        Ok(())
    } else {
        Err("the Supabase dedicated-session performance gate failed".to_string())
    }
}

fn admit_only(arguments: &[String]) -> Result<(), String> {
    if arguments.len() != 5 {
        return Err(
            "token path, public-key path, key identifier, issuer, and audience are required"
                .to_string(),
        );
    }
    let token = read_secret(&arguments[0])?;
    let public_key = std::fs::read(&arguments[1]).map_err(|_| "the public key cannot be read")?;
    let verifier = JwtVerifier::new_es256(
        &public_key,
        &arguments[2],
        &arguments[3],
        &arguments[4],
        300,
    )
    .map_err(|error| error.to_string())?;
    let user = verifier.admit(&token).map_err(|error| error.to_string())?;
    println!(
        "{{\"accepted\":true,\"identity_digest\":\"{}\"}}",
        hex(&user.identity_digest())
    );
    Ok(())
}

fn ndabi_probe(arguments: &[String]) -> Result<(), String> {
    if arguments.len() != 8 {
        return Err(
            "connection, token path, public-key path, key identifier, issuer, audience, start, and rows are required"
                .to_string(),
        );
    }
    let token = read_secret(&arguments[1])?;
    let public_key = std::fs::read(&arguments[2]).map_err(|_| "the public key cannot be read")?;
    let verifier = JwtVerifier::new_es256(
        &public_key,
        &arguments[3],
        &arguments[4],
        &arguments[5],
        300,
    )
    .map_err(|error| error.to_string())?;
    let user = verifier.admit(&token).map_err(|error| error.to_string())?;
    let start = arguments[6]
        .parse::<i64>()
        .map_err(|_| "the probe start is invalid")?;
    let rows = arguments[7]
        .parse::<u32>()
        .map_err(|_| "the probe row count is invalid")?;
    let result_budget = 6_u32
        .checked_add(rows.checked_mul(84).ok_or("the probe budget overflowed")?)
        .ok_or("the probe budget overflowed")?;
    let profile = profile()?;
    let identity = identity(profile)?;
    let mut state = NdabiState::new(
        &arguments[0],
        &user,
        profile,
        identity,
        rows,
        result_budget,
        99,
    )?;
    let probe = state.security_probe(start, rows, result_budget)?;
    println!(
        "{{\"accepted\":true,\"rows\":{rows},\"result_sha256\":\"{}\",\"changed_frame_refused\":{},\"replay_refused_before_query\":{},\"invalid_receipt_refused\":{},\"valid_result_accepted\":{}}}",
        hex(&Sha256::digest(probe.bytes)),
        probe.changed_frame_refused,
        probe.replay_refused_before_query,
        probe.invalid_receipt_refused,
        probe.valid_result_accepted,
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn measure_case(
    connection: &str,
    endpoint: &str,
    token: &str,
    user: &AdmittedIdentity,
    profile: RangeProfile,
    identity: BackendIdentity,
    start: i64,
    rows: u32,
    case_index: usize,
) -> Result<CaseReport, String> {
    let expected = expected_rows(start, rows);
    let result_budget = u32::try_from(expected.len()).map_err(|error| error.to_string())?;
    let mut ndabi = NdabiState::new(
        connection,
        user,
        profile,
        identity,
        rows,
        result_budget,
        case_index,
    )?;
    let transport_negotiation_ns = ndabi.transport_negotiation_ns;
    let rest = RestState::new(endpoint, token)?;
    let before_queries = ndabi.backend.data_queries();
    let mut samples: [Vec<Sample>; 2] = std::array::from_fn(|_| Vec::with_capacity(SAMPLES));
    for sample_index in 0..WARMUPS + SAMPLES {
        for offset in 0..2 {
            let arm = if (case_index + sample_index + offset).is_multiple_of(2) {
                Arm::Postgrest
            } else {
                Arm::Ndabi
            };
            let cpu_started = thread_cpu_ns()?;
            let allocation_started = begin_measurement();
            let started = Instant::now();
            let bytes = match arm {
                Arm::Postgrest => rest.execute(start, rows)?,
                Arm::Ndabi => ndabi.execute(start, rows, result_budget)?,
            };
            let wall_ns = elapsed_ns(started)?;
            let allocation = end_measurement(allocation_started);
            let cpu_ns = thread_cpu_ns()?.saturating_sub(cpu_started);
            if bytes != expected {
                return Err(format!("the {} result changed for {rows} rows", arm.id()));
            }
            black_box(&bytes);
            if sample_index >= WARMUPS {
                samples[arm as usize].push(Sample {
                    wall_ns,
                    cpu_ns,
                    allocation,
                });
            }
        }
    }
    let measurements = [Arm::Postgrest, Arm::Ndabi]
        .into_iter()
        .map(|arm| summarise(arm, std::mem::take(&mut samples[arm as usize])))
        .collect::<Vec<_>>();
    let postgrest = &measurements[Arm::Postgrest as usize];
    let ndabi_measurement = &measurements[Arm::Ndabi as usize];
    let ndabi_postgrest_p50_distance = ratio(ndabi_measurement.p50_ns, postgrest.p50_ns);
    let ndabi_postgrest_cpu_distance = ratio(ndabi_measurement.p50_cpu_ns, postgrest.p50_cpu_ns);
    let postgrest_request_lower_bound_bytes = rest.request_lower_bound_bytes(start, rows)?;
    let minimum_request_reduction =
        1.0 - FRAME_BYTES as f64 / postgrest_request_lower_bound_bytes as f64;
    let ndabi_data_queries = ndabi.backend.data_queries() - before_queries;
    let expected_data_queries = (WARMUPS + SAMPLES) as u64;
    let performance_passed = rows == 1 || ndabi_postgrest_p50_distance <= 0.50;
    let passed = ndabi_data_queries == expected_data_queries
        && minimum_request_reduction >= 0.69
        && performance_passed;
    Ok(CaseReport {
        rows,
        transport_negotiation_ns,
        ndabi_request_bytes: FRAME_BYTES,
        postgrest_request_lower_bound_bytes,
        minimum_request_reduction,
        result_bytes: expected.len(),
        result_sha256: hex(&Sha256::digest(&expected)),
        measurements,
        ndabi_data_queries,
        expected_data_queries,
        ndabi_postgrest_p50_distance,
        ndabi_postgrest_cpu_distance,
        passed,
    })
}

impl NdabiState {
    #[allow(clippy::too_many_arguments)]
    fn new(
        connection: &str,
        user: &AdmittedIdentity,
        profile: RangeProfile,
        identity: BackendIdentity,
        rows: u32,
        result_budget: u32,
        case_index: usize,
    ) -> Result<Self, String> {
        let authority = authority(user, identity, 6_700 + case_index as u64)?;
        let config = TransportConfig::new(0, MAXIMUM_FRAME_BYTES, MAXIMUM_CHUNK_BYTES, 1)
            .map_err(|error| error.to_string())?;
        let mut transport_client =
            TransportConnection::new(authority.clone(), TransportRole::Client, config);
        let mut transport_server =
            TransportConnection::new(authority.clone(), TransportRole::Server, config);
        let negotiation_started = Instant::now();
        negotiate(&mut transport_client, &mut transport_server)?;
        let transport_negotiation_ns = elapsed_ns(negotiation_started)?;
        let client = Client::connect(connection, NoTls).map_err(|error| error.to_string())?;
        let backend = SessionUserRangeBackend::new(
            client,
            profile,
            schema_digest(),
            policy_digest(),
            user,
            5_000,
        )
        .map_err(|error| error.to_string())?;
        Ok(Self {
            authority: authority.clone(),
            profile,
            wire_client: WireClientSession::new(authority.clone()),
            wire_server: ServerSession::new(authority, result_budget, rows)
                .map_err(|error| error.to_string())?,
            transport_client,
            transport_server,
            backend,
            replay: memory_replay_store(),
            result_frame: Vec::with_capacity(MAXIMUM_FRAME_BYTES as usize),
            transport_negotiation_ns,
        })
    }

    fn execute(&mut self, start: i64, rows: u32, result_budget: u32) -> Result<Vec<u8>, String> {
        let request = self
            .wire_client
            .encode(
                self.profile
                    .operation(start, rows)
                    .map_err(|error| error.to_string())?,
                result_budget,
                rows,
                deadline()?,
            )
            .map_err(|error| error.to_string())?;
        let client_request = self
            .transport_client
            .register_v1_request(&request)
            .map_err(|error| error.to_string())?;
        let execution = self
            .wire_server
            .execute(&request, &mut self.backend, &mut self.replay, &SystemClock)
            .map_err(|error| error.to_string())?;
        let server_request = self
            .transport_server
            .register_v1_request(&request)
            .map_err(|error| error.to_string())?;
        if client_request != server_request {
            return Err("the user request binding changed".to_string());
        }
        let receipt = self
            .transport_server
            .result_receipt(server_request.nonce, execution.rows, &execution.bytes)
            .map_err(|error| error.to_string())?;
        self.result_frame.resize(
            transport_frame_bytes(execution.bytes.len()).map_err(|error| error.to_string())?,
            0,
        );
        self.transport_server
            .encode(
                TransportKind::Result,
                TransportFields {
                    correlation_nonce: server_request.nonce,
                    rows: execution.rows,
                    result_shape: server_request.result_shape,
                    execution_receipt: receipt,
                    ..TransportFields::empty()
                },
                &execution.bytes,
                &mut self.result_frame,
            )
            .map_err(|error| error.to_string())?;
        let decoded = self
            .transport_client
            .decode(&self.result_frame, unix_us()?)
            .map_err(|error| error.to_string())?;
        if decoded.payload != execution.bytes {
            return Err("the user result changed during transport".to_string());
        }
        Ok(execution.bytes)
    }

    fn security_probe(
        &mut self,
        start: i64,
        rows: u32,
        result_budget: u32,
    ) -> Result<ProbeResult, String> {
        let request = self
            .wire_client
            .encode(
                self.profile
                    .operation(start, rows)
                    .map_err(|error| error.to_string())?,
                result_budget,
                rows,
                deadline()?,
            )
            .map_err(|error| error.to_string())?;
        let queries_before = self.backend.data_queries();
        let mut changed = request;
        changed[60] ^= 1;
        let changed_frame_refused = matches!(
            self.wire_server
                .execute(&changed, &mut self.backend, &mut self.replay, &SystemClock,),
            Err(ProtocolError::AuthenticationFailed)
        ) && self.backend.data_queries() == queries_before;
        let client_request = self
            .transport_client
            .register_v1_request(&request)
            .map_err(|error| error.to_string())?;
        let server_request = self
            .transport_server
            .register_v1_request(&request)
            .map_err(|error| error.to_string())?;
        let execution = self
            .wire_server
            .execute(&request, &mut self.backend, &mut self.replay, &SystemClock)
            .map_err(|error| error.to_string())?;
        let queries_after = self.backend.data_queries();
        let replay_refused_before_query = matches!(
            self.wire_server
                .execute(&request, &mut self.backend, &mut self.replay, &SystemClock,),
            Err(ProtocolError::Replay)
        ) && self.backend.data_queries() == queries_after;
        let fields = TransportFields {
            correlation_nonce: client_request.nonce,
            rows: execution.rows,
            result_shape: client_request.result_shape,
            execution_receipt: [9; 32],
            ..TransportFields::empty()
        };
        let mut invalid = vec![
            0;
            transport_frame_bytes(execution.bytes.len())
                .map_err(|error| error.to_string())?
        ];
        encode_transport(
            &self.authority,
            TransportDirection::ServerToClient,
            TransportKind::Result,
            fields,
            &execution.bytes,
            &mut invalid,
        )
        .map_err(|error| error.to_string())?;
        let invalid_receipt_refused = matches!(
            self.transport_client.decode(&invalid, unix_us()?),
            Err(ProtocolError::ReceiptMismatch)
        ) && self
            .transport_client
            .result_receipt(client_request.nonce, execution.rows, &execution.bytes)
            .is_ok();
        let receipt = self
            .transport_server
            .result_receipt(server_request.nonce, execution.rows, &execution.bytes)
            .map_err(|error| error.to_string())?;
        self.result_frame.resize(invalid.len(), 0);
        self.transport_server
            .encode(
                TransportKind::Result,
                TransportFields {
                    execution_receipt: receipt,
                    ..fields
                },
                &execution.bytes,
                &mut self.result_frame,
            )
            .map_err(|error| error.to_string())?;
        let decoded = self
            .transport_client
            .decode(&self.result_frame, unix_us()?)
            .map_err(|error| error.to_string())?;
        let valid_result_accepted = decoded.payload == execution.bytes;
        if !(changed_frame_refused
            && replay_refused_before_query
            && invalid_receipt_refused
            && valid_result_accepted)
        {
            return Err("an NDABI dedicated-session refusal failed".to_string());
        }
        Ok(ProbeResult {
            bytes: execution.bytes,
            changed_frame_refused,
            replay_refused_before_query,
            invalid_receipt_refused,
            valid_result_accepted,
        })
    }
}

struct ProbeResult {
    bytes: Vec<u8>,
    changed_frame_refused: bool,
    replay_refused_before_query: bool,
    invalid_receipt_refused: bool,
    valid_result_accepted: bool,
}

impl RestState {
    fn new(endpoint: &str, token: &str) -> Result<Self, String> {
        let client = HttpClient::builder()
            .pool_max_idle_per_host(1)
            .build()
            .map_err(|error| error.to_string())?;
        Ok(Self {
            client,
            endpoint: endpoint.trim_end_matches('/').to_string(),
            token: Zeroizing::new(token.to_string()),
        })
    }

    fn path(&self, start: i64, rows: u32) -> String {
        format!(
            "?select=id,bucket,owner,score,payload&id=gte.{start}&id=lt.{}&order=id",
            start + i64::from(rows)
        )
    }

    fn request_lower_bound_bytes(&self, start: i64, rows: u32) -> Result<usize, String> {
        let url = reqwest::Url::parse(&format!("{}{}", self.endpoint, self.path(start, rows)))
            .map_err(|error| error.to_string())?;
        let host = url
            .host_str()
            .ok_or_else(|| "the PostgREST host is absent".to_string())?;
        let port_bytes = url.port().map_or(0, |port| port.to_string().len() + 1);
        let query_bytes = url.query().map_or(0, |query| query.len() + 1);
        Ok(
            "GET  HTTP/1.1\r\nHost: \r\nAuthorization: Bearer \r\n\r\n".len()
                + url.path().len()
                + query_bytes
                + host.len()
                + port_bytes
                + self.token.len(),
        )
    }

    fn execute(&self, start: i64, rows: u32) -> Result<Vec<u8>, String> {
        let response = self
            .client
            .get(format!("{}{}", self.endpoint, self.path(start, rows)))
            .bearer_auth(self.token.as_str())
            .header("accept", "application/json")
            .send()
            .map_err(|error| error.to_string())?;
        if !response.status().is_success() {
            return Err(format!("PostgREST returned {}", response.status()));
        }
        let encoded = response.bytes().map_err(|error| error.to_string())?;
        let rows: Vec<RestRow> =
            serde_json::from_slice(&encoded).map_err(|error| error.to_string())?;
        encode_rest_rows(&rows)
    }
}

fn authority(
    user: &AdmittedIdentity,
    identity: BackendIdentity,
    session: u64,
) -> Result<Authority, String> {
    let mut tenant = [0; 16];
    tenant.copy_from_slice(
        &digest_label(b"ndabi/supabase/tenant/v1", user.issuer().as_bytes())[..16],
    );
    let mut actor = [0; 16];
    actor.copy_from_slice(&user.identity_digest()[..16]);
    let context = AuthorityContext::new(
        tenant,
        actor,
        1,
        digest_label(b"ndabi/supabase/capability/v1", b"user:range:read"),
        identity,
    )
    .map_err(|error| error.to_string())?;
    let expires_unix_us = user
        .session_expires_unix_s()
        .checked_mul(1_000_000)
        .ok_or_else(|| "the session expiry overflowed".to_string())?;
    Authority::new_read([67; 32], 1, session, expires_unix_us, context)
        .map_err(|error| error.to_string())
}

fn negotiate(
    client: &mut TransportConnection,
    server: &mut TransportConnection,
) -> Result<(), String> {
    transfer(
        client,
        server,
        TransportKind::Hello,
        TransportFields {
            auxiliary: MAXIMUM_FRAME_BYTES,
            ..TransportFields::empty()
        },
        &negotiation_payload(2, 2),
    )?;
    transfer(
        server,
        client,
        TransportKind::Accept,
        TransportFields {
            auxiliary: MAXIMUM_FRAME_BYTES,
            ..TransportFields::empty()
        },
        &negotiation_payload(2, 0),
    )
}

fn transfer(
    sender: &mut TransportConnection,
    receiver: &mut TransportConnection,
    kind: TransportKind,
    fields: TransportFields,
    payload: &[u8],
) -> Result<(), String> {
    let mut frame =
        vec![0; transport_frame_bytes(payload.len()).map_err(|error| error.to_string())?];
    sender
        .encode(kind, fields, payload, &mut frame)
        .map_err(|error| error.to_string())?;
    receiver
        .decode(&frame, unix_us()?)
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn negotiation_payload(first: u16, second: u16) -> [u8; 8] {
    let mut payload = [0; 8];
    payload[0..2].copy_from_slice(&first.to_le_bytes());
    payload[2..4].copy_from_slice(&second.to_le_bytes());
    payload[4..8].copy_from_slice(&MAXIMUM_CHUNK_BYTES.to_le_bytes());
    payload
}

fn profile() -> Result<RangeProfile, String> {
    RangeProfile::new(
        SQL,
        OperationBinding::new(67, 670).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
}

fn identity(profile: RangeProfile) -> Result<BackendIdentity, String> {
    profile
        .identity(schema_digest(), policy_digest())
        .map_err(|error| error.to_string())
}

fn schema_digest() -> [u8; 32] {
    digest_label(
        b"ndabi/supabase/schema/v2",
        b"supabase_items(id:i64,bucket:i32,owner:i32,score:i32,payload:bytes64,owner_sub:text)",
    )
}

fn policy_digest() -> [u8; 32] {
    digest_label(
        b"ndabi/supabase/policy/v2",
        b"role:authenticated;owner_sub=request.jwt.claims.sub;read-only",
    )
}

fn expected_rows(start: i64, rows: u32) -> Vec<u8> {
    let mut output = Vec::with_capacity(6 + rows as usize * 84);
    output.extend_from_slice(&1_u16.to_le_bytes());
    output.extend_from_slice(&rows.to_le_bytes());
    for identifier in start..start + i64::from(rows) {
        output.extend_from_slice(&identifier.to_le_bytes());
        output.extend_from_slice(&((identifier % 1_000) as i32).to_le_bytes());
        output.extend_from_slice(&((identifier % 100) as i32).to_le_bytes());
        output.extend_from_slice(&((identifier % 10_000) as i32).to_le_bytes());
        output.extend_from_slice(&[identifier as u8; 64]);
    }
    output
}

fn encode_rest_rows(rows: &[RestRow]) -> Result<Vec<u8>, String> {
    let row_count = u32::try_from(rows.len()).map_err(|error| error.to_string())?;
    let mut output = Vec::with_capacity(6 + rows.len() * 84);
    output.extend_from_slice(&1_u16.to_le_bytes());
    output.extend_from_slice(&row_count.to_le_bytes());
    for row in rows {
        output.extend_from_slice(&row.id.to_le_bytes());
        output.extend_from_slice(&row.bucket.to_le_bytes());
        output.extend_from_slice(&row.owner.to_le_bytes());
        output.extend_from_slice(&row.score.to_le_bytes());
        output.extend_from_slice(&decode_bytea(&row.payload)?);
    }
    Ok(output)
}

fn decode_bytea(value: &str) -> Result<[u8; 64], String> {
    let hex = value
        .strip_prefix("\\x")
        .ok_or_else(|| "the PostgREST payload is not hexadecimal".to_string())?;
    if hex.len() != 128 {
        return Err("the PostgREST payload length changed".to_string());
    }
    let mut output = [0; 64];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
            .map_err(|_| "the PostgREST payload is invalid".to_string())?;
    }
    Ok(output)
}

fn summarise(arm: Arm, mut samples: Vec<Sample>) -> Measurement {
    samples.sort_by_key(|sample| sample.wall_ns);
    let raw_ns = samples
        .iter()
        .map(|sample| sample.wall_ns)
        .collect::<Vec<_>>();
    let mut raw_cpu_ns = samples
        .iter()
        .map(|sample| sample.cpu_ns)
        .collect::<Vec<_>>();
    raw_cpu_ns.sort_unstable();
    Measurement {
        arm: arm.id(),
        p50_ns: percentile(&raw_ns, 50),
        p95_ns: percentile(&raw_ns, 95),
        p99_ns: percentile(&raw_ns, 99),
        p50_cpu_ns: percentile(&raw_cpu_ns, 50),
        mean_allocations: mean(
            &samples
                .iter()
                .map(|sample| sample.allocation.allocations)
                .collect::<Vec<_>>(),
        ),
        mean_allocated_bytes: mean(
            &samples
                .iter()
                .map(|sample| sample.allocation.allocated_bytes)
                .collect::<Vec<_>>(),
        ),
        peak_additional_live_bytes: samples
            .iter()
            .map(|sample| sample.allocation.peak_additional_live_bytes)
            .max()
            .unwrap_or(0),
        raw_ns,
        raw_cpu_ns,
    }
}

fn percentile(values: &[u64], percentage: usize) -> u64 {
    values[(values.len() - 1) * percentage / 100]
}

fn mean(values: &[u64]) -> f64 {
    values.iter().sum::<u64>() as f64 / values.len() as f64
}

fn ratio(first: u64, second: u64) -> f64 {
    first as f64 / second as f64
}

fn read_secret(path: &str) -> Result<Zeroizing<String>, String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| "the token file is absent")?;
    if !metadata.file_type().is_file() {
        return Err("the token path is not a regular file".to_string());
    }
    let token = std::fs::read_to_string(Path::new(path)).map_err(|_| "the token cannot be read")?;
    let token = token.trim();
    if token.is_empty() {
        return Err("the token is empty".to_string());
    }
    Ok(Zeroizing::new(token.to_string()))
}

fn deadline() -> Result<u64, String> {
    unix_us()?
        .checked_add(60_000_000)
        .ok_or_else(|| "the deadline overflowed".to_string())
}

fn unix_us() -> Result<u64, String> {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "the system clock failed")?
        .as_micros();
    u64::try_from(micros).map_err(|error| error.to_string())
}

fn elapsed_ns(started: Instant) -> Result<u64, String> {
    u64::try_from(started.elapsed().as_nanos()).map_err(|error| error.to_string())
}

#[cfg(unix)]
fn thread_cpu_ns() -> Result<u64, String> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: The operating system writes one valid `timespec` into the provided pointer.
    let status = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut time) };
    if status != 0 || time.tv_sec < 0 || time.tv_nsec < 0 {
        return Err("the thread CPU clock failed".to_string());
    }
    let seconds = u64::try_from(time.tv_sec).map_err(|error| error.to_string())?;
    let nanoseconds = u64::try_from(time.tv_nsec).map_err(|error| error.to_string())?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or_else(|| "the thread CPU clock overflowed".to_string())
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(output, "{byte:02x}").expect("a string write cannot fail");
    }
    output
}
