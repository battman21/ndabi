use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use ndabi_session::{Authority, Backend, ClientSession, RawOperation, ServerSession, FRAME_BYTES};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};
use serde::{Deserialize, Serialize};

const NOW: u64 = 1_000_000;
const DEADLINE: u64 = 2_000_000;
const RESULT_BYTES: usize = 350;
const MAXIMUM_RESULT_BYTES: u32 = 8_192;
const LOOPBACK_ITERATIONS: usize = 10_000;
const DELAY_ITERATIONS: usize = 200;
const LOOPBACK_WARMUP: usize = 500;
const DELAY_WARMUP: usize = 20;
const CONTROLLED_DELAY: Duration = Duration::from_millis(5);

#[derive(Clone, Deserialize, PartialEq, Serialize)]
struct NamedRequest {
    operation: String,
    trajectory_id: i64,
    snapshot_handle: i64,
    seed_member_ordinal: u32,
    maximum_causal_hops: u32,
}

impl NamedRequest {
    fn fixed() -> Self {
        Self {
            operation: "assemble_governed_context".to_string(),
            trajectory_id: 100,
            snapshot_handle: 1,
            seed_member_ordinal: 3,
            maximum_causal_hops: 3,
        }
    }
}

fn operation() -> RawOperation {
    RawOperation::new(0x31, 100, 1, (3 << 16) | 3).expect("fixed operation")
}

struct FixedBackend;

impl Backend for FixedBackend {
    fn execute(&mut self, supplied: RawOperation) -> Result<Vec<u8>, ndabi_session::SessionError> {
        if supplied != operation() {
            return Err(ndabi_session::SessionError::backend_refused());
        }
        Ok((0..RESULT_BYTES).map(|index| (index % 251) as u8).collect())
    }
}

#[derive(Clone, Copy)]
enum Surface {
    Json,
    Ndabi,
}

#[derive(Serialize)]
struct Measurement {
    condition: &'static str,
    surface: &'static str,
    iterations: usize,
    request_bytes: usize,
    response_bytes: usize,
    handshake_ns: u64,
    median_ns: u64,
    p95_ns: u64,
    operations_per_second: f64,
    tls13: bool,
    exact_results: bool,
    receipts_present: bool,
}

#[derive(Serialize)]
struct Report {
    campaign: &'static str,
    measurements: Vec<Measurement>,
    request_compression: f64,
    loopback_p95_ratio: f64,
    controlled_delay_p95_ratio: f64,
    passed: bool,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let (server_config, client_config) = tls_configs()?;
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|error| error.to_string())?;
    let address = listener.local_addr().map_err(|error| error.to_string())?;
    let server = thread::spawn(move || serve(listener, server_config));
    let cases = [
        (
            "loopback",
            Surface::Json,
            LOOPBACK_ITERATIONS,
            LOOPBACK_WARMUP,
            Duration::ZERO,
            601,
        ),
        (
            "loopback",
            Surface::Ndabi,
            LOOPBACK_ITERATIONS,
            LOOPBACK_WARMUP,
            Duration::ZERO,
            602,
        ),
        (
            "controlled-delay",
            Surface::Json,
            DELAY_ITERATIONS,
            DELAY_WARMUP,
            CONTROLLED_DELAY,
            603,
        ),
        (
            "controlled-delay",
            Surface::Ndabi,
            DELAY_ITERATIONS,
            DELAY_WARMUP,
            CONTROLLED_DELAY,
            604,
        ),
    ];
    let mut measurements = Vec::new();
    for (condition, surface, iterations, warmup, delay, session) in cases {
        measurements.push(measure_connection(
            address,
            client_config.clone(),
            condition,
            surface,
            iterations,
            warmup,
            delay,
            session,
        )?);
    }
    server
        .join()
        .map_err(|_| "the TLS server panicked".to_string())??;
    let json_bytes = measurements[0].request_bytes;
    let request_compression = 1.0 - FRAME_BYTES as f64 / json_bytes as f64;
    let loopback_p95_ratio = measurements[1].p95_ns as f64 / measurements[0].p95_ns as f64;
    let controlled_delay_p95_ratio = measurements[3].p95_ns as f64 / measurements[2].p95_ns as f64;
    let passed = measurements.iter().all(|measurement| {
        measurement.tls13 && measurement.exact_results && measurement.receipts_present
    }) && request_compression >= 0.35
        && loopback_p95_ratio <= 1.10;
    println!(
        "{}",
        serde_json::to_string_pretty(&Report {
            campaign: "NDABI TLS and controlled-delay v4.6",
            measurements,
            request_compression,
            loopback_p95_ratio,
            controlled_delay_p95_ratio,
            passed,
        })
        .map_err(|error| error.to_string())?
    );
    Ok(())
}

fn tls_configs() -> Result<(Arc<ServerConfig>, Arc<ClientConfig>), String> {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_string()])
            .map_err(|error| error.to_string())?;
    let certificate = cert.der().clone();
    let private_key = PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into();
    let server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], private_key)
        .map_err(|error| error.to_string())?;
    let mut roots = RootCertStore::empty();
    roots.add(certificate).map_err(|error| error.to_string())?;
    let client = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok((Arc::new(server), Arc::new(client)))
}

fn serve(listener: TcpListener, config: Arc<ServerConfig>) -> Result<(), String> {
    let cases = [
        (Surface::Json, Duration::ZERO, 601),
        (Surface::Ndabi, Duration::ZERO, 602),
        (Surface::Json, CONTROLLED_DELAY, 603),
        (Surface::Ndabi, CONTROLLED_DELAY, 604),
    ];
    for (surface, delay, session) in cases {
        let (socket, _) = listener.accept().map_err(|error| error.to_string())?;
        socket
            .set_nodelay(true)
            .map_err(|error| error.to_string())?;
        let connection =
            ServerConnection::new(config.clone()).map_err(|error| error.to_string())?;
        let mut stream = StreamOwned::new(connection, socket);
        serve_connection(&mut stream, surface, delay, session)?;
    }
    Ok(())
}

fn serve_connection(
    stream: &mut StreamOwned<ServerConnection, TcpStream>,
    surface: Surface,
    delay: Duration,
    session: u32,
) -> Result<(), String> {
    let binding = authority(session)?;
    let mut compiler = ClientSession::new(binding.clone());
    let mut server =
        ServerSession::new(binding, MAXIMUM_RESULT_BYTES).map_err(|error| error.to_string())?;
    let mut backend = FixedBackend;
    loop {
        let mut length = [0; 4];
        stream
            .read_exact(&mut length)
            .map_err(|error| error.to_string())?;
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 {
            return Ok(());
        }
        if length > 1_024 {
            return Err("the TLS request exceeds its transport budget".to_string());
        }
        let mut request = vec![0; length];
        stream
            .read_exact(&mut request)
            .map_err(|error| error.to_string())?;
        let result = match surface {
            Surface::Json => {
                let decoded: NamedRequest =
                    serde_json::from_slice(&request).map_err(|error| error.to_string())?;
                if decoded != NamedRequest::fixed() {
                    return Err("the TLS JSON request is not authorised".to_string());
                }
                let frame = compiler
                    .encode(operation(), MAXIMUM_RESULT_BYTES, DEADLINE)
                    .map_err(|error| error.to_string())?;
                server.execute(&frame, NOW, &mut backend)
            }
            Surface::Ndabi => server.execute(&request, NOW, &mut backend),
        }
        .map_err(|error| error.to_string())?;
        if !delay.is_zero() {
            thread::sleep(delay);
        }
        let response_length = u32::try_from(32 + result.bytes.len())
            .map_err(|_| "the TLS response is excessive".to_string())?;
        stream
            .write_all(&response_length.to_be_bytes())
            .map_err(|error| error.to_string())?;
        stream
            .write_all(&result.receipt)
            .map_err(|error| error.to_string())?;
        stream
            .write_all(&result.bytes)
            .map_err(|error| error.to_string())?;
        stream.flush().map_err(|error| error.to_string())?;
    }
}

#[allow(clippy::too_many_arguments)]
fn measure_connection(
    address: std::net::SocketAddr,
    config: Arc<ClientConfig>,
    condition: &'static str,
    surface: Surface,
    iterations: usize,
    warmup: usize,
    _delay: Duration,
    session: u32,
) -> Result<Measurement, String> {
    let socket = TcpStream::connect(address).map_err(|error| error.to_string())?;
    socket
        .set_nodelay(true)
        .map_err(|error| error.to_string())?;
    let name = ServerName::try_from("localhost").map_err(|error| error.to_string())?;
    let connection = ClientConnection::new(config, name).map_err(|error| error.to_string())?;
    let mut stream = StreamOwned::new(connection, socket);
    let handshake_started = Instant::now();
    while stream.conn.is_handshaking() {
        stream
            .conn
            .complete_io(&mut stream.sock)
            .map_err(|error| error.to_string())?;
    }
    let handshake_ns = handshake_started.elapsed().as_nanos() as u64;
    let tls13 = stream.conn.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3);
    let json = serde_json::to_vec(&NamedRequest::fixed()).map_err(|error| error.to_string())?;
    let mut client = ClientSession::new(authority(session)?);
    for _ in 0..warmup {
        exchange(&mut stream, surface, &json, &mut client)?;
    }
    let mut samples = Vec::with_capacity(iterations);
    let mut exact_results = true;
    let mut receipts_present = true;
    let total_started = Instant::now();
    for _ in 0..iterations {
        let started = Instant::now();
        let (receipt, bytes) = exchange(&mut stream, surface, &json, &mut client)?;
        samples.push(started.elapsed().as_nanos() as u64);
        exact_results &= bytes == expected_result();
        receipts_present &= receipt.iter().any(|byte| *byte != 0);
    }
    let elapsed = total_started.elapsed().as_secs_f64();
    stream
        .write_all(&0u32.to_be_bytes())
        .map_err(|error| error.to_string())?;
    stream.flush().map_err(|error| error.to_string())?;
    samples.sort_unstable();
    Ok(Measurement {
        condition,
        surface: match surface {
            Surface::Json => "json",
            Surface::Ndabi => "ndabi",
        },
        iterations,
        request_bytes: match surface {
            Surface::Json => json.len(),
            Surface::Ndabi => FRAME_BYTES,
        },
        response_bytes: 32 + RESULT_BYTES,
        handshake_ns,
        median_ns: percentile(&samples, 0.50),
        p95_ns: percentile(&samples, 0.95),
        operations_per_second: iterations as f64 / elapsed,
        tls13,
        exact_results,
        receipts_present,
    })
}

fn exchange(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
    surface: Surface,
    json: &[u8],
    client: &mut ClientSession,
) -> Result<([u8; 32], Vec<u8>), String> {
    let frame;
    let request = match surface {
        Surface::Json => json,
        Surface::Ndabi => {
            frame = client
                .encode(operation(), MAXIMUM_RESULT_BYTES, DEADLINE)
                .map_err(|error| error.to_string())?;
            &frame
        }
    };
    let length =
        u32::try_from(request.len()).map_err(|_| "the request is excessive".to_string())?;
    stream
        .write_all(&length.to_be_bytes())
        .map_err(|error| error.to_string())?;
    stream
        .write_all(request)
        .map_err(|error| error.to_string())?;
    stream.flush().map_err(|error| error.to_string())?;
    let mut response_length = [0; 4];
    stream
        .read_exact(&mut response_length)
        .map_err(|error| error.to_string())?;
    let response_length = u32::from_be_bytes(response_length) as usize;
    if response_length != 32 + RESULT_BYTES {
        return Err("the TLS response length is invalid".to_string());
    }
    let mut receipt = [0; 32];
    stream
        .read_exact(&mut receipt)
        .map_err(|error| error.to_string())?;
    let mut bytes = vec![0; RESULT_BYTES];
    stream
        .read_exact(&mut bytes)
        .map_err(|error| error.to_string())?;
    Ok((receipt, bytes))
}

fn authority(session: u32) -> Result<Authority, String> {
    Authority::new([46; 32], 1, session, DEADLINE, 10, 11, 12).map_err(|error| error.to_string())
}

fn expected_result() -> Vec<u8> {
    (0..RESULT_BYTES).map(|index| (index % 251) as u8).collect()
}

fn percentile(samples: &[u64], quantile: f64) -> u64 {
    let rank = (quantile * samples.len() as f64).ceil() as usize;
    samples[rank.saturating_sub(1).min(samples.len() - 1)]
}
