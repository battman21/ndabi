use std::fmt::Write as _;
use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use ndabi_protocol::{
    digest_label, transport_frame_bytes, Authority, AuthorityContext, Backend, BackendIdentity,
    BoundedOutput, ClientSession, ExecutionLimits, MemoryReplayStore, Operation, ServerSession,
    SystemClock, TransportConfig, TransportConnection, TransportFields, TransportKind,
    TransportRole, FRAME_BYTES,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};
use serde::{Deserialize, Serialize};

const MAXIMUM_FRAME_BYTES: u32 = 16_384;
const MAXIMUM_CHUNK_BYTES: u32 = 8_192;
const RESULT_BYTES: usize = 8_192;
const RESULT_ROWS: u32 = 8;
const DEADLINE_UNIX_US: u64 = u64::MAX - 2;
const EXPIRY_UNIX_US: u64 = u64::MAX - 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Surface {
    Json,
    Ndabi,
}

impl Surface {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "json" => Ok(Self::Json),
            "ndabi" => Ok(Self::Ndabi),
            _ => Err("the surface must be json or ndabi".to_string()),
        }
    }

    fn wire_id(self) -> u8 {
        match self {
            Self::Json => 1,
            Self::Ndabi => 2,
        }
    }

    fn from_wire(value: u8) -> Result<Self, String> {
        match value {
            1 => Ok(Self::Json),
            2 => Ok(Self::Ndabi),
            _ => Err("the surface identifier is invalid".to_string()),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Ndabi => "ndabi",
        }
    }
}

#[derive(Deserialize, Serialize)]
struct JsonRequest {
    operation: String,
    plan_handle: u32,
    owner: i64,
    minimum_score: i64,
    limit: u32,
    result_shape: String,
    policy: String,
    tenant: String,
    principal: String,
    purpose: String,
}

#[derive(Serialize)]
struct ClientReport {
    campaign: &'static str,
    surface: &'static str,
    iterations: usize,
    request_bytes: usize,
    result_bytes: usize,
    handshake_ns: u64,
    p50_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    operations_per_second: f64,
    tls13: bool,
    mutual_tls: bool,
    transport_v02_negotiated: bool,
    all_results_exact: bool,
    all_receipts_verified: bool,
    result_sha256: String,
}

struct FixedBackend {
    identity: BackendIdentity,
}

impl Backend for FixedBackend {
    fn identity(&self) -> BackendIdentity {
        self.identity
    }

    fn execute(
        &mut self,
        supplied: Operation,
        _limits: ExecutionLimits,
        output: &mut BoundedOutput,
    ) -> Result<(), ndabi_protocol::ProtocolError> {
        if supplied != operation()? {
            return Err(ndabi_protocol::ProtocolError::BackendRefused);
        }
        output.write_exact(RESULT_BYTES, RESULT_ROWS, |bytes| {
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = (index % 251) as u8;
            }
            Ok(())
        })
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let arguments = std::env::args().collect::<Vec<_>>();
    match arguments.get(1).map(String::as_str) {
        Some("server") if arguments.len() == 6 => {
            serve(&arguments[2], &arguments[3], &arguments[4], &arguments[5])
        }
        Some("client") if arguments.len() == 10 => client(
            &arguments[2],
            Surface::parse(&arguments[3])?,
            arguments[4]
                .parse()
                .map_err(|_| "the iteration count is invalid".to_string())?,
            &arguments[5],
            &arguments[6],
            &arguments[7],
            &arguments[8],
            arguments[9]
                .parse()
                .map_err(|_| "the warm-up count is invalid".to_string())?,
        ),
        _ => Err(
            "usage: ndabi_v84 server ADDRESS CERT_DER KEY_DER CA_DER | client ADDRESS SURFACE ITERATIONS CERT_DER KEY_DER CA_DER SERVER_NAME WARMUP"
                .to_string(),
        ),
    }
}

fn serve(address: &str, cert: &str, key: &str, ca: &str) -> Result<(), String> {
    let config = server_tls(cert, key, ca)?;
    let listener = TcpListener::bind(address).map_err(|error| error.to_string())?;
    println!(
        "READY {}",
        listener.local_addr().map_err(|error| error.to_string())?
    );
    std::io::stdout()
        .flush()
        .map_err(|error| error.to_string())?;
    let (socket, _) = listener.accept().map_err(|error| error.to_string())?;
    socket
        .set_nodelay(true)
        .map_err(|error| error.to_string())?;
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .and_then(|_| socket.set_write_timeout(Some(std::time::Duration::from_secs(10))))
        .map_err(|error| error.to_string())?;
    let connection = ServerConnection::new(config).map_err(|error| error.to_string())?;
    let mut stream = StreamOwned::new(connection, socket);
    let mut surface = [0_u8; 1];
    stream
        .read_exact(&mut surface)
        .map_err(|error| error.to_string())?;
    serve_connection(&mut stream, Surface::from_wire(surface[0])?)
}

fn serve_connection(
    stream: &mut StreamOwned<ServerConnection, TcpStream>,
    surface: Surface,
) -> Result<(), String> {
    let authority = authority()?;
    let config = transport_config()?;
    let mut transport = TransportConnection::new(authority.clone(), TransportRole::Server, config);
    let hello = read_message(stream, MAXIMUM_FRAME_BYTES as usize)?;
    transport
        .decode(&hello, unix_us()?)
        .map_err(|error| error.to_string())?;
    let mut accept = vec![0; transport_frame_bytes(8).map_err(|error| error.to_string())?];
    transport
        .encode(
            TransportKind::Accept,
            TransportFields {
                auxiliary: MAXIMUM_FRAME_BYTES,
                ..TransportFields::empty()
            },
            &negotiation_payload(2, 0),
            &mut accept,
        )
        .map_err(|error| error.to_string())?;
    write_message(stream, &accept)?;

    let server = ServerSession::new(authority.clone(), RESULT_BYTES as u32, RESULT_ROWS)
        .map_err(|error| error.to_string())?;
    let mut replay = MemoryReplayStore::default();
    let mut json_compiler = ClientSession::new(authority.clone());
    let mut backend = FixedBackend {
        identity: backend_identity()?,
    };
    loop {
        let request = match read_optional_message(stream, 4_096)? {
            Some(request) => request,
            None => return Ok(()),
        };
        let frame = match surface {
            Surface::Ndabi => request,
            Surface::Json => {
                let decoded: JsonRequest =
                    serde_json::from_slice(&request).map_err(|error| error.to_string())?;
                if serde_json::to_vec(&decoded).map_err(|error| error.to_string())? != request
                    || decoded.plan_handle != 840
                    || decoded.owner != 7
                    || decoded.minimum_score != 250
                    || decoded.limit != RESULT_ROWS
                {
                    return Err("the JSON request is not canonical".to_string());
                }
                json_compiler
                    .encode(
                        operation().map_err(|error| error.to_string())?,
                        RESULT_BYTES as u32,
                        RESULT_ROWS,
                        DEADLINE_UNIX_US,
                    )
                    .map_err(|error| error.to_string())?
                    .to_vec()
            }
        };
        let registered = transport
            .register_v1_request(&frame)
            .map_err(|error| error.to_string())?;
        let execution = server
            .execute(&frame, &mut backend, &mut replay, &SystemClock)
            .map_err(|error| error.to_string())?;
        let receipt = transport
            .result_receipt(registered.nonce, execution.rows, &execution.bytes)
            .map_err(|error| error.to_string())?;
        let mut response = vec![
            0;
            transport_frame_bytes(execution.bytes.len())
                .map_err(|error| error.to_string())?
        ];
        transport
            .encode(
                TransportKind::Result,
                TransportFields {
                    correlation_nonce: registered.nonce,
                    rows: execution.rows,
                    result_shape: registered.result_shape,
                    execution_receipt: receipt,
                    ..TransportFields::empty()
                },
                &execution.bytes,
                &mut response,
            )
            .map_err(|error| error.to_string())?;
        write_message(stream, &response)?;
    }
}

#[allow(clippy::too_many_arguments)]
fn client(
    address: &str,
    surface: Surface,
    iterations: usize,
    cert: &str,
    key: &str,
    ca: &str,
    server_name: &str,
    warmup: usize,
) -> Result<(), String> {
    if iterations == 0 {
        return Err("the iteration count must be positive".to_string());
    }
    let socket = TcpStream::connect(address).map_err(|error| error.to_string())?;
    socket
        .set_nodelay(true)
        .map_err(|error| error.to_string())?;
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .and_then(|_| socket.set_write_timeout(Some(std::time::Duration::from_secs(10))))
        .map_err(|error| error.to_string())?;
    let name = ServerName::try_from(server_name.to_string()).map_err(|error| error.to_string())?;
    let connection = ClientConnection::new(client_tls(cert, key, ca)?, name)
        .map_err(|error| error.to_string())?;
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
    let mutual_tls = stream
        .conn
        .peer_certificates()
        .is_some_and(|certificates| !certificates.is_empty());
    stream
        .write_all(&[surface.wire_id()])
        .map_err(|error| error.to_string())?;

    let authority = authority()?;
    let mut transport = TransportConnection::new(
        authority.clone(),
        TransportRole::Client,
        transport_config()?,
    );
    let mut hello = vec![0; transport_frame_bytes(8).map_err(|error| error.to_string())?];
    transport
        .encode(
            TransportKind::Hello,
            TransportFields {
                auxiliary: MAXIMUM_FRAME_BYTES,
                ..TransportFields::empty()
            },
            &negotiation_payload(2, 2),
            &mut hello,
        )
        .map_err(|error| error.to_string())?;
    write_message(&mut stream, &hello)?;
    let accept = read_message(&mut stream, MAXIMUM_FRAME_BYTES as usize)?;
    transport
        .decode(&accept, unix_us()?)
        .map_err(|error| error.to_string())?;

    let json = serde_json::to_vec(&json_request()).map_err(|error| error.to_string())?;
    let mut wire = ClientSession::new(authority);
    for _ in 0..warmup {
        exchange(&mut stream, surface, &json, &mut wire, &mut transport)?;
    }
    let mut samples = Vec::with_capacity(iterations);
    let mut all_results_exact = true;
    let mut all_receipts_verified = true;
    let expected = expected_result();
    let started_all = Instant::now();
    for _ in 0..iterations {
        let started = Instant::now();
        let (result, receipt_verified) =
            exchange(&mut stream, surface, &json, &mut wire, &mut transport)?;
        samples.push(started.elapsed().as_nanos() as u64);
        all_results_exact &= result == expected;
        all_receipts_verified &= receipt_verified;
    }
    let elapsed = started_all.elapsed().as_secs_f64();
    stream.conn.send_close_notify();
    stream.flush().map_err(|error| error.to_string())?;
    stream
        .sock
        .shutdown(Shutdown::Both)
        .map_err(|error| error.to_string())?;
    samples.sort_unstable();
    println!(
        "{}",
        serde_json::to_string_pretty(&ClientReport {
            campaign: "NDABI remote mTLS transport v8.4",
            surface: surface.name(),
            iterations,
            request_bytes: match surface {
                Surface::Json => json.len(),
                Surface::Ndabi => FRAME_BYTES,
            },
            result_bytes: RESULT_BYTES,
            handshake_ns,
            p50_ns: percentile(&samples, 0.50),
            p95_ns: percentile(&samples, 0.95),
            p99_ns: percentile(&samples, 0.99),
            operations_per_second: iterations as f64 / elapsed,
            tls13,
            mutual_tls,
            transport_v02_negotiated: transport.negotiated().is_some(),
            all_results_exact,
            all_receipts_verified,
            result_sha256: sha256_hex(&expected),
        })
        .map_err(|error| error.to_string())?
    );
    Ok(())
}

fn exchange(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
    surface: Surface,
    json: &[u8],
    wire: &mut ClientSession,
    transport: &mut TransportConnection,
) -> Result<(Vec<u8>, bool), String> {
    let frame = wire
        .encode(
            operation().map_err(|error| error.to_string())?,
            RESULT_BYTES as u32,
            RESULT_ROWS,
            DEADLINE_UNIX_US,
        )
        .map_err(|error| error.to_string())?;
    let registered = transport
        .register_v1_request(&frame)
        .map_err(|error| error.to_string())?;
    write_message(
        stream,
        match surface {
            Surface::Json => json,
            Surface::Ndabi => &frame,
        },
    )?;
    let response = read_message(stream, MAXIMUM_FRAME_BYTES as usize)?;
    let decoded = transport
        .decode(&response, unix_us()?)
        .map_err(|error| error.to_string())?;
    Ok((
        decoded.payload.to_vec(),
        decoded.fields.correlation_nonce == registered.nonce,
    ))
}

fn server_tls(cert: &str, key: &str, ca: &str) -> Result<Arc<ServerConfig>, String> {
    let mut roots = RootCertStore::empty();
    roots
        .add(read_certificate(ca)?)
        .map_err(|error| error.to_string())?;
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|error| error.to_string())?;
    let config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![read_certificate(cert)?], read_key(key)?)
        .map_err(|error| error.to_string())?;
    Ok(Arc::new(config))
}

fn client_tls(cert: &str, key: &str, ca: &str) -> Result<Arc<ClientConfig>, String> {
    let mut roots = RootCertStore::empty();
    roots
        .add(read_certificate(ca)?)
        .map_err(|error| error.to_string())?;
    let config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_client_auth_cert(vec![read_certificate(cert)?], read_key(key)?)
        .map_err(|error| error.to_string())?;
    Ok(Arc::new(config))
}

fn read_certificate(path: &str) -> Result<CertificateDer<'static>, String> {
    fs::read(path)
        .map(CertificateDer::from)
        .map_err(|error| error.to_string())
}

fn read_key(path: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>, String> {
    fs::read(path)
        .map(PrivatePkcs8KeyDer::from)
        .map(Into::into)
        .map_err(|error| error.to_string())
}

fn authority() -> Result<Authority, String> {
    Authority::new_read([84; 32], 1, 84, EXPIRY_UNIX_US, authority_context()?)
        .map_err(|error| error.to_string())
}

fn authority_context() -> Result<AuthorityContext, String> {
    AuthorityContext::new(
        *b"remote-tenant-01",
        *b"remote-reader-01",
        1,
        digest_label(b"ndabi/remote/capability/v1", b"read:fixed-memory-result"),
        backend_identity()?,
    )
    .map_err(|error| error.to_string())
}

fn backend_identity() -> Result<BackendIdentity, String> {
    BackendIdentity::new(
        84,
        1,
        digest_label(b"ndabi/remote/schema/v1", b"fixed-result:8192"),
        digest_label(b"ndabi/remote/policy/v1", b"read-only;registered-handle"),
        digest_label(b"ndabi/remote/plan/v1", b"handle:840"),
    )
    .map_err(|error| error.to_string())
}

fn operation() -> Result<Operation, ndabi_protocol::ProtocolError> {
    Operation::new(84, 840, 841, 7, 250, RESULT_ROWS)
}

fn json_request() -> JsonRequest {
    JsonRequest {
        operation: "execute_registered_memory_query".to_string(),
        plan_handle: 840,
        owner: 7,
        minimum_score: 250,
        limit: RESULT_ROWS,
        result_shape: "fixed-memory-result-v1".to_string(),
        policy: "governed-read-only".to_string(),
        tenant: "remote-tenant-01".to_string(),
        principal: "remote-reader-01".to_string(),
        purpose: "agent-memory-recall".to_string(),
    }
}

fn transport_config() -> Result<TransportConfig, String> {
    TransportConfig::new(0, MAXIMUM_FRAME_BYTES, MAXIMUM_CHUNK_BYTES, 1)
        .map_err(|error| error.to_string())
}

fn negotiation_payload(first: u16, second: u16) -> [u8; 8] {
    let mut payload = [0_u8; 8];
    payload[0..2].copy_from_slice(&first.to_le_bytes());
    payload[2..4].copy_from_slice(&second.to_le_bytes());
    payload[4..8].copy_from_slice(&MAXIMUM_CHUNK_BYTES.to_le_bytes());
    payload
}

fn expected_result() -> Vec<u8> {
    (0..RESULT_BYTES).map(|index| (index % 251) as u8).collect()
}

fn read_optional_message(
    stream: &mut impl Read,
    maximum: usize,
) -> Result<Option<Vec<u8>>, String> {
    let mut length = [0_u8; 4];
    match stream.read_exact(&mut length) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.to_string()),
    }
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > maximum {
        return Err("the transport message exceeds its budget".to_string());
    }
    let mut message = vec![0_u8; length];
    stream
        .read_exact(&mut message)
        .map_err(|error| error.to_string())?;
    Ok(Some(message))
}

fn read_message(stream: &mut impl Read, maximum: usize) -> Result<Vec<u8>, String> {
    read_optional_message(stream, maximum)?
        .ok_or_else(|| "the transport closed before a message arrived".to_string())
}

fn write_message(stream: &mut impl Write, message: &[u8]) -> Result<(), String> {
    let length =
        u32::try_from(message.len()).map_err(|_| "the message is too large".to_string())?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|_| stream.write_all(message))
        .and_then(|_| stream.flush())
        .map_err(|error| error.to_string())
}

fn unix_us() -> Result<u64, String> {
    let value = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "the system clock failed".to_string())?
        .as_micros();
    u64::try_from(value).map_err(|_| "the system clock exceeds the protocol".to_string())
}

fn percentile(samples: &[u64], quantile: f64) -> u64 {
    let rank = (quantile * samples.len() as f64).ceil() as usize;
    samples[rank.saturating_sub(1).min(samples.len() - 1)]
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(&mut output, "{byte:02x}").expect("a string write cannot fail");
    }
    output
}
