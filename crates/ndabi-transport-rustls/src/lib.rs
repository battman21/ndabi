//! Protect NDABI transport frames with a strict TLS 1.3 mutual-authentication profile.
//!
//! The caller owns certificate custody, revocation delivery, sockets, and timeouts.
//! This crate refuses early data and removes the redundant stream-length prefix.

#![forbid(unsafe_code)]

use std::fmt;
use std::io::{self, Read, Write};
use std::sync::Arc;

use ndabi_protocol::TRANSPORT_MIN_FRAME_BYTES;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};

pub const NDABI_ALPN: &[u8] = b"ndabi/2";
const FRAME_LENGTH_OFFSET: usize = 12;
const FRAME_PREFIX_BYTES: usize = 16;

#[derive(Clone)]
pub struct ClientTlsProfile {
    config: Arc<ClientConfig>,
}

#[derive(Clone)]
pub struct ServerTlsProfile {
    config: Arc<ServerConfig>,
}

#[derive(Debug)]
pub enum TransportTlsError {
    Allocation,
    Certificate(String),
    Configuration(&'static str),
    FrameLength,
    Io(io::Error),
    Tls(rustls::Error),
}

impl fmt::Display for TransportTlsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allocation => formatter.write_str("the transport frame allocation failed"),
            Self::Certificate(error) => {
                write!(formatter, "the certificate configuration failed: {error}")
            }
            Self::Configuration(error) => formatter.write_str(error),
            Self::FrameLength => formatter.write_str("the transport frame length is invalid"),
            Self::Io(error) => write!(formatter, "the transport input or output failed: {error}"),
            Self::Tls(error) => write!(formatter, "the TLS operation failed: {error}"),
        }
    }
}

impl std::error::Error for TransportTlsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Tls(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for TransportTlsError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<rustls::Error> for TransportTlsError {
    fn from(error: rustls::Error) -> Self {
        Self::Tls(error)
    }
}

pub fn server_profile(
    client_roots: impl IntoIterator<Item = CertificateDer<'static>>,
    certificate_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> Result<ServerTlsProfile, TransportTlsError> {
    if certificate_chain.is_empty() {
        return Err(TransportTlsError::Configuration(
            "the server certificate chain is empty",
        ));
    }
    let roots = root_store(client_roots)?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|error| TransportTlsError::Certificate(error.to_string()))?;
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(TransportTlsError::Tls)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificate_chain, private_key)
        .map_err(TransportTlsError::Tls)?;
    config.alpn_protocols = vec![NDABI_ALPN.to_vec()];
    config.max_early_data_size = 0;
    config.send_half_rtt_data = false;
    config.send_tls13_tickets = 0;
    Ok(ServerTlsProfile {
        config: Arc::new(config),
    })
}

pub fn client_profile(
    server_roots: impl IntoIterator<Item = CertificateDer<'static>>,
    certificate_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> Result<ClientTlsProfile, TransportTlsError> {
    if certificate_chain.is_empty() {
        return Err(TransportTlsError::Configuration(
            "the client certificate chain is empty",
        ));
    }
    let roots = root_store(server_roots)?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(TransportTlsError::Tls)?
        .with_root_certificates(roots)
        .with_client_auth_cert(certificate_chain, private_key)
        .map_err(TransportTlsError::Tls)?;
    config.alpn_protocols = vec![NDABI_ALPN.to_vec()];
    config.enable_early_data = false;
    Ok(ClientTlsProfile {
        config: Arc::new(config),
    })
}

pub fn establish_client<IO: Read + Write>(
    io: IO,
    profile: ClientTlsProfile,
    server_name: ServerName<'static>,
) -> Result<StreamOwned<ClientConnection, IO>, TransportTlsError> {
    let connection = ClientConnection::new(profile.config, server_name)?;
    let mut stream = StreamOwned::new(connection, io);
    while stream.conn.is_handshaking() {
        stream.conn.complete_io(&mut stream.sock)?;
    }
    validate_established(
        stream.conn.protocol_version(),
        stream.conn.alpn_protocol(),
        stream.conn.peer_certificates(),
    )?;
    Ok(stream)
}

pub fn establish_server<IO: Read + Write>(
    io: IO,
    profile: ServerTlsProfile,
) -> Result<StreamOwned<ServerConnection, IO>, TransportTlsError> {
    let connection = ServerConnection::new(profile.config)?;
    let mut stream = StreamOwned::new(connection, io);
    while stream.conn.is_handshaking() {
        stream.conn.complete_io(&mut stream.sock)?;
    }
    validate_established(
        stream.conn.protocol_version(),
        stream.conn.alpn_protocol(),
        stream.conn.peer_certificates(),
    )?;
    Ok(stream)
}

pub fn read_transport_frame<Reader: Read>(
    reader: &mut Reader,
    maximum_frame_bytes: u32,
    output: &mut Vec<u8>,
) -> Result<bool, TransportTlsError> {
    if maximum_frame_bytes < TRANSPORT_MIN_FRAME_BYTES as u32 {
        output.clear();
        return Err(TransportTlsError::FrameLength);
    }
    output.clear();
    output.resize(FRAME_PREFIX_BYTES, 0);
    if let Err(error) = reader.read_exact(&mut output[..1]) {
        output.clear();
        return if error.kind() == io::ErrorKind::UnexpectedEof {
            Ok(false)
        } else {
            Err(TransportTlsError::Io(error))
        };
    }
    if let Err(error) = reader.read_exact(&mut output[1..FRAME_PREFIX_BYTES]) {
        output.clear();
        return Err(TransportTlsError::Io(error));
    }
    let frame_bytes = u32::from_le_bytes(
        output[FRAME_LENGTH_OFFSET..FRAME_PREFIX_BYTES]
            .try_into()
            .expect("fixed frame prefix"),
    );
    if frame_bytes < TRANSPORT_MIN_FRAME_BYTES as u32 || frame_bytes > maximum_frame_bytes {
        output.clear();
        return Err(TransportTlsError::FrameLength);
    }
    let frame_bytes = frame_bytes as usize;
    if output
        .try_reserve_exact(frame_bytes - output.len())
        .is_err()
    {
        output.clear();
        return Err(TransportTlsError::Allocation);
    }
    output.resize(frame_bytes, 0);
    if let Err(error) = reader.read_exact(&mut output[FRAME_PREFIX_BYTES..]) {
        output.clear();
        return Err(TransportTlsError::Io(error));
    }
    Ok(true)
}

pub fn write_transport_frame<Writer: Write>(
    writer: &mut Writer,
    maximum_frame_bytes: u32,
    frame: &[u8],
) -> Result<(), TransportTlsError> {
    if frame.len() < TRANSPORT_MIN_FRAME_BYTES
        || frame.len() > maximum_frame_bytes as usize
        || frame.len() > u32::MAX as usize
        || u32::from_le_bytes(
            frame[FRAME_LENGTH_OFFSET..FRAME_PREFIX_BYTES]
                .try_into()
                .expect("checked frame prefix"),
        ) as usize
            != frame.len()
    {
        return Err(TransportTlsError::FrameLength);
    }
    writer.write_all(frame)?;
    writer.flush()?;
    Ok(())
}

fn root_store(
    certificates: impl IntoIterator<Item = CertificateDer<'static>>,
) -> Result<RootCertStore, TransportTlsError> {
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots
            .add(certificate)
            .map_err(|error| TransportTlsError::Certificate(error.to_string()))?;
    }
    if roots.is_empty() {
        return Err(TransportTlsError::Configuration(
            "the certificate trust store is empty",
        ));
    }
    Ok(roots)
}

fn validate_established(
    version: Option<rustls::ProtocolVersion>,
    alpn: Option<&[u8]>,
    peer_certificates: Option<&[CertificateDer<'_>]>,
) -> Result<(), TransportTlsError> {
    if version != Some(rustls::ProtocolVersion::TLSv1_3) {
        return Err(TransportTlsError::Configuration(
            "the connection did not negotiate TLS 1.3",
        ));
    }
    if alpn != Some(NDABI_ALPN) {
        return Err(TransportTlsError::Configuration(
            "the connection did not negotiate the NDABI protocol",
        ));
    }
    if peer_certificates.is_none_or(|certificates| certificates.is_empty()) {
        return Err(TransportTlsError::Configuration(
            "the connection did not authenticate a peer certificate",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    use ndabi_protocol::{
        digest_label, encode_transport, transport_frame_bytes, Authority, AuthorityContext,
        BackendIdentity, TransportDirection, TransportFields, TransportKind,
    };
    use rcgen::{
        date_time_ymd, BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, KeyUsagePurpose,
    };
    use rustls::pki_types::PrivatePkcs8KeyDer;

    use super::*;

    struct TestAuthority {
        certificate: CertificateDer<'static>,
        issuer: Issuer<'static, KeyPair>,
    }

    struct TestIdentity {
        certificate: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
    }

    #[test]
    fn frame_io_uses_the_authenticated_frame_length_without_an_extra_prefix() {
        let frame = hello_frame();
        let mut encoded = Vec::new();
        write_transport_frame(&mut encoded, 4096, &frame).expect("write frame");
        assert_eq!(encoded, frame);

        let mut decoded = vec![0xa5; 4];
        assert!(
            read_transport_frame(&mut Cursor::new(encoded), 4096, &mut decoded)
                .expect("read frame")
        );
        assert_eq!(decoded, frame);

        let mut closed = vec![0xa5; 4];
        assert!(
            !read_transport_frame(&mut Cursor::new(Vec::<u8>::new()), 4096, &mut closed)
                .expect("clean close")
        );
        assert!(closed.is_empty());
    }

    #[test]
    fn frame_io_refuses_bounded_and_truncated_lengths_without_partial_output() {
        let mut oversized = hello_frame();
        oversized[12..16].copy_from_slice(&4097_u32.to_le_bytes());
        let mut output = vec![0xa5; 4];
        assert!(matches!(
            read_transport_frame(&mut Cursor::new(oversized), 4096, &mut output),
            Err(TransportTlsError::FrameLength)
        ));
        assert!(output.is_empty());

        let mut truncated = hello_frame();
        truncated.truncate(32);
        assert!(matches!(
            read_transport_frame(&mut Cursor::new(truncated), 4096, &mut output),
            Err(TransportTlsError::Io(_))
        ));
        assert!(output.is_empty());
    }

    #[test]
    fn mutual_tls_accepts_valid_peers_and_same_authority_rotation() {
        let authority = test_authority();
        let client = test_identity(
            "client.ndabi.test",
            ExtendedKeyUsagePurpose::ClientAuth,
            &authority.issuer,
        );
        let server_one = test_identity(
            "server.ndabi.test",
            ExtendedKeyUsagePurpose::ServerAuth,
            &authority.issuer,
        );
        let server_two = test_identity(
            "server.ndabi.test",
            ExtendedKeyUsagePurpose::ServerAuth,
            &authority.issuer,
        );
        let client_profile = client_profile(
            [authority.certificate.clone()],
            vec![client.certificate],
            client.key,
        )
        .expect("client config");

        for server in [server_one, server_two] {
            let server_profile = server_profile(
                [authority.certificate.clone()],
                vec![server.certificate],
                server.key,
            )
            .expect("server config");
            exchange(client_profile.clone(), server_profile, "server.ndabi.test")
                .expect("mutual TLS exchange");
        }
    }

    #[test]
    fn mutual_tls_refuses_wrong_names_and_unknown_client_authorities() {
        let trusted = test_authority();
        let untrusted = test_authority();
        let valid_client = test_identity(
            "client.ndabi.test",
            ExtendedKeyUsagePurpose::ClientAuth,
            &trusted.issuer,
        );
        let unknown_client = test_identity(
            "client.ndabi.test",
            ExtendedKeyUsagePurpose::ClientAuth,
            &untrusted.issuer,
        );
        let server = test_identity(
            "server.ndabi.test",
            ExtendedKeyUsagePurpose::ServerAuth,
            &trusted.issuer,
        );
        let wrong_name_server_profile = server_profile(
            [trusted.certificate.clone()],
            vec![server.certificate],
            server.key,
        )
        .expect("server config");
        let valid_client_profile = client_profile(
            [trusted.certificate.clone()],
            vec![valid_client.certificate],
            valid_client.key,
        )
        .expect("client config");
        assert!(exchange(
            valid_client_profile,
            wrong_name_server_profile,
            "wrong.ndabi.test"
        )
        .is_err());

        let server = test_identity(
            "server.ndabi.test",
            ExtendedKeyUsagePurpose::ServerAuth,
            &trusted.issuer,
        );
        let unknown_client_server_profile = server_profile(
            [trusted.certificate.clone()],
            vec![server.certificate],
            server.key,
        )
        .expect("server config");
        let unknown_client_profile = client_profile(
            [trusted.certificate],
            vec![unknown_client.certificate],
            unknown_client.key,
        )
        .expect("client config");
        assert!(exchange(
            unknown_client_profile,
            unknown_client_server_profile,
            "server.ndabi.test"
        )
        .is_err());
    }

    #[test]
    fn tls_profile_refuses_expired_certificates_and_missing_alpn() {
        let authority = test_authority();
        let client = test_identity(
            "client.ndabi.test",
            ExtendedKeyUsagePurpose::ClientAuth,
            &authority.issuer,
        );
        let expired_server = test_expired_identity(
            "server.ndabi.test",
            ExtendedKeyUsagePurpose::ServerAuth,
            &authority.issuer,
        );
        let expired_client_profile = client_profile(
            [authority.certificate.clone()],
            vec![client.certificate],
            client.key,
        )
        .expect("client config");
        let expired_server_profile = server_profile(
            [authority.certificate.clone()],
            vec![expired_server.certificate],
            expired_server.key,
        )
        .expect("expired server config");
        assert!(exchange(
            expired_client_profile,
            expired_server_profile,
            "server.ndabi.test"
        )
        .is_err());

        let client = test_identity(
            "client.ndabi.test",
            ExtendedKeyUsagePurpose::ClientAuth,
            &authority.issuer,
        );
        let server = test_identity(
            "server.ndabi.test",
            ExtendedKeyUsagePurpose::ServerAuth,
            &authority.issuer,
        );
        let mut missing_alpn_client_profile = client_profile(
            [authority.certificate.clone()],
            vec![client.certificate],
            client.key,
        )
        .expect("client config");
        Arc::get_mut(&mut missing_alpn_client_profile.config)
            .expect("unique client config")
            .alpn_protocols
            .clear();
        let server_profile = server_profile(
            [authority.certificate],
            vec![server.certificate],
            server.key,
        )
        .expect("server config");
        assert!(exchange(
            missing_alpn_client_profile,
            server_profile,
            "server.ndabi.test"
        )
        .is_err());
    }

    fn exchange(
        client_profile: ClientTlsProfile,
        server_profile: ServerTlsProfile,
        server_name: &str,
    ) -> Result<(), String> {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(display)?;
        let address = listener.local_addr().map_err(display)?;
        let server = thread::spawn(move || -> Result<(), String> {
            let (socket, _) = listener.accept().map_err(display)?;
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .and_then(|_| socket.set_write_timeout(Some(Duration::from_secs(2))))
                .map_err(display)?;
            let mut stream = establish_server(socket, server_profile).map_err(display)?;
            let mut byte = [0; 1];
            stream.read_exact(&mut byte).map_err(display)?;
            stream.write_all(&byte).map_err(display)
        });
        let socket = TcpStream::connect(address).map_err(display)?;
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .and_then(|_| socket.set_write_timeout(Some(Duration::from_secs(2))))
            .map_err(display)?;
        let name = ServerName::try_from(server_name.to_string()).map_err(display)?;
        let client_result = (|| -> Result<(), String> {
            let mut stream = establish_client(socket, client_profile, name).map_err(display)?;
            stream.write_all(&[0x42]).map_err(display)?;
            let mut byte = [0; 1];
            stream.read_exact(&mut byte).map_err(display)?;
            if byte != [0x42] {
                return Err("the TLS result changed".to_string());
            }
            Ok(())
        })();
        let server_result = server
            .join()
            .map_err(|_| "the TLS server panicked".to_string())?;
        client_result.and(server_result)
    }

    fn test_authority() -> TestAuthority {
        let mut params = CertificateParams::new(Vec::new()).expect("CA parameters");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let key = KeyPair::generate().expect("CA key");
        let certificate = params.self_signed(&key).expect("CA certificate");
        TestAuthority {
            certificate: certificate.der().clone(),
            issuer: Issuer::new(params, key),
        }
    }

    fn test_identity(
        name: &str,
        usage: ExtendedKeyUsagePurpose,
        issuer: &Issuer<'static, KeyPair>,
    ) -> TestIdentity {
        test_identity_with_expiry(name, usage, issuer, false)
    }

    fn test_expired_identity(
        name: &str,
        usage: ExtendedKeyUsagePurpose,
        issuer: &Issuer<'static, KeyPair>,
    ) -> TestIdentity {
        test_identity_with_expiry(name, usage, issuer, true)
    }

    fn test_identity_with_expiry(
        name: &str,
        usage: ExtendedKeyUsagePurpose,
        issuer: &Issuer<'static, KeyPair>,
        expired: bool,
    ) -> TestIdentity {
        let mut params = CertificateParams::new(vec![name.to_string()]).expect("leaf parameters");
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![usage];
        if expired {
            params.not_before = date_time_ymd(2000, 1, 1);
            params.not_after = date_time_ymd(2001, 1, 1);
        }
        let key = KeyPair::generate().expect("leaf key");
        let certificate = params.signed_by(&key, issuer).expect("leaf certificate");
        TestIdentity {
            certificate: certificate.der().clone(),
            key: PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        }
    }

    fn hello_frame() -> Vec<u8> {
        let backend = BackendIdentity::new(
            1,
            2,
            digest_label(b"schema", b"transport IO"),
            digest_label(b"policy", b"transport IO"),
            digest_label(b"plan", b"transport IO"),
        )
        .expect("backend");
        let context = AuthorityContext::new(
            [1; 16],
            [2; 16],
            3,
            digest_label(b"capability", b"transport IO"),
            backend,
        )
        .expect("context");
        let authority = Authority::new_read([7; 32], 8, 9, u64::MAX, context).expect("authority");
        let mut payload = [0; 8];
        payload[0..2].copy_from_slice(&2_u16.to_le_bytes());
        payload[2..4].copy_from_slice(&2_u16.to_le_bytes());
        payload[4..8].copy_from_slice(&1024_u32.to_le_bytes());
        let mut frame = vec![0; transport_frame_bytes(payload.len()).expect("frame length")];
        encode_transport(
            &authority,
            TransportDirection::ClientToServer,
            TransportKind::Hello,
            TransportFields {
                auxiliary: 4096,
                ..TransportFields::empty()
            },
            &payload,
            &mut frame,
        )
        .expect("hello frame");
        frame
    }

    fn display(error: impl fmt::Display) -> String {
        error.to_string()
    }
}
