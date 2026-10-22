use std::io::Cursor;
use std::sync::Arc;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};

struct Identity {
    certificate: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

struct Authority {
    params: CertificateParams,
    key: KeyPair,
    certificate: CertificateDer<'static>,
}

fn authority(common_name: &str) -> Authority {
    let key = KeyPair::generate().expect("key");
    let mut params = CertificateParams::new(vec![common_name.to_string()]).expect("name");
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let certificate = params.self_signed(&key).expect("self signed");
    Authority {
        certificate: certificate.der().clone(),
        params,
        key,
    }
}

fn server_identity(authority: &Authority) -> Identity {
    let key = KeyPair::generate().expect("key");
    let mut params = CertificateParams::new(vec!["localhost".to_string()]).expect("name");
    params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let issuer = Issuer::from_params(&authority.params, &authority.key);
    let certificate = params.signed_by(&key, &issuer).expect("issued");
    Identity {
        certificate: certificate.der().clone(),
        key: PrivateKeyDer::try_from(key.serialize_der()).expect("private key"),
    }
}

fn client_trusting(root: &CertificateDer<'static>) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(root.clone()).expect("trust anchor");
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

fn server_presenting(identity: &Identity) -> Arc<ServerConfig> {
    Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![identity.certificate.clone()], identity.key.clone_key())
            .expect("server certificate"),
    )
}

fn take_tls(
    buffer: &mut Vec<u8>,
    read: impl FnOnce(&mut Cursor<&[u8]>) -> std::io::Result<usize>,
) -> Result<(), String> {
    if buffer.is_empty() {
        return Ok(());
    }
    let mut cursor = Cursor::new(buffer.as_slice());
    let read = read(&mut cursor).map_err(|error| error.to_string())?;
    buffer.drain(..read);
    Ok(())
}

fn handshake(
    client_config: Arc<ClientConfig>,
    server_config: Arc<ServerConfig>,
) -> Result<(), String> {
    let name = ServerName::try_from("localhost").expect("server name");
    let mut client = ClientConnection::new(client_config, name).expect("client");
    let mut server = ServerConnection::new(server_config).expect("server");
    let mut client_to_server = Vec::new();
    let mut server_to_client = Vec::new();
    for _ in 0..8 {
        if client.wants_write() {
            client
                .write_tls(&mut client_to_server)
                .map_err(|error| error.to_string())?;
        }
        take_tls(&mut client_to_server, |cursor| server.read_tls(cursor))?;
        server
            .process_new_packets()
            .map_err(|error| error.to_string())?;
        if server.wants_write() {
            server
                .write_tls(&mut server_to_client)
                .map_err(|error| error.to_string())?;
        }
        take_tls(&mut server_to_client, |cursor| client.read_tls(cursor))?;
        client
            .process_new_packets()
            .map_err(|error| error.to_string())?;
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
    }
    Err("handshake did not finish".to_string())
}

#[test]
fn rustls_rejects_a_certificate_from_an_untrusted_chain() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let trusted = authority("trusted-ca");
    let server = server_identity(&trusted);
    let untrusted = authority("untrusted-ca");

    handshake(
        client_trusting(&trusted.certificate),
        server_presenting(&server),
    )
    .expect("trusted chain");
    let error = handshake(
        client_trusting(&untrusted.certificate),
        server_presenting(&server),
    )
    .expect_err("untrusted chain");
    let error = error.to_ascii_lowercase();
    assert!(
        error.contains("certificate") || error.contains("unknownissuer"),
        "unexpected verification error: {error}"
    );
}
