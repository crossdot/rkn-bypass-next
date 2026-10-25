//! Интеграционные тесты mTLS-аутентификации.

use std::fs;
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use transport_tls::{ensure_crypto_provider, ClientTransport, ServerTransport, Transport};

const CA_CERT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-ca.crt");
const CA_KEY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-ca.key");
const SERVER_CERT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-server.crt");
const SERVER_KEY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-server.key");

fn read(path: &str) -> String {
    fs::read_to_string(path).unwrap()
}

fn certs_from(path: &str) -> Vec<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut read(path).as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

fn certs_from_str(pem: &str) -> Vec<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

fn key_from(path: &str) -> PrivateKeyDer<'static> {
    rustls_pemfile::private_key(&mut read(path).as_bytes())
        .unwrap()
        .unwrap()
}

fn key_from_str(pem: &str) -> PrivateKeyDer<'static> {
    rustls_pemfile::private_key(&mut pem.as_bytes())
        .unwrap()
        .unwrap()
}

fn ca_root_store() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    for c in certs_from(CA_CERT) {
        roots.add(c).unwrap();
    }
    roots
}

/// Генерирует клиентский сертификат, подписанный dev-ca.
fn gen_client(id: &str) -> crypto::GeneratedClient {
    crypto::generate_client_cert(id, &read(CA_CERT), &read(CA_KEY)).unwrap()
}

fn registry_with(clients: &[(String, String, bool)]) -> config::ClientRegistry {
    let mut toml = String::new();
    for (id, cert, revoked) in clients {
        toml.push_str(&format!(
            "[[server.clients]]\nclient_id = \"{id}\"\nkey_material = '''{cert}'''\nrevoked = {revoked}\n"
        ));
    }
    config::ClientRegistry::from_toml(&toml).unwrap()
}

fn build_server_config(registry: Arc<config::ClientRegistry>) -> Arc<ServerConfig> {
    let mut certs = certs_from(SERVER_CERT);
    certs.extend(certs_from(CA_CERT));
    let key = key_from(SERVER_KEY);
    let auth = server::AuthClientVerifier::new(Arc::new(ca_root_store()), registry).unwrap();
    Arc::new(
        ServerConfig::builder()
            .with_client_cert_verifier(Arc::new(auth))
            .with_single_cert(certs, key)
            .unwrap(),
    )
}

fn build_client_config(client: &crypto::GeneratedClient) -> Arc<ClientConfig> {
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(ca_root_store())
            .with_client_auth_cert(
                certs_from_str(&client.cert_pem),
                key_from_str(&String::from_utf8_lossy(client.key_pem.expose())),
            )
            .unwrap(),
    )
}

/// Прогоняет TLS-хендшейк и возвращает, успешен ли он с обеих сторон.
fn handshake_ok(server_config: Arc<ServerConfig>, client_config: Arc<ClientConfig>) -> bool {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (sock, _) = listener.accept().unwrap();
        ServerTransport::accept(sock, server_config, Duration::from_secs(5)).is_ok()
    });
    let mut client = ClientTransport::new(
        addr,
        "localhost",
        client_config,
        Duration::from_secs(5),
        Duration::from_secs(5),
    )
    .unwrap();
    let client_ok = client.connect().is_ok();
    client_ok && server.join().unwrap()
}

#[test]
fn valid_client_connects() {
    ensure_crypto_provider();
    let client = gen_client("alice");
    let registry = Arc::new(registry_with(&[(
        "alice".into(),
        client.cert_pem.clone(),
        false,
    )]));
    let server_cfg = build_server_config(registry);
    let client_cfg = build_client_config(&client);
    assert!(handshake_ok(server_cfg, client_cfg));
}

#[test]
fn unknown_client_rejected() {
    ensure_crypto_provider();
    let client = gen_client("alice");
    // Пустой реестр — клиент неизвестен.
    let registry = Arc::new(config::ClientRegistry::default());
    let server_cfg = build_server_config(registry);
    let client_cfg = build_client_config(&client);
    assert!(!handshake_ok(server_cfg, client_cfg));
}

#[test]
fn revoked_client_rejected() {
    ensure_crypto_provider();
    let client = gen_client("alice");
    let registry = Arc::new(registry_with(&[(
        "alice".into(),
        client.cert_pem.clone(),
        true,
    )]));
    let server_cfg = build_server_config(registry);
    let client_cfg = build_client_config(&client);
    assert!(!handshake_ok(server_cfg, client_cfg));
}

#[test]
fn rotation_old_rejected_new_works() {
    ensure_crypto_provider();
    let old = gen_client("alice");
    let new = gen_client("alice");

    // После ротации: реестр содержит только новый сертификат.
    let registry = Arc::new(registry_with(&[(
        "alice".into(),
        new.cert_pem.clone(),
        false,
    )]));
    let server_cfg = build_server_config(registry);

    assert!(!handshake_ok(
        Arc::clone(&server_cfg),
        build_client_config(&old)
    ));
    assert!(handshake_ok(server_cfg, build_client_config(&new)));
}

#[test]
fn two_clients_dont_conflict() {
    ensure_crypto_provider();
    let a = gen_client("alice");
    let b = gen_client("bob");
    let registry = Arc::new(registry_with(&[
        ("alice".into(), a.cert_pem.clone(), false),
        ("bob".into(), b.cert_pem.clone(), false),
    ]));
    let server_cfg = build_server_config(registry);
    assert!(handshake_ok(
        Arc::clone(&server_cfg),
        build_client_config(&a)
    ));
    assert!(handshake_ok(server_cfg, build_client_config(&b)));
}
