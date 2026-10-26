//! Общие хелперы интеграционных тестов mTLS (server + client).

use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use transport_tls::{ClientTransport, ServerTransport, Transport};

pub use transport_tls::ensure_crypto_provider;

pub const CA_CERT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-ca.crt");
pub const CA_KEY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-ca.key");
pub const SERVER_CERT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-server.crt");
pub const SERVER_KEY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-server.key");

pub fn read(path: &str) -> String {
    fs::read_to_string(path).unwrap()
}

pub fn certs_from(path: &str) -> Vec<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut read(path).as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

pub fn certs_from_str(pem: &str) -> Vec<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

pub fn key_from(path: &str) -> PrivateKeyDer<'static> {
    rustls_pemfile::private_key(&mut read(path).as_bytes())
        .unwrap()
        .unwrap()
}

pub fn key_from_str(pem: &str) -> PrivateKeyDer<'static> {
    rustls_pemfile::private_key(&mut pem.as_bytes())
        .unwrap()
        .unwrap()
}

pub fn ca_root_store() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    for c in certs_from(CA_CERT) {
        roots.add(c).unwrap();
    }
    roots
}

/// Генерирует клиентский сертификат, подписанный dev-ca.
pub fn gen_client(id: &str) -> crypto::GeneratedClient {
    crypto::generate_client_cert(id, &read(CA_CERT), &read(CA_KEY)).unwrap()
}

pub fn registry_with(clients: &[(String, String, bool)]) -> config::ClientRegistry {
    let mut toml = String::new();
    for (id, cert, revoked) in clients {
        toml.push_str(&format!(
            "[[server.clients]]\nclient_id = \"{id}\"\nkey_material = '''{cert}'''\nrevoked = {revoked}\n"
        ));
    }
    config::ClientRegistry::from_toml(&toml).unwrap()
}

fn build_server_config(
    registry: Arc<config::ClientRegistry>,
    remote_addr: SocketAddr,
) -> Arc<ServerConfig> {
    let mut certs = certs_from(SERVER_CERT);
    certs.extend(certs_from(CA_CERT));
    let key = key_from(SERVER_KEY);
    let inner = server::AuthClientVerifier::build_inner(Arc::new(ca_root_store())).unwrap();
    let auth = server::AuthClientVerifier::new(inner, registry, remote_addr);
    Arc::new(
        ServerConfig::builder()
            .with_client_cert_verifier(Arc::new(auth))
            .with_single_cert(certs, key)
            .unwrap(),
    )
}

pub fn build_client_config(client: &crypto::GeneratedClient) -> Arc<ClientConfig> {
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

/// Прогоняет TLS-хендшейк с реальным remote_addr (как в main.rs) и
/// возвращает, успешен ли он с обеих сторон.
pub async fn handshake_ok(
    registry: Arc<config::ClientRegistry>,
    client_config: Arc<ClientConfig>,
) -> bool {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (sock, peer) = listener.accept().await.unwrap();
        let server_config = build_server_config(registry, peer);
        ServerTransport::accept(sock, server_config, Duration::from_secs(5))
            .await
            .is_ok()
    });
    let mut client = ClientTransport::new(
        addr,
        "localhost",
        client_config,
        Duration::from_secs(5),
        Duration::from_secs(5),
    )
    .unwrap();
    let client_ok = client.connect().await.is_ok();
    client_ok && server.await.unwrap()
}
