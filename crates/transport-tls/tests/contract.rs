//! Контрактные тесты TLS-транспорта (общий suite из `testkit`).

use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::net::TcpListener;
use transport_tls::{ensure_crypto_provider, ClientTransport, ServerTransport, Transport};

const CERT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-server.crt");
const CA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-ca.crt");
const KEY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-server.key");

fn load_server_config() -> Arc<ServerConfig> {
    let mut certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut BufReader::new(File::open(CERT).unwrap()))
            .collect::<Result<_, _>>()
            .unwrap();
    certs.extend(
        rustls_pemfile::certs(&mut BufReader::new(File::open(CA).unwrap()))
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
    );
    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut BufReader::new(File::open(KEY).unwrap()))
            .unwrap()
            .unwrap();
    Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap(),
    )
}

fn load_client_config() -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut BufReader::new(File::open(CA).unwrap())) {
        roots.add(cert.unwrap()).unwrap();
    }
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

async fn make_pair() -> (ClientTransport, ServerTransport) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let server_cfg = load_server_config();
    let server = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        ServerTransport::accept(sock, server_cfg, Duration::from_secs(5))
            .await
            .unwrap()
    });
    let mut client = ClientTransport::new(
        addr,
        "localhost",
        load_client_config(),
        Duration::from_secs(5),
        Duration::from_secs(5),
    )
    .unwrap();
    client.connect().await.unwrap();
    let server = server.await.unwrap();
    (client, server)
}

#[tokio::test]
async fn contract() {
    ensure_crypto_provider();
    testkit::contract_suite(make_pair).await;
}
