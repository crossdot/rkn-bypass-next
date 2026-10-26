//! Контрактные тесты QUIC-транспорта (общий suite из `testkit`).

use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use transport_api::Transport;
use transport_quic::{ensure_crypto_provider, QuicClientTransport, QuicServerTransport};

const CERT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-server.crt");
const CA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-ca.crt");
const KEY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-server.key");

fn load_server_config() -> rustls::ServerConfig {
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
    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap()
}

fn load_client_config() -> rustls::ClientConfig {
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut BufReader::new(File::open(CA).unwrap())) {
        roots.add(cert.unwrap()).unwrap();
    }
    ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

async fn make_pair() -> (QuicClientTransport, QuicServerTransport) {
    let server_cfg = transport_quic::server_config(load_server_config()).unwrap();
    let endpoint =
        Arc::new(quinn::Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap()).unwrap());
    let addr: SocketAddr = endpoint.local_addr().unwrap();
    let ep = Arc::clone(&endpoint);
    let server = tokio::spawn(async move {
        let incoming = ep.accept().await.unwrap();
        // полный handshake, 0-RTT не используется (не зовём into_0rtt).
        let conn = incoming.await.unwrap();
        QuicServerTransport::new(Arc::clone(&ep), conn)
    });

    let client_cfg = transport_quic::client_config(load_client_config()).unwrap();
    let mut client =
        QuicClientTransport::new(addr, "localhost", client_cfg, Duration::from_secs(5)).unwrap();
    client.connect().await.unwrap();

    let server = server.await.unwrap();
    // `endpoint` держится и в `server` (Arc) — не дропается здесь.
    drop(endpoint);
    (client, server)
}

#[ignore = "TODO(P4b): STREAM frame не доходит до accept_bi после write (quinn driver); разобраться"]
#[tokio::test(flavor = "multi_thread")]
async fn contract() {
    ensure_crypto_provider();
    testkit::contract_suite(make_pair).await;
}
