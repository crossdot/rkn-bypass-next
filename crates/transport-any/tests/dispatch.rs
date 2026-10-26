//! `AnyClientTransport`/`AnyServerTransport` прогоняют общий `contract_suite`
//! над TLS и QUIC: `proxy-core` видит только `Transport`.

use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use transport_any::{AnyClientTransport, AnyServerTransport};
use transport_api::Transport;
use transport_quic::{QuicClientTransport, QuicServerTransport};

const CERT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-server.crt");
const CA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-ca.crt");
const KEY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-server.key");

fn certs(path: &str) -> Vec<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut BufReader::new(File::open(path).unwrap()))
        .collect::<Result<_, _>>()
        .unwrap()
}

fn roots() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    for c in certs(CA) {
        roots.add(c).unwrap();
    }
    roots
}

fn tls_server() -> Arc<ServerConfig> {
    let mut all = certs(CERT);
    all.extend(certs(CA));
    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut BufReader::new(File::open(KEY).unwrap()))
            .unwrap()
            .unwrap();
    Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(all, key)
            .unwrap(),
    )
}

fn tls_client() -> Arc<ClientConfig> {
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots())
            .with_no_client_auth(),
    )
}

async fn make_pair_tls() -> (AnyClientTransport, AnyServerTransport) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        AnyServerTransport::Tls(
            transport_tls::ServerTransport::accept(sock, tls_server(), Duration::from_secs(5))
                .await
                .unwrap(),
        )
    });
    let mut client = AnyClientTransport::Tls(
        transport_tls::ClientTransport::new(
            addr,
            "localhost",
            tls_client(),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .unwrap(),
    );
    client.connect().await.unwrap();
    let server = server.await.unwrap();
    (client, server)
}

async fn make_pair_quic() -> (AnyClientTransport, AnyServerTransport) {
    let server_cfg = transport_quic::server_config(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                {
                    let mut all = certs(CERT);
                    all.extend(certs(CA));
                    all
                },
                rustls_pemfile::private_key(&mut BufReader::new(File::open(KEY).unwrap()))
                    .unwrap()
                    .unwrap(),
            )
            .unwrap(),
    )
    .unwrap();
    let endpoint =
        Arc::new(quinn::Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap()).unwrap());
    let addr = endpoint.local_addr().unwrap();
    let ep = Arc::clone(&endpoint);
    let server = tokio::spawn(async move {
        let incoming = ep.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        AnyServerTransport::Quic(QuicServerTransport::new(Arc::clone(&ep), conn))
    });
    let client_cfg = transport_quic::client_config(
        ClientConfig::builder()
            .with_root_certificates(roots())
            .with_no_client_auth(),
    )
    .unwrap();
    let mut client = AnyClientTransport::Quic(
        QuicClientTransport::new(addr, "localhost", client_cfg, Duration::from_secs(5)).unwrap(),
    );
    client.connect().await.unwrap();
    let server = server.await.unwrap();
    (client, server)
}

#[tokio::test(flavor = "multi_thread")]
async fn tls_dispatch() {
    transport_quic::ensure_crypto_provider();
    testkit::contract_suite(
        make_pair_tls,
        &[testkit::Initiator::Client, testkit::Initiator::Server],
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn quic_dispatch() {
    transport_quic::ensure_crypto_provider();
    testkit::contract_suite(make_pair_quic, &[testkit::Initiator::Client]).await;
}

/// Регрессия: `relay` шлёт чанками (несколько `send` на поток).
/// `finish()` внутри `send` ломал бы второй чанк.
#[tokio::test(flavor = "multi_thread")]
async fn quic_multi_send_chunks() {
    transport_quic::ensure_crypto_provider();
    let (mut client, mut server) = make_pair_quic().await;
    client.send(b"aaa").await.unwrap();
    client.send(b"bbb").await.unwrap();
    client.send(b"ccc").await.unwrap();

    let mut got = Vec::new();
    let mut buf = [0u8; 64];
    while got.len() < 9 {
        let n = server.recv(&mut buf).await.unwrap();
        assert!(n > 0, "неожиданный EOF");
        got.extend_from_slice(&buf[..n]);
    }
    assert_eq!(&got, b"aaabbbccc");
    client.close().await.unwrap();
}
