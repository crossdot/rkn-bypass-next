//! Rolling upgrade: новый клиент (Ping/Pong) против старого сервера (P5.3).
//!
//! Старый сервер знает только `Connect`/`ConnectAck`. Проба `Ping` для него —
//! неизвестный kind: соединение закрывается без ответа. Политика обязана
//! детерминированно вернуть `preferred` (`all_failed_default`), а обычный
//! CONNECT — продолжить работать.

use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::net::TcpListener;

use config::{TransportKind, TransportPolicy, TransportStrategy};
use transport_manager::{
    client_transport, Probe, SelectReason, TransportFactory, TransportManager, TransportProbe,
};
use transport_tls::{ServerTransport, Transport};

const CERT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-server.crt");
const CA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-ca.crt");
const KEY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-server.key");

fn load_certs(path: &str) -> Vec<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut BufReader::new(File::open(path).unwrap()))
        .collect::<Result<_, _>>()
        .unwrap()
}

fn load_key(path: &str) -> PrivateKeyDer<'static> {
    rustls_pemfile::private_key(&mut BufReader::new(File::open(path).unwrap()))
        .unwrap()
        .unwrap()
}

fn server_config() -> Arc<ServerConfig> {
    let mut certs = load_certs(CERT);
    certs.extend(load_certs(CA));
    Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, load_key(KEY))
            .unwrap(),
    )
}

fn client_config() -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for cert in load_certs(CA) {
        roots.add(cert).unwrap();
    }
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// «Старый» сервер: отвечает только на `Connect`, любой другой kind
/// (Ping) закрывает соединение — как сервер до P5.3.
async fn spawn_old_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = server_config();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            let config = Arc::clone(&config);
            tokio::spawn(async move {
                let Ok(mut transport) =
                    ServerTransport::accept(sock, config, Duration::from_secs(5)).await
                else {
                    return;
                };
                let Ok(message) = protocol::read_message(&mut transport).await else {
                    return;
                };
                if message.kind != protocol::MessageKind::Connect {
                    return; // Ping неизвестен: без ответа, соединение закрыто
                }
                let _ = protocol::write_message(
                    &mut transport,
                    &protocol::Message::new(protocol::MessageKind::ConnectAck, vec![0x00]),
                )
                .await;
                let mut buf = [0u8; 1];
                let _ = transport.recv(&mut buf).await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn new_client_works_against_old_server_without_ping_pong() {
    transport_tls::ensure_crypto_provider();
    let addr = spawn_old_server().await;

    let policy = TransportPolicy {
        strategy: TransportStrategy::Auto,
        preferred: TransportKind::Tls,
        probe_timeout: Duration::from_millis(300),
        ..TransportPolicy::default()
    };
    let config = client_config();
    let factory: TransportFactory = {
        let config = Arc::clone(&config);
        Arc::new(move |kind| {
            client_transport(
                kind,
                addr,
                "localhost",
                &config,
                Duration::from_secs(2),
                Duration::from_secs(2),
            )
        })
    };
    let probe: Arc<dyn Probe> = Arc::new(TransportProbe::new(
        Arc::clone(&factory),
        policy.probe_timeout,
        addr,
    ));
    let manager = TransportManager::new(policy, probe);

    // Проба TLS упирается в отсутствие Pong, QUIC — в закрытый UDP.
    let selection = manager.select().await;
    assert_eq!(selection.kind, TransportKind::Tls);
    assert_eq!(selection.reason, SelectReason::AllFailedDefault);

    // Несмотря на провал пробы, обычный CONNECT к старому серверу работает.
    let mut client = factory(TransportKind::Tls).unwrap();
    client.connect().await.expect("tls connect");
    let target = socks5::Target {
        addr: socks5::Addr::IPv4([127, 0, 0, 1]),
        port: 80,
    };
    proxy_core::write_connect_target(&mut client, &target)
        .await
        .expect("connect target");
    let rep = tokio::time::timeout(
        Duration::from_secs(2),
        proxy_core::read_connect_ack(&mut client),
    )
    .await
    .expect("ack timeout")
    .expect("ack");
    assert_eq!(rep, 0x00, "старый сервер подтверждает CONNECT");
}
