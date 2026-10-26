//! SOCKS5-клиент: принимает CONNECT от приложений и проксирует их через
//! TLS или QUIC (с mTLS) к серверу.
//!
//! Транспорт выбирает `TransportManager` (P5.3): детерминированная политика
//! `preferred` → fallback, TTL-кэш и backoff. Конфигурация через env:
//! `TRANSPORT` (`auto`|`tls`|`quic`, дефолт `auto`), `TRANSPORT_PREFERRED`,
//! `TRANSPORT_PROBE_TIMEOUT_MS`, `TRANSPORT_TTL_S`, `TRANSPORT_FAIL_TTL_S`,
//! `TRANSPORT_PROBE_ATTEMPTS`, `LISTEN_ADDR`, `SERVER_ADDR`, `CA_PATH`,
//! `CLIENT_CERT`, `CLIENT_KEY`.
//!
//! События выбора: `event=transport_selected` / `event=transport_state`
//! (см. ADR-023).

use std::fs::File;
use std::io::BufReader;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore};
use transport_any::AnyClientTransport;
use transport_manager::{Probe, TransportFactory, TransportManager, TransportProbe};
use transport_tls::{ensure_crypto_provider, TransportError};

const SERVER_NAME: &str = "localhost";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn load_client_config(
    ca_path: &str,
    client_cert_path: &str,
    client_key_path: &str,
) -> Result<ClientConfig, Box<dyn std::error::Error>> {
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut BufReader::new(File::open(ca_path)?)) {
        roots.add(cert?)?;
    }
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut BufReader::new(File::open(client_cert_path)?))
            .collect::<Result<_, _>>()?;
    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut BufReader::new(File::open(client_key_path)?))?
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "client key not found")
            })?;
    Ok(ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)?)
}

/// Создаёт транспорт нужного типа через общий конструктор
/// (`transport-manager::client_transport`) — без дублирования в приложениях.
fn build_transport(
    kind: config::TransportKind,
    server_addr: SocketAddr,
    rustls_config: &Arc<ClientConfig>,
) -> Result<AnyClientTransport, TransportError> {
    transport_manager::client_transport(
        kind,
        server_addr,
        SERVER_NAME,
        rustls_config,
        CONNECT_TIMEOUT,
        HANDSHAKE_TIMEOUT,
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ensure_crypto_provider();
    tracing_subscriber::fmt()
        .compact()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let policy = config::TransportPolicy::from_env()?;
    let listen_addr = env_or("LISTEN_ADDR", "127.0.0.1:1080");
    let server_addr_str = env_or("SERVER_ADDR", "127.0.0.1:8443");
    let server_addr: SocketAddr = server_addr_str
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve SERVER_ADDR {server_addr_str}: {e}"))?
        .next()
        .ok_or_else(|| format!("SERVER_ADDR {server_addr_str} resolved to no address"))?;
    let ca_path = env_or(
        "CA_PATH",
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-ca.crt"),
    );
    let client_cert = env_or("CLIENT_CERT", "");
    let client_key = env_or("CLIENT_KEY", "");
    if client_cert.is_empty() || client_key.is_empty() {
        return Err("CLIENT_CERT and CLIENT_KEY must be set".into());
    }

    let rustls_config = Arc::new(load_client_config(&ca_path, &client_cert, &client_key)?);

    let factory: TransportFactory = {
        let rustls_config = Arc::clone(&rustls_config);
        Arc::new(move |kind| build_transport(kind, server_addr, &rustls_config))
    };
    let probe: Arc<dyn Probe> = Arc::new(TransportProbe::new(
        Arc::clone(&factory),
        policy.probe_timeout,
        server_addr,
    ));
    let manager = Arc::new(TransportManager::new(policy.clone(), probe));

    let listener = TcpListener::bind(&listen_addr).await?;
    println!(
        "SOCKS5 listening on {listen_addr} (strategy={:?}, preferred={:?}, server {server_addr})",
        policy.strategy, policy.preferred
    );

    loop {
        let (app, _) = listener.accept().await?;
        let manager = Arc::clone(&manager);
        let factory = Arc::clone(&factory);
        tokio::spawn(async move {
            let selection = manager.select().await;
            let client = match factory(selection.kind) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("client init error: {e}");
                    return;
                }
            };
            match proxy_core::serve_client_connection(app, client, proxy_core::ACK_TIMEOUT).await {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("connection error: {e}");
                    // Транспортный сбой (не ответ цели) — повод перепроверить
                    // доступность на следующем соединении.
                    if matches!(e, proxy_core::ProxyError::Transport(_)) {
                        manager
                            .invalidate(
                                selection.kind,
                                transport_manager::SelectReason::FallbackPrevFailed,
                            )
                            .await;
                    }
                }
            }
        });
    }
}
