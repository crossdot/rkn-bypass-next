//! Сервер: принимает логические потоки от клиента (TLS или QUIC) и открывает
//! TCP к запрошенному адресу (mTLS + адресные правила).
//!
//! Конфигурация через env: `TRANSPORT` (`auto`|`tls`|`quic`; дефолт `auto` —
//! TLS на TCP и QUIC на UDP одновременно), `LISTEN_ADDR`, `CERT_PATH`,
//! `KEY_PATH`, `CA_PATH`, `RULES_PATH`, `CLIENTS_PATH`.

use std::fs::File;
use std::io::{BufReader, IsTerminal};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::danger::ClientCertVerifier;
use rustls::{RootCertStore, ServerConfig};
use transport_any::AnyServerTransport;
use transport_tls::{ensure_crypto_provider, ServerTransport};

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, Box<dyn std::error::Error>> {
    rustls_pemfile::certs(&mut BufReader::new(File::open(path)?))
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn load_key(path: &str) -> Result<PrivateKeyDer<'static>, Box<dyn std::error::Error>> {
    rustls_pemfile::private_key(&mut BufReader::new(File::open(path)?))?.ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "private key not found").into()
    })
}

/// Загружает адресные правила из `RULES_PATH`, иначе — безопасный default.
fn load_address_rules() -> config::AddressRules {
    match std::env::var("RULES_PATH").ok().filter(|s| !s.is_empty()) {
        Some(path) => match std::fs::read_to_string(&path) {
            Ok(toml) => match config::AddressRules::from_toml(&toml) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("warning: bad config {path}: {e}; using default rules");
                    config::AddressRules::default()
                }
            },
            Err(e) => {
                eprintln!("warning: cannot read {path}: {e}; using default rules");
                config::AddressRules::default()
            }
        },
        None => config::AddressRules::default(),
    }
}

/// Загружает реестр клиентов из `CLIENTS_PATH`, иначе — пустой (fail closed).
fn load_client_registry() -> config::ClientRegistry {
    match std::env::var("CLIENTS_PATH").ok().filter(|s| !s.is_empty()) {
        Some(path) => match std::fs::read_to_string(&path) {
            Ok(toml) => match config::ClientRegistry::from_toml(&toml) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("warning: bad clients config {path}: {e}; no clients authorized");
                    config::ClientRegistry::default()
                }
            },
            Err(e) => {
                eprintln!("warning: cannot read {path}: {e}; no clients authorized");
                config::ClientRegistry::default()
            }
        },
        None => config::ClientRegistry::default(),
    }
}

/// TLS: `TcpListener` + per-connection rustls config с `AuthClientVerifier`
/// (адрес пира известен из `accept`).
async fn run_tls(
    listen_addr: &str,
    inner: Arc<dyn ClientCertVerifier>,
    services: Arc<server::Services>,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(listen_addr).await?;
    println!("TLS server listening on {listen_addr} (mTLS)");

    loop {
        let (sock, remote_addr) = listener.accept().await?;
        let inner = Arc::clone(&inner);
        let services = Arc::clone(&services);
        let certs = certs.clone();
        let key = key.clone_key();
        tokio::spawn(async move {
            let auth = server::AuthClientVerifier::new(
                inner,
                Arc::clone(&services.registry),
                Some(remote_addr),
            );
            let verifier: Arc<dyn ClientCertVerifier> = Arc::new(auth);
            let tls_config = match ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)
            {
                Ok(c) => Arc::new(c),
                Err(e) => {
                    eprintln!("tls config error: {e}");
                    return;
                }
            };
            match ServerTransport::accept(sock, tls_config, Duration::from_secs(10)).await {
                Ok(transport) => {
                    services.handle(AnyServerTransport::Tls(transport)).await;
                }
                Err(e) => eprintln!("handshake error: {e}"),
            }
        });
    }
}

/// QUIC: `quinn::Endpoint::server` + `accept` + `Incoming`. Verifier общий на
/// Endpoint, `remote_addr` до handshake недоступен → `None` (ADR-022).
async fn run_quic(
    listen_addr: &str,
    inner: Arc<dyn ClientCertVerifier>,
    services: Arc<server::Services>,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr: SocketAddr = listen_addr.parse()?;
    let auth = server::AuthClientVerifier::new(inner, Arc::clone(&services.registry), None);
    let verifier: Arc<dyn ClientCertVerifier> = Arc::new(auth);
    let rustls_config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?;
    let quinn_config = transport_quic::server_config(rustls_config)?;
    let endpoint = Arc::new(quinn::Endpoint::server(quinn_config, addr)?);
    println!("QUIC server listening on {listen_addr} (mTLS)");

    loop {
        let Some(incoming) = endpoint.accept().await else {
            return Ok(());
        };
        let services = Arc::clone(&services);
        let endpoint = Arc::clone(&endpoint);
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    let transport = AnyServerTransport::Quic(
                        transport_quic::QuicServerTransport::new(endpoint, conn),
                    );
                    services.handle(transport).await;
                }
                Err(e) => eprintln!("quic handshake error: {e}"),
            }
        });
    }
}

/// Dual-listen (`TRANSPORT=auto`): TLS на TCP и QUIC на UDP по одному адресу.
///
/// `inner`-верификатор цепочки, реестр клиентов, `SessionManager` и адресные
/// правила общие: `max_sessions` считается глобально, аудит идёт в один
/// subscriber (ADR-023). QUIC-верификатор по-прежнему один на Endpoint
/// (ADR-022) и построен из того же `inner`, поэтому состояния не расходятся.
async fn run_both(
    listen_addr: &str,
    inner: Arc<dyn ClientCertVerifier>,
    services: Arc<server::Services>,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<(), Box<dyn std::error::Error>> {
    let tls = run_tls(
        listen_addr,
        Arc::clone(&inner),
        Arc::clone(&services),
        certs.clone(),
        key.clone_key(),
    );
    let quic = run_quic(listen_addr, inner, services, certs, key);
    tokio::try_join!(tls, quic)?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ensure_crypto_provider();
    // Аудит-логи: компактный key=value на stderr; уровень по умолчанию info
    // (переопределяется RUST_LOG). См. ADR-021 «Аудит handshake'ей».
    tracing_subscriber::fmt()
        .compact()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        // key=value должно быть машинно-читаемым в файлах/journalctl/CI:
        // цвет только на терминале (ADR-021/ADR-023).
        .with_ansi(std::io::stderr().is_terminal())
        .init();

    let strategy = match std::env::var("TRANSPORT") {
        Ok(v) => v.parse::<config::TransportStrategy>()?,
        Err(_) => config::TransportStrategy::Auto,
    };
    let listen_addr = env_or("LISTEN_ADDR", "127.0.0.1:8443");
    let cert_path = env_or(
        "CERT_PATH",
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-server.crt"),
    );
    let ca_path = env_or(
        "CA_PATH",
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-ca.crt"),
    );
    let key_path = env_or(
        "KEY_PATH",
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-server.key"),
    );

    let rules = load_address_rules();
    let registry = Arc::new(load_client_registry());
    println!(
        "transport={strategy:?}, clients authorized: {}",
        registry.len()
    );

    // mTLS: доверяем CA (dev-ca) для клиентских сертификатов.
    let mut client_roots = RootCertStore::empty();
    for cert in load_certs(&ca_path)? {
        client_roots.add(cert)?;
    }
    // Внутренний верификатор цепочки — один раз, шарится между соединениями.
    let inner = server::AuthClientVerifier::build_inner(Arc::new(client_roots))?;

    let mut certs = load_certs(&cert_path)?;
    certs.extend(load_certs(&ca_path)?);
    let key = load_key(&key_path)?;

    let sessions = Arc::new(server::SessionManager::new());
    // Один экземпляр на процесс: TLS- и QUIC-циклы делят реестр, счётчик
    // сессий и правила (ADR-023 §8).
    let services = Arc::new(server::Services::new(registry, sessions, rules));
    match strategy {
        config::TransportStrategy::Auto => {
            run_both(&listen_addr, inner, services, certs, key).await?;
        }
        config::TransportStrategy::Tls => {
            run_tls(&listen_addr, inner, services, certs, key).await?;
        }
        config::TransportStrategy::Quic => {
            run_quic(&listen_addr, inner, services, certs, key).await?;
        }
    }
    Ok(())
}
