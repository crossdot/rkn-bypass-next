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

/// Читает env-файл (`KEY=VALUE`, `#`-комментарии) и применяет к процессу.
fn load_env_file(path: &str) -> Result<(), String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("cannot read env file {path}: {e}"))?;
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            return Err(format!(
                "{path}:{}: expected KEY=VALUE, got `{line}`",
                i + 1
            ));
        };
        let k = k.trim();
        if k.is_empty() {
            return Err(format!("{path}:{}: empty key", i + 1));
        }
        let v = v.trim().trim_matches(|c| c == '"' || c == '\'');
        std::env::set_var(k, v);
    }
    Ok(())
}

/// `--check-config <env-file>`: валидация конфигурации без запуска сервера.
fn check_config(path: &str) -> Result<(), String> {
    load_env_file(path)?;

    let listen = env_or("LISTEN_ADDR", "127.0.0.1:8443");
    listen
        .parse::<SocketAddr>()
        .map_err(|e| format!("LISTEN_ADDR={listen}: {e}"))?;

    if let Ok(v) = std::env::var("TRANSPORT") {
        if !v.is_empty() {
            v.parse::<config::TransportStrategy>()
                .map_err(|e| format!("TRANSPORT={v}: {e}"))?;
        }
    }

    let cert_path = env_or("CERT_PATH", "");
    let key_path = env_or("KEY_PATH", "");
    let ca_path = env_or("CA_PATH", "");
    if cert_path.is_empty() {
        return Err("CERT_PATH is not set".into());
    }
    if key_path.is_empty() {
        return Err("KEY_PATH is not set".into());
    }
    if ca_path.is_empty() {
        return Err("CA_PATH is not set".into());
    }

    let mut certs = load_certs(&cert_path).map_err(|e| format!("CERT_PATH={cert_path}: {e}"))?;
    let key = load_key(&key_path).map_err(|e| format!("KEY_PATH={key_path}: {e}"))?;
    let ca_certs = load_certs(&ca_path).map_err(|e| format!("CA_PATH={ca_path}: {e}"))?;
    certs.extend(ca_certs.iter().cloned());

    let mut roots = RootCertStore::empty();
    for c in &ca_certs {
        roots
            .add(c.clone())
            .map_err(|e| format!("CA_PATH={ca_path}: {e}"))?;
    }
    let inner = server::AuthClientVerifier::build_inner(Arc::new(roots))
        .map_err(|e| format!("CA_PATH={ca_path}: {e}"))?;
    ServerConfig::builder()
        .with_client_cert_verifier(inner)
        .with_single_cert(certs, key)
        .map_err(|e| {
            format!("CERT_PATH/KEY_PATH: certificate/private key invalid or mismatch: {e}")
        })?;

    if let Ok(p) = std::env::var("RULES_PATH") {
        if !p.is_empty() {
            let toml = std::fs::read_to_string(&p).map_err(|e| format!("RULES_PATH={p}: {e}"))?;
            config::AddressRules::from_toml(&toml).map_err(|e| format!("RULES_PATH={p}: {e}"))?;
        }
    }
    if let Ok(p) = std::env::var("CLIENTS_PATH") {
        if !p.is_empty() {
            let toml = std::fs::read_to_string(&p).map_err(|e| format!("CLIENTS_PATH={p}: {e}"))?;
            config::ClientRegistry::from_toml(&toml)
                .map_err(|e| format!("CLIENTS_PATH={p}: {e}"))?;
        }
    }
    Ok(())
}

/// Если передан `--check-config <env-file>` — вернуть код выхода (иначе None).
fn check_config_if_requested() -> Option<i32> {
    let args: Vec<String> = std::env::args().collect();
    let pos = args.iter().position(|a| a == "--check-config")?;
    let Some(path) = args.get(pos + 1) else {
        eprintln!("error: --check-config requires <env-file>");
        return Some(2);
    };
    ensure_crypto_provider();
    match check_config(path) {
        Ok(()) => {
            println!("config OK: {path}");
            Some(0)
        }
        Err(e) => {
            eprintln!("error: {e}");
            Some(1)
        }
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

/// Если задан `TASK_METRICS_INTERVAL_S`, периодически пишет
/// `event=task_metrics alive_tasks=<n>` (tokio `Handle::metrics()`).
/// Только для нагрузочных испытаний (P11); по умолчанию выключено.
fn spawn_task_metrics() {
    let Ok(raw) = std::env::var("TASK_METRICS_INTERVAL_S") else {
        return;
    };
    let Ok(secs) = raw.parse::<u64>() else {
        return;
    };
    if secs == 0 {
        return;
    }
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(secs));
        loop {
            tick.tick().await;
            let alive_tasks = tokio::runtime::Handle::current()
                .metrics()
                .num_alive_tasks();
            tracing::info!(event = %"task_metrics", alive_tasks = alive_tasks);
        }
    });
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if let Some(code) = check_config_if_requested() {
        std::process::exit(code);
    }

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

    spawn_task_metrics();

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

#[cfg(test)]
mod check_config_tests {
    use super::*;
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    fn certs_dir() -> String {
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs").to_string()
    }

    fn tmp_file(name: &str, body: &str) -> String {
        let p = std::env::temp_dir().join(format!("rkn-check-{}-{name}", std::process::id()));
        std::fs::write(&p, body).unwrap();
        p.to_string_lossy().into_owned()
    }

    fn server_env(key_name: &str) -> String {
        let d = certs_dir();
        format!(
            "LISTEN_ADDR=127.0.0.1:18443\nTRANSPORT=tls\n\
             CERT_PATH={d}/dev-server.crt\nKEY_PATH={d}/{key_name}\nCA_PATH={d}/dev-ca.crt\n\
             RULES_PATH=\nCLIENTS_PATH=\n"
        )
    }

    #[test]
    fn valid_config_ok() {
        let _g = LOCK.lock().unwrap();
        let f = tmp_file("valid.env", &server_env("dev-server.key"));
        assert_eq!(check_config(&f), Ok(()));
    }

    #[test]
    fn missing_cert_fails() {
        let _g = LOCK.lock().unwrap();
        let f = tmp_file(
            "nocert.env",
            "LISTEN_ADDR=127.0.0.1:18443\nCERT_PATH=/nonexistent.crt\n\
             KEY_PATH=/nonexistent.key\nCA_PATH=/nonexistent.crt\n",
        );
        let e = check_config(&f).unwrap_err();
        assert!(e.contains("CERT_PATH"), "{e}");
    }

    #[test]
    fn key_cert_mismatch_fails() {
        let _g = LOCK.lock().unwrap();
        let f = tmp_file("mismatch.env", &server_env("dev-ca.key"));
        let e = check_config(&f).unwrap_err();
        assert!(e.to_lowercase().contains("mismatch"), "{e}");
    }

    #[test]
    fn broken_rules_fails() {
        let _g = LOCK.lock().unwrap();
        let rules = tmp_file("rules.toml", "this is not toml = = =\n");
        let d = certs_dir();
        let f = tmp_file(
            "brokenrules.env",
            &format!(
                "LISTEN_ADDR=127.0.0.1:18443\nTRANSPORT=tls\n\
                 CERT_PATH={d}/dev-server.crt\nKEY_PATH={d}/dev-server.key\n\
                 CA_PATH={d}/dev-ca.crt\nRULES_PATH={rules}\nCLIENTS_PATH=\n"
            ),
        );
        let e = check_config(&f).unwrap_err();
        assert!(e.contains("RULES_PATH"), "{e}");
    }
}
