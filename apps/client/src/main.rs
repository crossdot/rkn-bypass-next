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
use std::io::{BufReader, IsTerminal};
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

/// `--check-config <env-file>`: валидация конфигурации без запуска клиента.
fn check_config(path: &str) -> Result<(), String> {
    load_env_file(path)?;

    let listen = env_or("LISTEN_ADDR", "127.0.0.1:1080");
    listen
        .parse::<SocketAddr>()
        .map_err(|e| format!("LISTEN_ADDR={listen}: {e}"))?;

    let server = env_or("SERVER_ADDR", "");
    if server.is_empty() {
        return Err("SERVER_ADDR is not set".into());
    }
    server
        .to_socket_addrs()
        .map_err(|e| format!("SERVER_ADDR={server}: {e}"))?
        .next()
        .ok_or_else(|| format!("SERVER_ADDR={server}: resolved to no address"))?;

    config::TransportPolicy::from_env().map_err(|e| format!("transport policy: {e}"))?;

    let ca = env_or("CA_PATH", "");
    let ccert = env_or("CLIENT_CERT", "");
    let ckey = env_or("CLIENT_KEY", "");
    if ca.is_empty() {
        return Err("CA_PATH is not set".into());
    }
    if ccert.is_empty() {
        return Err("CLIENT_CERT is not set".into());
    }
    if ckey.is_empty() {
        return Err("CLIENT_KEY is not set".into());
    }

    load_client_config(&ca, &ccert, &ckey).map_err(|e| {
        format!("CA_PATH/CLIENT_CERT/CLIENT_KEY: certificate/private key invalid or mismatch: {e}")
    })?;
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

#[cfg(test)]
mod check_config_tests {
    use super::*;
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    fn certs_dir() -> String {
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs").to_string()
    }

    fn tmp_file(name: &str, body: &str) -> String {
        let p = std::env::temp_dir().join(format!("rkn-check-cli-{}-{name}", std::process::id()));
        std::fs::write(&p, body).unwrap();
        p.to_string_lossy().into_owned()
    }

    fn client_env(key_name: &str) -> String {
        let d = certs_dir();
        format!(
            "LISTEN_ADDR=127.0.0.1:11080\nSERVER_ADDR=127.0.0.1:18443\nTRANSPORT=tls\n\
             CA_PATH={d}/dev-ca.crt\nCLIENT_CERT={d}/dev-server.crt\nCLIENT_KEY={d}/{key_name}\n"
        )
    }

    #[test]
    fn valid_config_ok() {
        let _g = LOCK.lock().unwrap();
        let f = tmp_file("valid.env", &client_env("dev-server.key"));
        assert_eq!(check_config(&f), Ok(()));
    }

    #[test]
    fn missing_cert_fails() {
        let _g = LOCK.lock().unwrap();
        let f = tmp_file(
            "nocert.env",
            "LISTEN_ADDR=127.0.0.1:11080\nSERVER_ADDR=127.0.0.1:18443\n\
             CA_PATH=/nonexistent.crt\nCLIENT_CERT=/nonexistent.crt\nCLIENT_KEY=/nonexistent.key\n",
        );
        let e = check_config(&f).unwrap_err();
        assert!(e.contains("CA_PATH/CLIENT_CERT/CLIENT_KEY"), "{e}");
    }

    #[test]
    fn key_cert_mismatch_fails() {
        let _g = LOCK.lock().unwrap();
        let f = tmp_file("mismatch.env", &client_env("dev-ca.key"));
        let e = check_config(&f).unwrap_err();
        assert!(e.to_lowercase().contains("mismatch"), "{e}");
    }
}
