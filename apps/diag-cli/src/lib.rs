//! Логика диагностики цепочки connect → handshake → data (Ping/Pong) → SOCKS5.
//!
//! Проверка доступности и передача данных выполняются общим модулем
//! `transport-manager` (та же проба, что у политики выбора транспорта), чтобы
//! diag-cli и runtime не расходились.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::fs::File;
use std::io::BufReader;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rustls::{ClientConfig, RootCertStore};
use transport_manager::{client_transport, Probe, ProbeFailure, TransportProbe};
use transport_tls::Transport;

/// Адрес сервера по умолчанию.
pub const DEFAULT_SERVER_ADDR: &str = "127.0.0.1:8443";
/// Таймаут каждой сетевой операции.
pub const TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Статус этапа диагностики.
#[derive(Debug, PartialEq, Eq)]
pub enum StageStatus {
    /// Этап прошёл успешно.
    Ok,
    /// Этап не прошёл — с классом ошибки.
    Failed(String),
    /// Этап пропущен из-за сбоя предыдущего.
    Skipped,
}

/// Результат одного этапа.
#[derive(Debug, PartialEq, Eq)]
pub struct StageResult {
    /// Имя этапа.
    pub name: &'static str,
    /// Статус этапа.
    pub status: StageStatus,
}

/// Разбирает `host:port` (домен, IPv4, IPv6 в скобках или без).
pub fn parse_target(s: &str) -> Result<socks5::Target, String> {
    let (host, port_str) = s.rsplit_once(':').ok_or("expected <host>:<port>")?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| format!("invalid port: {port_str}"))?;
    let host = host.trim_matches(['[', ']']);
    let addr = if let Ok(ip) = host.parse::<Ipv4Addr>() {
        socks5::Addr::IPv4(ip.octets())
    } else if let Ok(ip) = host.parse::<Ipv6Addr>() {
        socks5::Addr::IPv6(ip.octets())
    } else if !host.is_empty() {
        socks5::Addr::Domain(host.as_bytes().to_vec())
    } else {
        return Err("empty host".into());
    };
    Ok(socks5::Target { addr, port })
}

/// Класс io-ошибки.
pub fn io_class(e: &std::io::Error) -> &'static str {
    use std::io::ErrorKind::*;
    match e.kind() {
        ConnectionRefused => "connection-refused",
        TimedOut | WouldBlock => "timeout",
        NetworkUnreachable => "network-unreachable",
        HostUnreachable => "host-unreachable",
        ConnectionReset => "connection-reset",
        _ => "io",
    }
}

/// Класс SOCKS5 REP-кода.
pub fn rep_class(rep: u8) -> &'static str {
    match rep {
        0x00 => "ok",
        0x01 => "general-failure",
        0x02 => "not-allowed",
        0x03 => "network-unreachable",
        0x04 => "host-unreachable",
        0x05 => "connection-refused",
        0x07 => "command-not-supported",
        _ => "unknown",
    }
}

/// Загружает клиентский TLS-конфиг.
///
/// `CA_PATH` переопределяет CA (по умолчанию dev CA). Если заданы и
/// `CLIENT_CERT`, и `CLIENT_KEY` — включается mTLS (как у клиента против
/// текущего сервера, ADR-021); иначе — без клиентского сертификата.
pub fn load_client_config() -> Result<Arc<ClientConfig>, Box<dyn std::error::Error>> {
    let ca_path = std::env::var("CA_PATH").unwrap_or_else(|_| {
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-ca.crt").to_string()
    });
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut BufReader::new(File::open(&ca_path)?)) {
        roots.add(cert?)?;
    }
    let builder = ClientConfig::builder().with_root_certificates(roots);

    let cert_path = std::env::var("CLIENT_CERT").ok().filter(|s| !s.is_empty());
    let key_path = std::env::var("CLIENT_KEY").ok().filter(|s| !s.is_empty());
    let config = match (cert_path, key_path) {
        (Some(cert_path), Some(key_path)) => {
            let certs: Vec<_> = rustls_pemfile::certs(&mut BufReader::new(File::open(&cert_path)?))
                .collect::<Result<_, _>>()?;
            let key = rustls_pemfile::private_key(&mut BufReader::new(File::open(&key_path)?))?
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::NotFound, "client key not found")
                })?;
            builder.with_client_auth_cert(certs, key)?
        }
        _ => builder.with_no_client_auth(),
    };
    Ok(Arc::new(config))
}

fn ok(name: &'static str) -> StageResult {
    StageResult {
        name,
        status: StageStatus::Ok,
    }
}

fn failed(name: &'static str, msg: impl Into<String>) -> StageResult {
    StageResult {
        name,
        status: StageStatus::Failed(msg.into()),
    }
}

fn failure_message(failure: &ProbeFailure) -> String {
    match failure {
        ProbeFailure::UdpFiltered => "udp-filtered".into(),
        ProbeFailure::TlsRefused => "tls-refused".into(),
        ProbeFailure::ServerUnreachable => "server-unreachable".into(),
        ProbeFailure::Handshake(msg) => format!("handshake: {msg}"),
        ProbeFailure::DataPath(msg) => format!("data-path: {msg}"),
    }
}

/// Прогоняет диагностику до цели для указанного транспорта.
///
/// Этапы: `connect` → `handshake` → `data` (Ping/Pong, 1 байт) → `socks5`
/// (Connect + ConnectAck на отдельном соединении).
pub async fn run_check_kind(
    server_addr: SocketAddr,
    target: &socks5::Target,
    kind: config::TransportKind,
) -> Vec<StageResult> {
    transport_tls::ensure_crypto_provider();
    let mut out = Vec::new();

    let config = match load_client_config() {
        Ok(c) => c,
        Err(e) => {
            out.push(StageResult {
                name: "connect",
                status: StageStatus::Skipped,
            });
            out.push(failed("handshake", e.to_string()));
            skip(&mut out, &["data", "socks5"]);
            return out;
        }
    };

    let factory: transport_manager::TransportFactory = {
        let config = Arc::clone(&config);
        Arc::new(move |k: config::TransportKind| {
            client_transport(
                k,
                server_addr,
                "localhost",
                &config,
                CONNECT_TIMEOUT,
                HANDSHAKE_TIMEOUT,
            )
        })
    };
    let probe = TransportProbe::new(factory, TIMEOUT, server_addr);
    let report = probe.probe(kind).await;

    match report.failure {
        None => {
            out.push(ok("connect"));
            out.push(ok("handshake"));
            out.push(ok("data"));
        }
        Some(
            failure @ (ProbeFailure::TlsRefused
            | ProbeFailure::UdpFiltered
            | ProbeFailure::ServerUnreachable),
        ) => {
            out.push(failed("connect", failure_message(&failure)));
            skip(&mut out, &["handshake", "data", "socks5"]);
            return out;
        }
        Some(failure @ ProbeFailure::Handshake(_)) => {
            out.push(ok("connect"));
            out.push(failed("handshake", failure_message(&failure)));
            skip(&mut out, &["data", "socks5"]);
            return out;
        }
        Some(failure @ ProbeFailure::DataPath(_)) => {
            out.push(ok("connect"));
            out.push(ok("handshake"));
            out.push(failed("data", failure_message(&failure)));
            skip(&mut out, &["socks5"]);
            return out;
        }
    }

    // SOCKS5-этап: отдельное соединение (после Ping сервер закрывает поток).
    let mut client = match client_transport(
        kind,
        server_addr,
        "localhost",
        &config,
        CONNECT_TIMEOUT,
        HANDSHAKE_TIMEOUT,
    ) {
        Ok(c) => c,
        Err(e) => {
            out.push(failed("socks5", e.to_string()));
            return out;
        }
    };
    if let Err(e) = client.connect().await {
        out.push(failed("socks5", e.to_string()));
        return out;
    }
    if let Err(e) = proxy_core::write_connect_target(&mut client, target).await {
        out.push(failed("socks5", e.to_string()));
        return out;
    }
    let rep = match tokio::time::timeout(TIMEOUT, proxy_core::read_connect_ack(&mut client)).await {
        Ok(Ok(rep)) => rep,
        Ok(Err(e)) => {
            out.push(failed("socks5", e.to_string()));
            return out;
        }
        Err(_) => {
            out.push(failed("socks5", "timeout"));
            return out;
        }
    };
    if rep != 0x00 {
        out.push(failed(
            "socks5",
            format!("{} (0x{rep:02x})", rep_class(rep)),
        ));
        return out;
    }
    out.push(ok("socks5"));
    out
}

/// Совместимая обёртка: проверка TLS-транспорта.
pub async fn run_check(server_addr: SocketAddr, target: &socks5::Target) -> Vec<StageResult> {
    run_check_kind(server_addr, target, config::TransportKind::Tls).await
}

fn skip(out: &mut Vec<StageResult>, names: &[&'static str]) {
    for name in names {
        out.push(StageResult {
            name,
            status: StageStatus::Skipped,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4() {
        let t = parse_target("127.0.0.1:80").unwrap();
        assert_eq!(t.addr, socks5::Addr::IPv4([127, 0, 0, 1]));
        assert_eq!(t.port, 80);
    }

    #[test]
    fn parse_ipv6() {
        let t = parse_target("[::1]:8080").unwrap();
        assert_eq!(
            t.addr,
            socks5::Addr::IPv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        );
        assert_eq!(t.port, 8080);
    }

    #[test]
    fn parse_domain() {
        let t = parse_target("example.com:443").unwrap();
        assert_eq!(t.addr, socks5::Addr::Domain(b"example.com".to_vec()));
        assert_eq!(t.port, 443);
    }

    #[test]
    fn parse_bad_target() {
        assert!(parse_target("nocolon").is_err());
        assert!(parse_target("host:notaport").is_err());
    }

    #[test]
    fn rep_class_mapping() {
        assert_eq!(rep_class(0x00), "ok");
        assert_eq!(rep_class(0x02), "not-allowed");
        assert_eq!(rep_class(0x03), "network-unreachable");
        assert_eq!(rep_class(0x04), "host-unreachable");
        assert_eq!(rep_class(0x05), "connection-refused");
        assert_eq!(rep_class(0x07), "command-not-supported");
        assert_eq!(rep_class(0x7f), "unknown");
    }

    #[test]
    fn io_class_mapping() {
        use std::io::ErrorKind::*;
        assert_eq!(
            io_class(&std::io::Error::from(ConnectionRefused)),
            "connection-refused"
        );
        assert_eq!(io_class(&std::io::Error::from(TimedOut)), "timeout");
        assert_eq!(
            io_class(&std::io::Error::from(NetworkUnreachable)),
            "network-unreachable"
        );
        assert_eq!(
            io_class(&std::io::Error::from(HostUnreachable)),
            "host-unreachable"
        );
    }
}
