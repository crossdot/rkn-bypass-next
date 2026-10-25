//! Логика диагностики цепочки connect → TLS → SOCKS5 → relay.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::fs::File;
use std::io::BufReader;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

/// Адрес сервера по умолчанию.
pub const DEFAULT_SERVER_ADDR: &str = "127.0.0.1:8443";
/// Таймаут каждой сетевой операции.
pub const TIMEOUT: Duration = Duration::from_secs(5);

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

/// Загружает клиентский TLS-конфиг (доверяет dev CA).
pub fn load_client_config() -> Result<Arc<ClientConfig>, Box<dyn std::error::Error>> {
    let ca_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-ca.crt");
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut BufReader::new(File::open(ca_path)?)) {
        roots.add(cert?)?;
    }
    Ok(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

/// Прогоняет диагностику до цели и возвращает результаты этапов.
pub fn run_check(server_addr: SocketAddr, target: &socks5::Target) -> Vec<StageResult> {
    transport_tls::ensure_crypto_provider();
    let mut out = Vec::new();

    // [1] connect
    let sock = match TcpStream::connect_timeout(&server_addr, TIMEOUT) {
        Ok(s) => {
            out.push(StageResult {
                name: "connect",
                status: StageStatus::Ok,
            });
            s
        }
        Err(e) => {
            out.push(StageResult {
                name: "connect",
                status: StageStatus::Failed(io_class(&e).into()),
            });
            skip(&mut out, &["tls", "socks5", "relay"]);
            return out;
        }
    };
    let _ = sock.set_read_timeout(Some(TIMEOUT));
    let _ = sock.set_write_timeout(Some(TIMEOUT));

    // [2] tls
    let config = match load_client_config() {
        Ok(c) => c,
        Err(e) => {
            out.push(StageResult {
                name: "tls",
                status: StageStatus::Failed(e.to_string()),
            });
            skip(&mut out, &["socks5", "relay"]);
            return out;
        }
    };
    let server_name = match ServerName::try_from("localhost".to_owned()) {
        Ok(n) => n,
        Err(e) => {
            out.push(StageResult {
                name: "tls",
                status: StageStatus::Failed(e.to_string()),
            });
            skip(&mut out, &["socks5", "relay"]);
            return out;
        }
    };
    let conn = match ClientConnection::new(config, server_name) {
        Ok(c) => c,
        Err(e) => {
            out.push(StageResult {
                name: "tls",
                status: StageStatus::Failed(e.to_string()),
            });
            skip(&mut out, &["socks5", "relay"]);
            return out;
        }
    };
    let mut stream = StreamOwned::new(conn, sock);
    loop {
        if !stream.conn.is_handshaking() {
            break;
        }
        if let Err(e) = stream.conn.complete_io(&mut stream.sock) {
            out.push(StageResult {
                name: "tls",
                status: StageStatus::Failed(io_class(&e).into()),
            });
            skip(&mut out, &["socks5", "relay"]);
            return out;
        }
    }
    out.push(StageResult {
        name: "tls",
        status: StageStatus::Ok,
    });

    // [3] socks5 (Connect + ConnectAck)
    if let Err(e) = proxy_core::write_connect_target(&mut stream, target) {
        out.push(StageResult {
            name: "socks5",
            status: StageStatus::Failed(e.to_string()),
        });
        skip(&mut out, &["relay"]);
        return out;
    }
    let rep = match proxy_core::read_connect_ack(&mut stream) {
        Ok(rep) => rep,
        Err(e) => {
            let cls = match e {
                proxy_core::ProxyError::ConnectAckTimeout => "timeout",
                _ => "protocol-error",
            };
            out.push(StageResult {
                name: "socks5",
                status: StageStatus::Failed(cls.into()),
            });
            skip(&mut out, &["relay"]);
            return out;
        }
    };
    if rep != 0x00 {
        out.push(StageResult {
            name: "socks5",
            status: StageStatus::Failed(format!("{} (0x{rep:02x})", rep_class(rep))),
        });
        skip(&mut out, &["relay"]);
        return out;
    }
    out.push(StageResult {
        name: "socks5",
        status: StageStatus::Ok,
    });

    // [4] relay
    out.push(StageResult {
        name: "relay",
        status: StageStatus::Ok,
    });
    out
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
