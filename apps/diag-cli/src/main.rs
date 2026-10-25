//! `diag check <host>:<port>` — диагностика цепочки
//! connect → TLS → SOCKS5-handshake → relay с классом ошибки на каждом этапе.

use std::fs::File;
use std::io::BufReader;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use transport_tls::ensure_crypto_provider;

const SERVER_ADDR: &str = "127.0.0.1:8443";
const TIMEOUT: Duration = Duration::from_secs(5);

fn load_client_config() -> Result<Arc<ClientConfig>, Box<dyn std::error::Error>> {
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

/// Разбирает `host:port` (домен, IPv4, IPv6 в скобках или без).
fn parse_target(s: &str) -> Result<socks5::Target, String> {
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

fn io_class(e: &std::io::Error) -> &'static str {
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

fn rep_class(rep: u8) -> &'static str {
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    ensure_crypto_provider();
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 || args[1] != "check" {
        eprintln!("usage: diag-cli check <host>:<port>");
        std::process::exit(2);
    }
    let target = match parse_target(&args[2]) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("bad target: {e}");
            std::process::exit(2);
        }
    };

    let server_addr: SocketAddr = SERVER_ADDR.parse()?;
    println!("diag check {} -> server {server_addr}", args[2]);

    // [1] connect
    let sock = match TcpStream::connect_timeout(&server_addr, TIMEOUT) {
        Ok(s) => {
            println!("[1] connect   OK");
            s
        }
        Err(e) => {
            println!("[1] connect   FAIL: {}", io_class(&e));
            return Ok(());
        }
    };
    sock.set_read_timeout(Some(TIMEOUT))?;
    sock.set_write_timeout(Some(TIMEOUT))?;

    // [2] tls
    let config = load_client_config()?;
    let server_name = match ServerName::try_from("localhost".to_owned()) {
        Ok(n) => n,
        Err(e) => {
            println!("[2] tls       FAIL: invalid server name: {e}");
            return Ok(());
        }
    };
    let conn = match ClientConnection::new(config, server_name) {
        Ok(c) => c,
        Err(e) => {
            println!("[2] tls       FAIL: {e}");
            return Ok(());
        }
    };
    let mut stream = StreamOwned::new(conn, sock);
    loop {
        if !stream.conn.is_handshaking() {
            break;
        }
        if let Err(e) = stream.conn.complete_io(&mut stream.sock) {
            println!("[2] tls       FAIL: {}", io_class(&e));
            return Ok(());
        }
    }
    println!("[2] tls       OK");

    // [3] socks5 (Connect + ConnectAck)
    if let Err(e) = proxy_core::write_connect_target(&mut stream, &target) {
        println!("[3] socks5    FAIL: {e}");
        return Ok(());
    }
    let rep = match proxy_core::read_connect_ack(&mut stream) {
        Ok(rep) => rep,
        Err(e) => {
            let cls = match e {
                proxy_core::ProxyError::ConnectAckTimeout => "timeout",
                _ => "protocol-error",
            };
            println!("[3] socks5    FAIL: {cls}");
            return Ok(());
        }
    };
    if rep != 0x00 {
        println!("[3] socks5    FAIL: {} (0x{rep:02x})", rep_class(rep));
        println!("[4] relay     skipped");
        return Ok(());
    }
    println!("[3] socks5    OK");

    // [4] relay
    println!("[4] relay     ready (connection established)");

    Ok(())
}
