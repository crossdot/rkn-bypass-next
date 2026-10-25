//! Интеграционные тесты SOCKS5-режима.

use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use transport_tls::{ensure_crypto_provider, ClientTransport, ServerTransport};

const CERT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-server.crt");
const CA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-ca.crt");
const KEY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-server.key");

fn load_server_config() -> Arc<ServerConfig> {
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
    Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap(),
    )
}

fn load_client_config(trust_server: bool) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    if trust_server {
        for cert in rustls_pemfile::certs(&mut BufReader::new(File::open(CA).unwrap())) {
            roots.add(cert.unwrap()).unwrap();
        }
    }
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

fn socket_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let a = TcpStream::connect(addr).unwrap();
    let (b, _) = listener.accept().unwrap();
    (a, b)
}

/// Закрытый (не слушающий) порт на 127.0.0.1.
fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn target_from_socket(addr: SocketAddr) -> socks5::Target {
    let a = match addr.ip() {
        IpAddr::V4(ip) => socks5::Addr::IPv4(ip.octets()),
        IpAddr::V6(ip) => socks5::Addr::IPv6(ip.octets()),
    };
    socks5::Target {
        addr: a,
        port: addr.port(),
    }
}

/// TCP echo-сервер на заданном адресе, принимающий ровно `n` соединений.
fn spawn_echo_target_on(bind: &str, n: usize) -> SocketAddr {
    let listener = TcpListener::bind(bind).unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for _ in 0..n {
            let (mut sock, _) = match listener.accept() {
                Ok(x) => x,
                Err(_) => break,
            };
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    });
    addr
}

/// TLS-сервер, принимающий ровно `n` соединений и релеющий их в цель.
fn spawn_tls_server(config: Arc<ServerConfig>, n: usize) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for _ in 0..n {
            let (sock, _) = listener.accept().unwrap();
            let config = Arc::clone(&config);
            thread::spawn(move || {
                let server = ServerTransport::accept(sock, config, Duration::from_secs(5)).unwrap();
                let _ = proxy_core::serve_server_connection(server, Duration::from_secs(5));
            });
        }
    });
    addr
}

/// TLS-сервер с произвольным поведением после приёма соединения.
fn spawn_fake_server<F: FnOnce(ServerTransport) + Send + 'static>(behavior: F) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server_cfg = load_server_config();
    thread::spawn(move || {
        let (sock, _) = listener.accept().unwrap();
        let server = ServerTransport::accept(sock, server_cfg, Duration::from_secs(5)).unwrap();
        behavior(server);
    });
    addr
}

/// Прогоняет полный клиентский сценарий и возвращает REP-код и эхо-данные.
fn run_connect(
    server_addr: SocketAddr,
    target_addr: SocketAddr,
    ack_timeout: Duration,
    payload: &[u8],
) -> (u8, Vec<u8>) {
    let (mut app, proxy_side) = socket_pair();
    let client_cfg = load_client_config(true);

    let handle = thread::spawn(move || {
        let client = ClientTransport::new(
            server_addr,
            "localhost",
            client_cfg,
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .unwrap();
        proxy_core::serve_client_connection(proxy_side, client, ack_timeout)
    });

    // SOCKS5 greeting: version 5, 1 method, no-auth.
    app.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut sel = [0u8; 2];
    app.read_exact(&mut sel).unwrap();
    assert_eq!(sel, [0x05, 0x00]);

    // CONNECT-запрос к цели.
    let mut req = vec![0x05, 0x01, 0x00];
    req.extend_from_slice(&target_from_socket(target_addr).encode());
    app.write_all(&req).unwrap();

    // Ответ: VER REP RSV ATYP BND.ADDR BND.PORT (10 байт).
    let mut reply = [0u8; 10];
    app.read_exact(&mut reply).unwrap();
    assert_eq!(reply[0], 0x05);
    let rep = reply[1];

    let mut echoed = Vec::new();
    if rep == 0x00 {
        app.write_all(payload).unwrap();
        let mut out = vec![0u8; payload.len()];
        app.read_exact(&mut out).unwrap();
        echoed = out;
    }

    drop(app);
    let _ = handle.join();
    (rep, echoed)
}

#[test]
fn handshake_connect_ok() {
    let (mut client, mut proxy) = socket_pair();
    client.write_all(&[0x05, 0x01, 0x00]).unwrap();
    client
        .write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50])
        .unwrap();

    let target = proxy_core::handshake(&mut proxy).unwrap();
    assert_eq!(target.port, 80);

    let mut sel = [0u8; 2];
    client.read_exact(&mut sel).unwrap();
    assert_eq!(sel, [0x05, 0x00]);
}

#[test]
fn handshake_udp_associate_rejected() {
    let (mut client, mut proxy) = socket_pair();
    client.write_all(&[0x05, 0x01, 0x00]).unwrap();
    client
        .write_all(&[0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50])
        .unwrap();

    let err = proxy_core::handshake(&mut proxy).unwrap_err();
    assert!(matches!(
        err,
        proxy_core::ProxyError::CommandNotSupported(socks5::Command::UdpAssociate)
    ));

    let mut resp = [0u8; 2 + 10];
    client.read_exact(&mut resp).unwrap();
    assert_eq!(&resp[..2], &[0x05, 0x00]);
    assert_eq!(resp[3], 0x07);
}

#[test]
fn handshake_bind_rejected() {
    let (mut client, mut proxy) = socket_pair();
    client.write_all(&[0x05, 0x01, 0x00]).unwrap();
    client
        .write_all(&[0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50])
        .unwrap();

    let err = proxy_core::handshake(&mut proxy).unwrap_err();
    assert!(matches!(
        err,
        proxy_core::ProxyError::CommandNotSupported(socks5::Command::Bind)
    ));

    let mut resp = [0u8; 2 + 10];
    client.read_exact(&mut resp).unwrap();
    assert_eq!(resp[3], 0x07);
}

#[test]
fn handshake_bad_version() {
    let (mut client, mut proxy) = socket_pair();
    client.write_all(&[0x04, 0x01, 0x00]).unwrap();

    let err = proxy_core::handshake(&mut proxy).unwrap_err();
    assert!(matches!(
        err,
        proxy_core::ProxyError::Socks5(socks5::Socks5Error::UnsupportedVersion(0x04))
    ));
}

#[test]
fn relay_mid_transfer_drop() {
    let (mut app, proxy_side) = socket_pair();
    let (mut remote, remote_side) = socket_pair();

    let handle = thread::spawn(move || proxy_core::relay(proxy_side, remote_side));

    app.write_all(b"hello").unwrap();
    let mut buf = [0u8; 5];
    remote.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"hello");

    remote.write_all(b"world").unwrap();
    drop(remote);

    let mut buf2 = [0u8; 5];
    app.read_exact(&mut buf2).unwrap();
    assert_eq!(&buf2, b"world");

    let mut rest = [0u8; 1];
    assert_eq!(app.read(&mut rest).unwrap(), 0);

    let _ = handle.join();
}

#[test]
fn end_to_end_connect_echo() {
    ensure_crypto_provider();
    let target_addr = spawn_echo_target_on("127.0.0.1:0", 1);
    let server_cfg = load_server_config();
    let server_addr = spawn_tls_server(server_cfg, 1);

    let (rep, echoed) = run_connect(server_addr, target_addr, Duration::from_secs(5), b"hello");
    assert_eq!(rep, 0x00);
    assert_eq!(echoed, b"hello");
}

#[test]
fn concurrent_connects() {
    ensure_crypto_provider();
    let n = 8;
    let target_addr = spawn_echo_target_on("127.0.0.1:0", n);
    let server_cfg = load_server_config();
    let server_addr = spawn_tls_server(server_cfg, n);

    let handles: Vec<_> = (0..n)
        .map(|i| {
            let payload = format!("payload-{i}").into_bytes();
            thread::spawn(move || {
                run_connect(server_addr, target_addr, Duration::from_secs(5), &payload)
            })
        })
        .collect();

    for (i, handle) in handles.into_iter().enumerate() {
        let (rep, echoed) = handle.join().unwrap();
        assert_eq!(rep, 0x00);
        assert_eq!(echoed, format!("payload-{i}").into_bytes());
    }
}

#[test]
fn connect_refused_reports_rep() {
    ensure_crypto_provider();
    let target = SocketAddr::from(([127, 0, 0, 1], closed_port()));
    let server_cfg = load_server_config();
    let server_addr = spawn_tls_server(server_cfg, 1);

    let (rep, _) = run_connect(server_addr, target, Duration::from_secs(5), b"");
    assert_eq!(rep, 0x05); // connection refused
}

#[test]
fn connect_ack_timeout_reports_rep() {
    ensure_crypto_provider();
    // Сервер читает цель, но не отвечает ack — клиент должен выйти по таймауту.
    let server_addr = spawn_fake_server(|mut server| {
        let _ = proxy_core::read_connect_target(&mut server);
        thread::sleep(Duration::from_secs(5));
    });

    let target = SocketAddr::from(([127, 0, 0, 1], 80));
    let (rep, _) = run_connect(server_addr, target, Duration::from_millis(300), b"");
    assert_eq!(rep, 0x04); // host unreachable (ack timeout)
}

#[test]
fn bad_connect_ack_reports_failure() {
    ensure_crypto_provider();
    // Сервер отправляет битый ConnectAck (payload 2 байта вместо 1).
    let server_addr = spawn_fake_server(|mut server| {
        let _ = proxy_core::read_connect_target(&mut server);
        protocol::write_message(
            &mut server,
            &protocol::Message::new(protocol::MessageKind::ConnectAck, vec![0x00, 0x00]),
        )
        .unwrap();
    });

    let target = SocketAddr::from(([127, 0, 0, 1], 80));
    let (rep, _) = run_connect(server_addr, target, Duration::from_secs(5), b"");
    assert_eq!(rep, 0x01); // general failure (malformed ack)
}

#[test]
fn ipv6_loopback() {
    ensure_crypto_provider();
    // Явный скип, если IPv6 loopback недоступен.
    if TcpListener::bind("[::1]:0").is_err() {
        eprintln!("IPv6 loopback not supported; skipping ipv6_loopback");
        return;
    }

    let target_addr = spawn_echo_target_on("[::1]:0", 1);
    let server_cfg = load_server_config();
    let server_addr = spawn_tls_server(server_cfg, 1);

    let (rep, echoed) = run_connect(server_addr, target_addr, Duration::from_secs(5), b"hello");
    assert_eq!(rep, 0x00);
    assert_eq!(echoed, b"hello");
}
