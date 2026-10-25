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

/// TCP echo-сервер, принимающий ровно `n` соединений.
fn spawn_echo_target(n: usize) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
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
                let _ = proxy_core::serve_server_connection(server);
            });
        }
    });
    addr
}

/// Прогоняет полный клиентский сценарий и возвращает полученный эхо-ответ.
fn run_connect(server_addr: SocketAddr, target_addr: SocketAddr, payload: &[u8]) -> Vec<u8> {
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
        proxy_core::serve_client_connection(proxy_side, client)
    });

    // SOCKS5 greeting: version 5, 1 method, no-auth.
    app.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut sel = [0u8; 2];
    app.read_exact(&mut sel).unwrap();
    assert_eq!(sel, [0x05, 0x00]);

    // CONNECT-запрос к цели (IPv4).
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    match target_addr.ip() {
        IpAddr::V4(ip) => req.extend_from_slice(&ip.octets()),
        IpAddr::V6(ip) => req.extend_from_slice(&ip.octets()),
    }
    req.extend_from_slice(&target_addr.port().to_be_bytes());
    app.write_all(&req).unwrap();

    // Ответ успеха: VER REP RSV ATYP BND.ADDR BND.PORT.
    let mut reply = [0u8; 10];
    app.read_exact(&mut reply).unwrap();
    assert_eq!(reply[0], 0x05);
    assert_eq!(reply[1], 0x00);

    // Передаём данные и читаем эхо.
    app.write_all(payload).unwrap();
    let mut out = vec![0u8; payload.len()];
    app.read_exact(&mut out).unwrap();

    drop(app);
    let _ = handle.join();
    out
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
    assert_eq!(resp[3], 0x07); // command not supported
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

    // Удалённая сторона шлёт часть данных и обрывает соединение.
    remote.write_all(b"world").unwrap();
    drop(remote);

    let mut buf2 = [0u8; 5];
    app.read_exact(&mut buf2).unwrap();
    assert_eq!(&buf2, b"world");

    let mut rest = [0u8; 1];
    assert_eq!(app.read(&mut rest).unwrap(), 0); // EOF после обрыва

    let _ = handle.join();
}

#[test]
fn end_to_end_connect_echo() {
    ensure_crypto_provider();
    let target_addr = spawn_echo_target(1);
    let server_cfg = load_server_config();
    let server_addr = spawn_tls_server(server_cfg, 1);

    let got = run_connect(server_addr, target_addr, b"hello");
    assert_eq!(got, b"hello");
}

#[test]
fn concurrent_connects() {
    ensure_crypto_provider();
    let n = 8;
    let target_addr = spawn_echo_target(n);
    let server_cfg = load_server_config();
    let server_addr = spawn_tls_server(server_cfg, n);

    let handles: Vec<_> = (0..n)
        .map(|i| {
            let payload = format!("payload-{i}").into_bytes();
            thread::spawn(move || run_connect(server_addr, target_addr, &payload))
        })
        .collect();

    for (i, handle) in handles.into_iter().enumerate() {
        let got = handle.join().unwrap();
        assert_eq!(got, format!("payload-{i}").into_bytes());
    }
}
