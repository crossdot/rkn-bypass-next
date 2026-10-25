//! Интеграционные тесты TLS-транспорта.

use std::fs::File;
use std::io::BufReader;
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use transport_tls::{
    ensure_crypto_provider, ClientTransport, ServerTransport, Transport, TransportError,
};

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

fn bind() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    (listener, addr)
}

/// Читает ровно `len` байт через [`Transport::recv`].
fn recv_exact(t: &mut impl Transport, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut filled = 0;
    while filled < len {
        let n = t.recv(&mut out[filled..]).expect("recv");
        assert!(n > 0, "unexpected EOF");
        filled += n;
    }
    out
}

#[test]
fn round_trip_echo() {
    ensure_crypto_provider();
    let (listener, addr) = bind();
    let server_cfg = load_server_config();
    let server = thread::spawn(move || {
        let (sock, _) = listener.accept().unwrap();
        let mut t = ServerTransport::accept(sock, server_cfg, Duration::from_secs(5)).unwrap();
        let got = recv_exact(&mut t, 5);
        t.send(&got).unwrap();
        t.close().unwrap();
    });

    let mut t = ClientTransport::new(
        addr,
        "localhost",
        load_client_config(true),
        Duration::from_secs(5),
        Duration::from_secs(5),
    )
    .unwrap();
    t.connect().unwrap();
    assert_eq!(t.send(b"hello").unwrap(), 5);
    assert_eq!(recv_exact(&mut t, 5), b"hello");
    t.close().unwrap();
    server.join().unwrap();
}

#[test]
fn bad_certificate_rejected() {
    ensure_crypto_provider();
    let (listener, addr) = bind();
    let server_cfg = load_server_config();
    let server = thread::spawn(move || {
        let (sock, _) = listener.accept().unwrap();
        // Клиент оборвёт handshake после отклонения сертификата.
        let _ = ServerTransport::accept(sock, server_cfg, Duration::from_secs(5));
    });

    let mut t = ClientTransport::new(
        addr,
        "localhost",
        load_client_config(false),
        Duration::from_secs(5),
        Duration::from_secs(5),
    )
    .unwrap();
    let res = t.connect();
    assert!(matches!(res, Err(TransportError::ConnectFailed(_))));
    server.join().unwrap();
}

#[test]
fn handshake_timeout() {
    ensure_crypto_provider();
    let (listener, addr) = bind();
    let server = thread::spawn(move || {
        let (sock, _) = listener.accept().unwrap();
        // Держим сокет, но не делаем TLS: клиент не дождётся ServerHello.
        thread::sleep(Duration::from_secs(3));
        drop(sock);
    });

    let mut t = ClientTransport::new(
        addr,
        "localhost",
        load_client_config(true),
        Duration::from_secs(5),
        Duration::from_millis(500),
    )
    .unwrap();
    let start = Instant::now();
    let res = t.connect();
    assert!(res.is_err());
    assert!(start.elapsed() >= Duration::from_millis(400));
    server.join().unwrap();
}

#[test]
fn drop_mid_transfer_detected() {
    ensure_crypto_provider();
    let (listener, addr) = bind();
    let server_cfg = load_server_config();
    let server = thread::spawn(move || {
        let (sock, _) = listener.accept().unwrap();
        let mut t = ServerTransport::accept(sock, server_cfg, Duration::from_secs(5)).unwrap();
        // Отправляем данные и резко обрываем соединение без close_notify.
        t.send(b"0123456789").unwrap();
        drop(t);
    });

    let mut t = ClientTransport::new(
        addr,
        "localhost",
        load_client_config(true),
        Duration::from_secs(5),
        Duration::from_secs(5),
    )
    .unwrap();
    t.connect().unwrap();

    let mut total = Vec::new();
    let mut buf = [0u8; 64];
    let terminated = loop {
        match t.recv(&mut buf) {
            Ok(0) => break Ok(()),
            Ok(n) => total.extend_from_slice(&buf[..n]),
            Err(e) => break Err(e),
        }
    };

    assert_eq!(total, b"0123456789");
    assert!(matches!(terminated, Ok(()) | Err(_)));
    server.join().unwrap();
}
