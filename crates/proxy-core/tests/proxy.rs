//! Интеграционные тесты SOCKS5-режима и адресных правил.

use std::fs::File;
use std::future::Future;
use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
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

async fn socket_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let a = TcpStream::connect(addr).await.unwrap();
    let (b, _) = listener.accept().await.unwrap();
    (a, b)
}

/// Закрытый (не слушающий) порт на заданном IP.
fn closed_port_on(ip: IpAddr) -> u16 {
    let listener = std::net::TcpListener::bind(SocketAddr::new(ip, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// IPv4-адрес хоста (для недостижимой по loopback цели в тестах).
fn host_ipv4() -> Ipv4Addr {
    let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
    sock.connect("8.8.8.8:80").unwrap();
    match sock.local_addr().unwrap().ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => panic!("no IPv4 address"),
    }
}

/// Permissive-правила: разрешают весь IPv4 (кроме hardcoded-deny).
fn permissive_rules() -> config::AddressRules {
    config::AddressRules::from_toml(
        r#"[server.address_rules]
        allow_cidrs = ["0.0.0.0/0"]"#,
    )
    .unwrap()
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
async fn spawn_echo_target_on(bind: &str, n: usize) -> SocketAddr {
    let listener = TcpListener::bind(bind).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        for _ in 0..n {
            let (mut sock, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
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

/// TLS-сервер, принимающий ровно `n` соединений и релеющий их в цель
/// с заданными адресными правилами.
async fn spawn_tls_server(
    config: Arc<ServerConfig>,
    n: usize,
    rules: config::AddressRules,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        for _ in 0..n {
            let (sock, _) = listener.accept().await.unwrap();
            let config = Arc::clone(&config);
            let rules = rules.clone();
            tokio::spawn(async move {
                let server = ServerTransport::accept(sock, config, Duration::from_secs(5))
                    .await
                    .unwrap();
                let _ = proxy_core::serve_server_connection(server, Duration::from_secs(3), &rules)
                    .await;
            });
        }
    });
    addr
}

/// TLS-сервер с произвольным поведением после приёма соединения.
async fn spawn_fake_server<F, Fut>(behavior: F) -> SocketAddr
where
    F: FnOnce(ServerTransport) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_cfg = load_server_config();
    tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        let server = ServerTransport::accept(sock, server_cfg, Duration::from_secs(5))
            .await
            .unwrap();
        behavior(server).await;
    });
    addr
}

/// Прогоняет полный клиентский сценарий и возвращает REP-код и эхо-данные.
async fn run_connect(
    server_addr: SocketAddr,
    target_addr: SocketAddr,
    ack_timeout: Duration,
    payload: &[u8],
) -> (u8, Vec<u8>) {
    let (mut app, proxy_side) = socket_pair().await;
    let client_cfg = load_client_config(true);

    let handle = tokio::spawn(async move {
        let client = ClientTransport::new(
            server_addr,
            "localhost",
            client_cfg,
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .unwrap();
        proxy_core::serve_client_connection(proxy_side, client, ack_timeout).await
    });

    app.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut sel = [0u8; 2];
    app.read_exact(&mut sel).await.unwrap();
    assert_eq!(sel, [0x05, 0x00]);

    let mut req = vec![0x05, 0x01, 0x00];
    req.extend_from_slice(&target_from_socket(target_addr).encode());
    app.write_all(&req).await.unwrap();

    let mut reply = [0u8; 10];
    app.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 0x05);
    let rep = reply[1];

    let mut echoed = Vec::new();
    if rep == 0x00 {
        app.write_all(payload).await.unwrap();
        let mut out = vec![0u8; payload.len()];
        app.read_exact(&mut out).await.unwrap();
        echoed = out;
    }

    drop(app);
    let _ = handle.await;
    (rep, echoed)
}

#[tokio::test]
async fn handshake_connect_ok() {
    let (mut client, mut proxy) = socket_pair().await;
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    client
        .write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50])
        .await
        .unwrap();

    let target = proxy_core::handshake(&mut proxy).await.unwrap();
    assert_eq!(target.port, 80);

    let mut sel = [0u8; 2];
    client.read_exact(&mut sel).await.unwrap();
    assert_eq!(sel, [0x05, 0x00]);
}

#[tokio::test]
async fn handshake_udp_associate_rejected() {
    let (mut client, mut proxy) = socket_pair().await;
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    client
        .write_all(&[0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50])
        .await
        .unwrap();

    let err = proxy_core::handshake(&mut proxy).await.unwrap_err();
    assert!(matches!(
        err,
        proxy_core::ProxyError::CommandNotSupported(socks5::Command::UdpAssociate)
    ));

    let mut resp = [0u8; 2 + 10];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(&resp[..2], &[0x05, 0x00]);
    assert_eq!(resp[3], 0x07);
}

#[tokio::test]
async fn handshake_bind_rejected() {
    let (mut client, mut proxy) = socket_pair().await;
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    client
        .write_all(&[0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50])
        .await
        .unwrap();

    let err = proxy_core::handshake(&mut proxy).await.unwrap_err();
    assert!(matches!(
        err,
        proxy_core::ProxyError::CommandNotSupported(socks5::Command::Bind)
    ));

    let mut resp = [0u8; 2 + 10];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[3], 0x07);
}

#[tokio::test]
async fn handshake_bad_version() {
    let (mut client, mut proxy) = socket_pair().await;
    client.write_all(&[0x04, 0x01, 0x00]).await.unwrap();

    let err = proxy_core::handshake(&mut proxy).await.unwrap_err();
    assert!(matches!(
        err,
        proxy_core::ProxyError::Socks5(socks5::Socks5Error::UnsupportedVersion(0x04))
    ));
}

#[tokio::test]
async fn end_to_end_connect_echo() {
    ensure_crypto_provider();
    let host = host_ipv4();
    let target_addr = spawn_echo_target_on(&format!("{host}:0"), 1).await;
    let server_addr = spawn_tls_server(load_server_config(), 1, permissive_rules()).await;

    let (rep, echoed) =
        run_connect(server_addr, target_addr, Duration::from_secs(5), b"hello").await;
    assert_eq!(rep, 0x00);
    assert_eq!(echoed, b"hello");
}

#[tokio::test]
async fn concurrent_connects() {
    ensure_crypto_provider();
    let n = 8;
    let host = host_ipv4();
    let target_addr = spawn_echo_target_on(&format!("{host}:0"), n).await;
    let server_addr = spawn_tls_server(load_server_config(), n, permissive_rules()).await;

    let mut handles = Vec::new();
    for i in 0..n {
        let payload = format!("payload-{i}").into_bytes();
        handles.push(tokio::spawn(async move {
            run_connect(server_addr, target_addr, Duration::from_secs(5), &payload).await
        }));
    }

    for (i, handle) in handles.into_iter().enumerate() {
        let (rep, echoed) = handle.await.unwrap();
        assert_eq!(rep, 0x00);
        assert_eq!(echoed, format!("payload-{i}").into_bytes());
    }
}

#[tokio::test]
async fn connect_refused_reports_rep() {
    ensure_crypto_provider();
    let host = host_ipv4();
    let port = closed_port_on(IpAddr::V4(host));
    let target = SocketAddr::from((host, port));
    let server_addr = spawn_tls_server(load_server_config(), 1, permissive_rules()).await;

    let (rep, _) = run_connect(server_addr, target, Duration::from_secs(5), b"").await;
    assert_eq!(rep, 0x05); // connection refused
}

#[tokio::test]
async fn connect_ack_timeout_reports_rep() {
    ensure_crypto_provider();
    let server_addr = spawn_fake_server(|mut server| async move {
        let _ = proxy_core::read_connect_target(&mut server).await;
        tokio::time::sleep(Duration::from_secs(5)).await;
    })
    .await;

    let target = SocketAddr::from(([127, 0, 0, 1], 80));
    let (rep, _) = run_connect(server_addr, target, Duration::from_millis(300), b"").await;
    assert_eq!(rep, 0x04); // host unreachable (ack timeout)
}

#[tokio::test]
async fn bad_connect_ack_reports_failure() {
    ensure_crypto_provider();
    let server_addr = spawn_fake_server(|mut server| async move {
        let _ = proxy_core::read_connect_target(&mut server).await;
        protocol::write_message(
            &mut server,
            &protocol::Message::new(protocol::MessageKind::ConnectAck, vec![0x00, 0x00]),
        )
        .await
        .unwrap();
    })
    .await;

    let target = SocketAddr::from(([127, 0, 0, 1], 80));
    let (rep, _) = run_connect(server_addr, target, Duration::from_secs(5), b"").await;
    assert_eq!(rep, 0x01); // general failure (malformed ack)
}

#[tokio::test]
async fn blocked_loopback_rep() {
    ensure_crypto_provider();
    let server_addr =
        spawn_tls_server(load_server_config(), 1, config::AddressRules::default()).await;
    let target = SocketAddr::from(([127, 0, 0, 1], 80));
    let (rep, _) = run_connect(server_addr, target, Duration::from_secs(5), b"").await;
    assert_eq!(rep, 0x02); // not allowed
}

#[tokio::test]
async fn blocked_ipv6_loopback_rep() {
    ensure_crypto_provider();
    let server_addr =
        spawn_tls_server(load_server_config(), 1, config::AddressRules::default()).await;
    let target = SocketAddr::from((Ipv6Addr::LOCALHOST, 80));
    let (rep, _) = run_connect(server_addr, target, Duration::from_secs(5), b"").await;
    assert_eq!(rep, 0x02);
}

#[tokio::test]
async fn blocked_link_local_rep() {
    ensure_crypto_provider();
    let server_addr =
        spawn_tls_server(load_server_config(), 1, config::AddressRules::default()).await;
    let target = SocketAddr::from(([169, 254, 1, 1], 8080));
    let (rep, _) = run_connect(server_addr, target, Duration::from_secs(5), b"").await;
    assert_eq!(rep, 0x02);
}

#[tokio::test]
async fn blocked_low_port_rep() {
    ensure_crypto_provider();
    let server_addr =
        spawn_tls_server(load_server_config(), 1, config::AddressRules::default()).await;
    // Публичный IP, порт 22 — отклонён правилом низких портов.
    let target = SocketAddr::from(([8, 8, 8, 8], 22));
    let (rep, _) = run_connect(server_addr, target, Duration::from_secs(5), b"").await;
    assert_eq!(rep, 0x02);
}

#[tokio::test]
async fn allowed_private_cidr_not_blocked() {
    ensure_crypto_provider();
    let rules = config::AddressRules::from_toml(
        r#"[server.address_rules]
        allow_cidrs = ["192.168.1.0/24"]"#,
    )
    .unwrap();
    let server_addr = spawn_tls_server(load_server_config(), 1, rules).await;
    let target = SocketAddr::from(([192, 168, 1, 1], 8080));
    let (rep, _) = run_connect(server_addr, target, Duration::from_secs(5), b"").await;
    assert_ne!(rep, 0x02); // адрес разрешён (не «not allowed»)
}

#[tokio::test]
async fn deny_cidr_overrides_allow() {
    ensure_crypto_provider();
    let rules = config::AddressRules::from_toml(
        r#"[server.address_rules]
        allow_cidrs = ["192.168.1.0/24"]
        deny_cidrs = ["192.168.1.0/24"]"#,
    )
    .unwrap();
    let server_addr = spawn_tls_server(load_server_config(), 1, rules).await;
    let target = SocketAddr::from(([192, 168, 1, 1], 8080));
    let (rep, _) = run_connect(server_addr, target, Duration::from_secs(5), b"").await;
    assert_eq!(rep, 0x02); // deny выигрывает
}
