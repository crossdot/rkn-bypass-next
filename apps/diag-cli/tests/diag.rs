//! Интеграционный тест диагностики: недоступный хост → класс ошибки.

use std::fs::File;
use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use transport_tls::ServerTransport;

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

fn host_ipv4() -> Ipv4Addr {
    let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
    sock.connect("8.8.8.8:80").unwrap();
    match sock.local_addr().unwrap().ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => panic!("no IPv4 address"),
    }
}

/// TLS-сервер, обслуживающий одно соединение с permissive-правилами.
async fn spawn_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = load_server_config();
    tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        let server = ServerTransport::accept(sock, config, Duration::from_secs(5))
            .await
            .unwrap();
        let rules = config::AddressRules::from_toml(
            r#"[server.address_rules]
            allow_cidrs = ["0.0.0.0/0"]"#,
        )
        .unwrap();
        let _ = proxy_core::serve_server_connection(server, Duration::from_secs(3), &rules).await;
    });
    addr
}

#[tokio::test]
async fn diag_check_unreachable_host_reports_class() {
    let server_addr = spawn_server().await;

    // Закрытый порт на host IP → connection refused.
    let host = host_ipv4();
    let listener = std::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(host), 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let target = socks5::Target {
        addr: socks5::Addr::IPv4(host.octets()),
        port,
    };

    let stages = diag_cli::run_check(server_addr, &target).await;

    assert_eq!(stages.len(), 4);
    assert_eq!(stages[0].name, "connect");
    assert_eq!(stages[0].status, diag_cli::StageStatus::Ok);
    assert_eq!(stages[1].name, "tls");
    assert_eq!(stages[1].status, diag_cli::StageStatus::Ok);
    assert_eq!(stages[2].name, "socks5");
    assert!(
        matches!(&stages[2].status, diag_cli::StageStatus::Failed(s) if s.starts_with("connection-refused")),
        "expected connection-refused, got {:?}",
        stages[2].status
    );
    assert_eq!(stages[3].name, "relay");
    assert_eq!(stages[3].status, diag_cli::StageStatus::Skipped);
}
