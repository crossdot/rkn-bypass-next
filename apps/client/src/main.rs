//! SOCKS5-клиент: принимает CONNECT от приложений и проксирует их через
//! TLS или QUIC (с mTLS) к серверу.
//!
//! Конфигурация через env: `TRANSPORT` (`tls`|`quic`, дефолт `tls`),
//! `LISTEN_ADDR`, `SERVER_ADDR`, `CA_PATH`, `CLIENT_CERT`, `CLIENT_KEY`.

use std::fs::File;
use std::io::BufReader;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore};
use transport_any::AnyClientTransport;
use transport_tls::{ensure_crypto_provider, ClientTransport};

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ensure_crypto_provider();

    let kind = match std::env::var("TRANSPORT") {
        Ok(v) => v.parse::<config::TransportKind>()?,
        Err(_) => config::TransportKind::Tls,
    };
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

    let rustls_config = load_client_config(&ca_path, &client_cert, &client_key)?;
    let listener = TcpListener::bind(&listen_addr).await?;
    println!("SOCKS5 listening on {listen_addr} (transport={kind:?}, server {server_addr})");

    loop {
        let (app, _) = listener.accept().await?;
        let rustls_config = rustls_config.clone();
        tokio::spawn(async move {
            let client = match kind {
                config::TransportKind::Tls => {
                    match ClientTransport::new(
                        server_addr,
                        "localhost",
                        Arc::new(rustls_config),
                        Duration::from_secs(5),
                        Duration::from_secs(10),
                    ) {
                        Ok(c) => AnyClientTransport::Tls(c),
                        Err(e) => {
                            eprintln!("client init error: {e}");
                            return;
                        }
                    }
                }
                config::TransportKind::Quic => {
                    let quinn_config = match transport_quic::client_config(rustls_config) {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!("quic client config error: {e}");
                            return;
                        }
                    };
                    match transport_quic::QuicClientTransport::new(
                        server_addr,
                        "localhost",
                        quinn_config,
                        Duration::from_secs(5),
                    ) {
                        Ok(c) => AnyClientTransport::Quic(c),
                        Err(e) => {
                            eprintln!("client init error: {e}");
                            return;
                        }
                    }
                }
            };
            if let Err(e) =
                proxy_core::serve_client_connection(app, client, proxy_core::ACK_TIMEOUT).await
            {
                eprintln!("connection error: {e}");
            }
        });
    }
}
