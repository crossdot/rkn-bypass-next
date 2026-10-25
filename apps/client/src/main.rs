//! SOCKS5-клиент: принимает CONNECT от приложений и проксирует их
//! через TLS к серверу.
//!
//! Конфигурация через переменные окружения (с дефолтами для нативной
//! разработки): `LISTEN_ADDR`, `SERVER_ADDR`, `CA_PATH`.

use std::fs::File;
use std::io::BufReader;
use std::net::{SocketAddr, TcpListener, ToSocketAddrs};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rustls::{ClientConfig, RootCertStore};
use transport_tls::{ensure_crypto_provider, ClientTransport};

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn load_client_config(ca_path: &str) -> Result<Arc<ClientConfig>, Box<dyn std::error::Error>> {
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    ensure_crypto_provider();

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

    let config = load_client_config(&ca_path)?;
    let listener = TcpListener::bind(&listen_addr)?;
    println!("SOCKS5 listening on {listen_addr} (server {server_addr})");

    for stream in listener.incoming() {
        let app = stream?;
        let config = Arc::clone(&config);
        thread::spawn(move || {
            let client = match ClientTransport::new(
                server_addr,
                "localhost",
                config,
                Duration::from_secs(5),
                Duration::from_secs(10),
            ) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("client init error: {e}");
                    return;
                }
            };
            if let Err(e) =
                proxy_core::serve_client_connection(app, client, proxy_core::ACK_TIMEOUT)
            {
                eprintln!("connection error: {e}");
            }
        });
    }
    Ok(())
}
