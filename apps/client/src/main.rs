//! SOCKS5-клиент: принимает CONNECT от приложений и проксирует их
//! через TLS к серверу.

use std::fs::File;
use std::io::BufReader;
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rustls::{ClientConfig, RootCertStore};
use transport_tls::{ensure_crypto_provider, ClientTransport};

const SERVER_ADDR: &str = "127.0.0.1:8443";
const LISTEN_ADDR: &str = "127.0.0.1:1080";

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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    ensure_crypto_provider();
    let config = load_client_config()?;
    let server_addr: SocketAddr = SERVER_ADDR.parse()?;
    let listener = TcpListener::bind(LISTEN_ADDR)?;
    println!("SOCKS5 listening on {LISTEN_ADDR}");

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
