//! TLS-сервер: принимает логические потоки от клиента и открывает
//! TCP к запрошенному адресу.

use std::fs::File;
use std::io::BufReader;
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use transport_tls::{ensure_crypto_provider, ServerTransport};

const LISTEN_ADDR: &str = "127.0.0.1:8443";

fn load_server_config() -> Result<Arc<ServerConfig>, Box<dyn std::error::Error>> {
    let cert_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-server.crt");
    let ca_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-ca.crt");
    let key_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-server.key");

    let mut certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut BufReader::new(File::open(cert_path)?))
            .collect::<Result<_, _>>()?;
    certs.extend(
        rustls_pemfile::certs(&mut BufReader::new(File::open(ca_path)?))
            .collect::<Result<Vec<_>, _>>()?,
    );
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut BufReader::new(
        File::open(key_path)?,
    ))?
    .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "private key not found"))?;

    Ok(Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?,
    ))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    ensure_crypto_provider();
    let config = load_server_config()?;
    let listener = TcpListener::bind(LISTEN_ADDR)?;
    println!("TLS server listening on {LISTEN_ADDR}");

    for stream in listener.incoming() {
        let sock = stream?;
        let config = Arc::clone(&config);
        thread::spawn(move || {
            match ServerTransport::accept(sock, config, Duration::from_secs(10)) {
                Ok(server) => {
                    if let Err(e) =
                        proxy_core::serve_server_connection(server, proxy_core::CONNECT_TIMEOUT)
                    {
                        eprintln!("connection error: {e}");
                    }
                }
                Err(e) => eprintln!("handshake error: {e}"),
            }
        });
    }
    Ok(())
}
