//! Минимальный TLS-сервер: принимает соединения, читает контрольное
//! сообщение и отвечает подтверждением.

use std::fs::File;
use std::io::BufReader;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use transport_tls::{ensure_crypto_provider, ServerTransport, Transport};

const CONTROL_BYTES: &[u8] = b"rkn-bypass-control";

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

fn handle(sock: TcpStream, config: Arc<ServerConfig>) -> Result<(), Box<dyn std::error::Error>> {
    let mut transport = ServerTransport::accept(sock, config, Duration::from_secs(10))?;

    let msg = protocol::read_message(&mut transport)?;
    if msg.kind != protocol::MessageKind::Control || msg.payload != CONTROL_BYTES {
        return Err("unexpected control message".into());
    }
    println!(
        "received control bytes: {:?}",
        String::from_utf8_lossy(&msg.payload)
    );

    protocol::write_message(
        &mut transport,
        &protocol::Message::new(protocol::MessageKind::Control, b"ack".to_vec()),
    )?;
    transport.close()?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    ensure_crypto_provider();
    let config = load_server_config()?;
    let listener = TcpListener::bind("127.0.0.1:8443")?;
    println!("listening on {}", listener.local_addr()?);

    for stream in listener.incoming() {
        let stream = stream?;
        let config = Arc::clone(&config);
        thread::spawn(move || {
            if let Err(e) = handle(stream, config) {
                eprintln!("handler error: {e}");
            }
        });
    }
    Ok(())
}
