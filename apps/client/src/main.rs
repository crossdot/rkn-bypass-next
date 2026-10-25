//! Минимальный TLS-клиент: подключается к серверу, проходит
//! TLS-аутентификацию по сертификату и передаёт контрольные байты.

use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::{ClientConfig, RootCertStore};
use transport_tls::{ensure_crypto_provider, ClientTransport, Transport};

const CONTROL_BYTES: &[u8] = b"rkn-bypass-control";

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
    let addr: SocketAddr = "127.0.0.1:8443".parse()?;

    let mut transport = ClientTransport::new(
        addr,
        "localhost",
        config,
        Duration::from_secs(5),
        Duration::from_secs(10),
    )?;
    transport.connect()?;
    println!("connected to {addr}");

    protocol::write_message(
        &mut transport,
        &protocol::Message::new(protocol::MessageKind::Control, CONTROL_BYTES.to_vec()),
    )?;
    println!("sent control bytes");

    let response = protocol::read_message(&mut transport)?;
    println!(
        "received: kind={:?} payload={:?}",
        response.kind,
        String::from_utf8_lossy(&response.payload)
    );

    if response.kind != protocol::MessageKind::Control || response.payload != b"ack" {
        return Err("unexpected response".into());
    }

    transport.close()?;
    println!("ok");
    Ok(())
}
