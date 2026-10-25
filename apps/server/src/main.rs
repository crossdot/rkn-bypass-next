//! TLS-сервер: принимает логические потоки от клиента и открывает
//! TCP к запрошенному адресу (с проверкой адресных правил).
//!
//! Конфигурация через переменные окружения (с дефолтами для нативной
//! разработки): `LISTEN_ADDR`, `CERT_PATH`, `KEY_PATH`, `CA_PATH`,
//! `RULES_PATH`.

use std::fs::File;
use std::io::BufReader;
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use transport_tls::{ensure_crypto_provider, ServerTransport};

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn load_tls_config(
    cert_path: &str,
    ca_path: &str,
    key_path: &str,
) -> Result<Arc<ServerConfig>, Box<dyn std::error::Error>> {
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

/// Загружает адресные правила из `RULES_PATH`, иначе — безопасный default.
fn load_address_rules() -> config::AddressRules {
    let Some(path) = std::env::var("RULES_PATH").ok().filter(|s| !s.is_empty()) else {
        return config::AddressRules::default();
    };
    match std::fs::read_to_string(&path) {
        Ok(toml) => match config::AddressRules::from_toml(&toml) {
            Ok(rules) => rules,
            Err(e) => {
                eprintln!("warning: bad config {path}: {e}; using default rules");
                config::AddressRules::default()
            }
        },
        Err(e) => {
            eprintln!("warning: cannot read {path}: {e}; using default rules");
            config::AddressRules::default()
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    ensure_crypto_provider();

    let listen_addr = env_or("LISTEN_ADDR", "127.0.0.1:8443");
    let cert_path = env_or(
        "CERT_PATH",
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-server.crt"),
    );
    let ca_path = env_or(
        "CA_PATH",
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-ca.crt"),
    );
    let key_path = env_or(
        "KEY_PATH",
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-server.key"),
    );

    let tls_config = load_tls_config(&cert_path, &ca_path, &key_path)?;
    let rules = load_address_rules();
    let listener = TcpListener::bind(&listen_addr)?;
    println!("TLS server listening on {listen_addr}");

    for stream in listener.incoming() {
        let sock = stream?;
        let tls_config = Arc::clone(&tls_config);
        let rules = rules.clone();
        thread::spawn(move || {
            match ServerTransport::accept(sock, tls_config, Duration::from_secs(10)) {
                Ok(server) => {
                    if let Err(e) = proxy_core::serve_server_connection(
                        server,
                        proxy_core::CONNECT_TIMEOUT,
                        &rules,
                    ) {
                        eprintln!("connection error: {e}");
                    }
                }
                Err(e) => eprintln!("handshake error: {e}"),
            }
        });
    }
    Ok(())
}
