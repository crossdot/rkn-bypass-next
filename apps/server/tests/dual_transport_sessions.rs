//! Глобальный `max_sessions` через оба транспорта (ADR-023 §8).
//!
//! `run_both` делит один `Services` между TLS- и QUIC-циклами. Тест проверяет
//! именно риск этой схемы: лимит считается по обоим транспортам вместе, а не
//! per-transport. 1 TLS + 1 QUIC сессия при лимите 2 → третья отклоняется.

use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::danger::ClientCertVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::net::TcpListener;
use transport_any::AnyServerTransport;
use transport_tls::{ClientTransport, ServerTransport, Transport};

const CERT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-server.crt");
const CA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-ca.crt");
const CA_KEY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-ca.key");
const KEY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-server.key");
const TIMEOUT: Duration = Duration::from_secs(3);

fn load_certs(path: &str) -> Vec<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut BufReader::new(File::open(path).unwrap()))
        .collect::<Result<_, _>>()
        .unwrap()
}

fn load_key(path: &str) -> PrivateKeyDer<'static> {
    rustls_pemfile::private_key(&mut BufReader::new(File::open(path).unwrap()))
        .unwrap()
        .unwrap()
}

/// Соединение «висит» (сессия занята): recv не вернул данных за 250 мс.
async fn stays_open<T: Transport>(transport: &mut T) -> bool {
    let mut buf = [0u8; 1];
    tokio::time::timeout(Duration::from_millis(250), transport.recv(&mut buf))
        .await
        .is_err()
}

#[tokio::test]
async fn session_limit_is_global_across_transports() {
    transport_tls::ensure_crypto_provider();

    // Реестр: один клиент с лимитом 2. Клиентский сертификат подписан dev CA —
    // его же trust'ит сервер.
    let ca_pem = std::fs::read_to_string(CA).unwrap();
    let ca_key_pem = std::fs::read_to_string(CA_KEY).unwrap();
    let client = crypto::generate_client_cert("dual-transport", &ca_pem, &ca_key_pem).unwrap();
    let registry = Arc::new(
        config::ClientRegistry::from_toml(&format!(
            "[[server.clients]]\nclient_id = \"dual\"\nkey_material = '''{}'''\nmax_sessions = 2\n",
            client.cert_pem
        ))
        .unwrap(),
    );

    let services = Arc::new(server::Services::new(
        Arc::clone(&registry),
        Arc::new(server::SessionManager::new()),
        config::AddressRules::from_toml("[server.address_rules]\nallow_cidrs = [\"0.0.0.0/0\"]\n")
            .unwrap(),
    ));

    // Доверенный корень для клиентских сертификатов — dev CA.
    let mut roots = RootCertStore::empty();
    for cert in load_certs(CA) {
        roots.add(cert).unwrap();
    }
    let roots = Arc::new(roots);
    let inner_tls = server::AuthClientVerifier::build_inner(Arc::clone(&roots)).unwrap();
    let inner_quic = server::AuthClientVerifier::build_inner(Arc::clone(&roots)).unwrap();

    let mut server_certs = load_certs(CERT);
    server_certs.extend(load_certs(CA));
    let server_key = load_key(KEY);

    // --- TLS-цикл ---
    let tls_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tls_addr = tls_listener.local_addr().unwrap();
    {
        let services = Arc::clone(&services);
        let inner = Arc::clone(&inner_tls);
        let certs = server_certs.clone();
        let key = server_key.clone_key();
        tokio::spawn(async move {
            loop {
                let Ok((sock, remote)) = tls_listener.accept().await else {
                    return;
                };
                let services = Arc::clone(&services);
                let inner = Arc::clone(&inner);
                let certs = certs.clone();
                let key = key.clone_key();
                tokio::spawn(async move {
                    let auth = server::AuthClientVerifier::new(
                        inner,
                        Arc::clone(&services.registry),
                        Some(remote),
                    );
                    let verifier: Arc<dyn ClientCertVerifier> = Arc::new(auth);
                    let Ok(config) = ServerConfig::builder()
                        .with_client_cert_verifier(verifier)
                        .with_single_cert(certs, key)
                    else {
                        return;
                    };
                    let Ok(transport) =
                        ServerTransport::accept(sock, Arc::new(config), TIMEOUT).await
                    else {
                        return;
                    };
                    services.handle(AnyServerTransport::Tls(transport)).await;
                });
            }
        });
    }

    // --- QUIC-цикл (тот же Services) ---
    let auth = server::AuthClientVerifier::new(Arc::clone(&inner_quic), registry, None);
    let verifier: Arc<dyn ClientCertVerifier> = Arc::new(auth);
    let rustls_config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_certs, server_key)
        .unwrap();
    let endpoint = Arc::new(
        quinn::Endpoint::server(
            transport_quic::server_config(rustls_config).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap(),
    );
    let quic_addr = endpoint.local_addr().unwrap();
    {
        let services = Arc::clone(&services);
        let endpoint = Arc::clone(&endpoint);
        tokio::spawn(async move {
            loop {
                let Some(incoming) = endpoint.accept().await else {
                    return;
                };
                let services = Arc::clone(&services);
                let endpoint = Arc::clone(&endpoint);
                tokio::spawn(async move {
                    if let Ok(conn) = incoming.await {
                        let transport = transport_quic::QuicServerTransport::new(endpoint, conn);
                        services.handle(AnyServerTransport::Quic(transport)).await;
                    }
                });
            }
        });
    }

    // --- клиент ---
    let client_certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut BufReader::new(client.cert_pem.as_bytes()))
            .collect::<Result<_, _>>()
            .unwrap();
    let client_key = rustls_pemfile::private_key(&mut BufReader::new(client.key_pem.expose()))
        .unwrap()
        .unwrap();
    let mut client_roots = RootCertStore::empty();
    for cert in load_certs(CA) {
        client_roots.add(cert).unwrap();
    }
    let client_config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(client_roots)
            .with_client_auth_cert(client_certs, client_key)
            .unwrap(),
    );

    // 1) TLS-сессия (держим открытой, ничего не отправляя).
    let mut tls_session = ClientTransport::new(
        tls_addr,
        "localhost",
        Arc::clone(&client_config),
        TIMEOUT,
        TIMEOUT,
    )
    .unwrap();
    tls_session.connect().await.expect("tls session 1");
    assert!(stays_open(&mut tls_session).await, "TLS-сессия активна");

    // 2) QUIC-сессия.
    let quic_config = transport_quic::client_config((*client_config).clone()).unwrap();
    let mut quic_session =
        transport_quic::QuicClientTransport::new(quic_addr, "localhost", quic_config, TIMEOUT)
            .unwrap();
    quic_session.connect().await.expect("quic session 1");
    assert!(stays_open(&mut quic_session).await, "QUIC-сессия активна");

    // 3) Третья сессия при лимите 2 (1 TLS + 1 QUIC) должна быть отклонена.
    let mut rejected = ClientTransport::new(
        tls_addr,
        "localhost",
        Arc::clone(&client_config),
        TIMEOUT,
        TIMEOUT,
    )
    .unwrap();
    let is_rejected = match rejected.connect().await {
        Err(_) => true,
        Ok(()) => !stays_open(&mut rejected).await,
    };
    assert!(
        is_rejected,
        "лимит должен считаться глобально: 1 TLS + 1 QUIC при max_sessions=2"
    );

    // 4) Освобождаем TLS-сессию — соединение снова принимается.
    drop(tls_session);
    let mut accepted_again = false;
    for _ in 0..20 {
        let mut next = ClientTransport::new(
            tls_addr,
            "localhost",
            Arc::clone(&client_config),
            TIMEOUT,
            TIMEOUT,
        )
        .unwrap();
        if next.connect().await.is_ok() && stays_open(&mut next).await {
            accepted_again = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(accepted_again, "после release сессия снова принимается");
}
