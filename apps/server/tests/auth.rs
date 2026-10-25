//! Интеграционные тесты mTLS-аутентификации.

mod common;
use common::*;

use std::sync::Arc;

#[test]
fn valid_client_connects() {
    ensure_crypto_provider();
    let client = gen_client("alice");
    let registry = Arc::new(registry_with(&[(
        "alice".into(),
        client.cert_pem.clone(),
        false,
    )]));
    let server_cfg = build_server_config(registry);
    let client_cfg = build_client_config(&client);
    assert!(handshake_ok(server_cfg, client_cfg));
}

#[test]
fn unknown_client_rejected() {
    ensure_crypto_provider();
    let client = gen_client("alice");
    // Пустой реестр — клиент неизвестен.
    let registry = Arc::new(config::ClientRegistry::default());
    let server_cfg = build_server_config(registry);
    let client_cfg = build_client_config(&client);
    assert!(!handshake_ok(server_cfg, client_cfg));
}

#[test]
fn revoked_client_rejected() {
    ensure_crypto_provider();
    let client = gen_client("alice");
    let registry = Arc::new(registry_with(&[(
        "alice".into(),
        client.cert_pem.clone(),
        true,
    )]));
    let server_cfg = build_server_config(registry);
    let client_cfg = build_client_config(&client);
    assert!(!handshake_ok(server_cfg, client_cfg));
}

#[test]
fn rotation_old_rejected_new_works() {
    ensure_crypto_provider();
    let old = gen_client("alice");
    let new = gen_client("alice");

    // После ротации: реестр содержит только новый сертификат.
    let registry = Arc::new(registry_with(&[(
        "alice".into(),
        new.cert_pem.clone(),
        false,
    )]));
    let server_cfg = build_server_config(registry);

    assert!(!handshake_ok(
        Arc::clone(&server_cfg),
        build_client_config(&old)
    ));
    assert!(handshake_ok(server_cfg, build_client_config(&new)));
}

#[test]
fn two_clients_dont_conflict() {
    ensure_crypto_provider();
    let a = gen_client("alice");
    let b = gen_client("bob");
    let registry = Arc::new(registry_with(&[
        ("alice".into(), a.cert_pem.clone(), false),
        ("bob".into(), b.cert_pem.clone(), false),
    ]));
    let server_cfg = build_server_config(registry);
    assert!(handshake_ok(
        Arc::clone(&server_cfg),
        build_client_config(&a)
    ));
    assert!(handshake_ok(server_cfg, build_client_config(&b)));
}
