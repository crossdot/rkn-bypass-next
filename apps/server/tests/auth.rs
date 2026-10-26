//! Интеграционные тесты mTLS-аутентификации.

mod common;
use common::*;

use std::sync::Arc;

#[tokio::test]
async fn valid_client_connects() {
    ensure_crypto_provider();
    let client = gen_client("alice");
    let registry = Arc::new(registry_with(&[(
        "alice".into(),
        client.cert_pem.clone(),
        false,
    )]));
    let client_cfg = build_client_config(&client);
    assert!(handshake_ok(registry, client_cfg).await);
}

#[tokio::test]
async fn unknown_client_rejected() {
    ensure_crypto_provider();
    let client = gen_client("alice");
    // Пустой реестр — клиент неизвестен.
    let registry = Arc::new(config::ClientRegistry::default());
    let client_cfg = build_client_config(&client);
    assert!(!handshake_ok(registry, client_cfg).await);
}

#[tokio::test]
async fn revoked_client_rejected() {
    ensure_crypto_provider();
    let client = gen_client("alice");
    let registry = Arc::new(registry_with(&[(
        "alice".into(),
        client.cert_pem.clone(),
        true,
    )]));
    let client_cfg = build_client_config(&client);
    assert!(!handshake_ok(registry, client_cfg).await);
}

#[tokio::test]
async fn rotation_old_rejected_new_works() {
    ensure_crypto_provider();
    let old = gen_client("alice");
    let new = gen_client("alice");

    // После ротации: реестр содержит только новый сертификат.
    let registry = Arc::new(registry_with(&[(
        "alice".into(),
        new.cert_pem.clone(),
        false,
    )]));

    assert!(!handshake_ok(Arc::clone(&registry), build_client_config(&old)).await);
    assert!(handshake_ok(registry, build_client_config(&new)).await);
}

#[tokio::test]
async fn two_clients_dont_conflict() {
    ensure_crypto_provider();
    let a = gen_client("alice");
    let b = gen_client("bob");
    let registry = Arc::new(registry_with(&[
        ("alice".into(), a.cert_pem.clone(), false),
        ("bob".into(), b.cert_pem.clone(), false),
    ]));
    assert!(handshake_ok(Arc::clone(&registry), build_client_config(&a)).await);
    assert!(handshake_ok(registry, build_client_config(&b)).await);
}
