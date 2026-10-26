//! Тест аудит-событий handshake'а: structured logging.
//! См. ADR-021 «Аудит handshake'ей».

mod common;
use common::*;

use std::sync::Arc;
use tracing_test::traced_test;

/// Читает глобальный буфер `#[traced_test]` (ловит события из всех потоков,
/// включая поток сервера в `handshake_ok`).
fn captured_lines() -> Vec<String> {
    let buf = tracing_test::internal::global_buf()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    String::from_utf8(buf.clone())
        .expect("invalid utf8 in captured logs")
        .lines()
        .map(String::from)
        .collect()
}

#[tokio::test]
#[traced_test]
async fn audit_ok_event() {
    ensure_crypto_provider();
    let a = gen_client("alice");
    let fp = a.fingerprint.clone();
    let registry = Arc::new(registry_with(&[(
        "alice".into(),
        a.cert_pem.clone(),
        false,
    )]));
    assert!(handshake_ok(registry, build_client_config(&a)).await);

    let needle = format!("fingerprint=sha256:{fp}");
    let lines = captured_lines();
    let events: Vec<_> = lines
        .iter()
        .filter(|l| l.contains("event=mtls_handshake") && l.contains(&needle))
        .collect();
    assert_eq!(events.len(), 1, "expected one audit event: {lines:?}");
    let e = events[0];
    assert!(e.contains("outcome=ok"), "{e}");
    assert!(e.contains("client_id=alice"), "{e}");
    assert!(e.contains("remote_addr=127.0.0.1:"), "{e}");
}

#[tokio::test]
#[traced_test]
async fn audit_unknown_fingerprint() {
    ensure_crypto_provider();
    let a = gen_client("alice");
    let fp = a.fingerprint.clone();
    let registry = Arc::new(config::ClientRegistry::default());
    assert!(!handshake_ok(registry, build_client_config(&a)).await);

    let needle = format!("fingerprint=sha256:{fp}");
    let lines = captured_lines();
    let events: Vec<_> = lines
        .iter()
        .filter(|l| l.contains("event=mtls_handshake") && l.contains(&needle))
        .collect();
    assert_eq!(events.len(), 1, "expected one audit event: {lines:?}");
    let e = events[0];
    assert!(e.contains("outcome=rejected"), "{e}");
    assert!(e.contains("reason=unknown_fingerprint"), "{e}");
    assert!(e.contains("remote_addr=127.0.0.1:"), "{e}");
}

#[tokio::test]
#[traced_test]
async fn audit_revoked_with_client_id() {
    ensure_crypto_provider();
    let a = gen_client("alice");
    let fp = a.fingerprint.clone();
    let registry = Arc::new(registry_with(&[("alice".into(), a.cert_pem.clone(), true)]));
    assert!(!handshake_ok(registry, build_client_config(&a)).await);

    let needle = format!("fingerprint=sha256:{fp}");
    let lines = captured_lines();
    let events: Vec<_> = lines
        .iter()
        .filter(|l| l.contains("event=mtls_handshake") && l.contains(&needle))
        .collect();
    assert_eq!(events.len(), 1, "expected one audit event: {lines:?}");
    let e = events[0];
    assert!(e.contains("outcome=rejected"), "{e}");
    assert!(e.contains("reason=revoked"), "{e}");
    assert!(e.contains("client_id=alice"), "{e}");
}

#[tokio::test]
#[traced_test]
async fn audit_never_logs_pem() {
    ensure_crypto_provider();
    let a = gen_client("alice");
    let b = gen_client("bob");

    // Все три сценария: ok, unknown, revoked.
    let ok = Arc::new(registry_with(&[(
        "alice".into(),
        a.cert_pem.clone(),
        false,
    )]));
    assert!(handshake_ok(ok, build_client_config(&a)).await);
    let unknown = Arc::new(config::ClientRegistry::default());
    assert!(!handshake_ok(unknown, build_client_config(&b)).await);
    let revoked = Arc::new(registry_with(&[("alice".into(), a.cert_pem.clone(), true)]));
    assert!(!handshake_ok(revoked, build_client_config(&a)).await);

    for line in captured_lines() {
        assert!(!line.contains("-----BEGIN"), "PEM leak: {line}");
        assert!(!line.contains("PRIVATE KEY"), "key leak: {line}");
        assert!(!line.contains("-----END"), "PEM leak: {line}");
    }
}
