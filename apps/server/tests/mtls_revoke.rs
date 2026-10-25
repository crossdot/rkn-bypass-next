//! Тест отзыва клиента: отозванный клиент не устанавливает новое
//! соединение после перезапуска сервера с обновлённым конфигом.
//! См. ADR-021 «Отзыв и ротация».

mod common;
use common::*;

use std::sync::Arc;

#[test]
fn revoke_applied_on_restart() {
    ensure_crypto_provider();
    let a = gen_client("alice");
    let b = gen_client("bob");

    // До отзыва: оба клиента авторизованы и подключаются.
    let before = Arc::new(registry_with(&[
        ("alice".into(), a.cert_pem.clone(), false),
        ("bob".into(), b.cert_pem.clone(), false),
    ]));
    assert!(handshake_ok(Arc::clone(&before), build_client_config(&a)));
    assert!(handshake_ok(before, build_client_config(&b)));

    // Перезапуск с конфигом, где alice отозван.
    let after = Arc::new(registry_with(&[
        ("alice".into(), a.cert_pem.clone(), true),
        ("bob".into(), b.cert_pem.clone(), false),
    ]));

    // Отозванный клиент не проходит рукопожатие.
    assert!(!handshake_ok(Arc::clone(&after), build_client_config(&a)));
    // Остальные клиенты продолжают подключаться.
    assert!(handshake_ok(after, build_client_config(&b)));
}
