//! Отзыв клиента применяется при перезапуске/перезагрузке конфига — по QUIC.
//! Семантика та же, что в `mtls_revoke.rs` (ADR-021, ADR-022).

mod common;

use std::sync::Arc;

use common::*;

#[tokio::test(flavor = "multi_thread")]
async fn quic_revoke_applied_on_restart() {
    ensure_crypto_provider();
    let alice = gen_client("alice");
    let bob = gen_client("bob");
    let alice_cfg = build_client_config_quic(&alice);
    let bob_cfg = build_client_config_quic(&bob);

    let before = Arc::new(registry_with(&[
        ("alice".to_string(), alice.cert_pem.clone(), false),
        ("bob".to_string(), bob.cert_pem.clone(), false),
    ]));
    assert!(
        handshake_ok_quic(Arc::clone(&before), alice_cfg.clone()).await,
        "alice должен пройти handshake до отзыва"
    );
    assert!(
        handshake_ok_quic(Arc::clone(&before), bob_cfg.clone()).await,
        "bob должен пройти handshake до отзыва"
    );

    // «Перезапуск»: новый реестр, alice отозван.
    let after = Arc::new(registry_with(&[
        ("alice".to_string(), alice.cert_pem.clone(), true),
        ("bob".to_string(), bob.cert_pem.clone(), false),
    ]));
    assert!(
        !handshake_ok_quic(Arc::clone(&after), alice_cfg).await,
        "отозванный alice не должен пройти handshake"
    );
    assert!(
        handshake_ok_quic(Arc::clone(&after), bob_cfg).await,
        "bob должен пройти handshake после отзыва alice"
    );
}
