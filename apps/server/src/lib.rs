//! Серверная аутентификация: mTLS-верификатор и session manager.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::WebPkiClientVerifier;
use rustls::{DigitallySignedStruct, DistinguishedName, Error, RootCertStore, SignatureScheme};

/// mTLS-верификатор: проверяет цепочку через `WebPkiClientVerifier` и
/// дополнительно — что fingerprint сертификата известен и не отозван.
///
/// Отказ происходит на TLS-уровне, до прикладного слоя (до `ConnectAck`).
#[derive(Debug)]
pub struct AuthClientVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    registry: Arc<config::ClientRegistry>,
    /// Адрес пира, если известен до handshake. QUIC-верификатор общий для
    /// Endpoint'а и адрес пира до handshake недоступен → `None` (ADR-022).
    remote_addr: Option<SocketAddr>,
}

impl AuthClientVerifier {
    /// Собирает внутренний верификатор цепочки (WebPkiClientVerifier)
    /// один раз; результат шарится между всеми соединениями.
    pub fn build_inner(
        roots: Arc<RootCertStore>,
    ) -> Result<Arc<dyn ClientCertVerifier>, rustls::server::VerifierBuilderError> {
        WebPkiClientVerifier::builder(roots).build()
    }

    /// Лёгкая обёртка на одно соединение: разделяемый верификатор цепочки,
    /// реестр известных клиентов и `remote_addr` (для аудит-событий).
    pub fn new(
        inner: Arc<dyn ClientCertVerifier>,
        registry: Arc<config::ClientRegistry>,
        remote_addr: Option<SocketAddr>,
    ) -> Self {
        Self {
            inner,
            registry,
            remote_addr,
        }
    }
}

impl ClientCertVerifier for AuthClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        // Цепочка/подпись/срок проверяются здесь; при неудаче — TLS-уровень
        // (bad_signature/expired/untrusted), аудит не эмитируется (ADR-021).
        self.inner
            .verify_client_cert(end_entity, intermediates, now)?;
        let fp = crypto::fingerprint(end_entity.as_ref());
        let fp_display = format!("sha256:{fp}");
        // `None` — адрес недоступен (QUIC pre-handshake, ADR-022).
        let remote_addr = match self.remote_addr {
            Some(a) => a.to_string(),
            None => "-".to_string(),
        };
        match self.registry.find_by_fingerprint(&fp) {
            Some(e) if !e.revoked => {
                tracing::info!(
                    event = %"mtls_handshake",
                    outcome = %"ok",
                    fingerprint = %fp_display,
                    client_id = %e.client_id,
                    remote_addr = %remote_addr,
                );
                Ok(ClientCertVerified::assertion())
            }
            Some(e) => {
                tracing::warn!(
                    event = %"mtls_handshake",
                    outcome = %"rejected",
                    reason = %"revoked",
                    fingerprint = %fp_display,
                    client_id = %e.client_id,
                    remote_addr = %remote_addr,
                );
                Err(Error::General("client not authorized".to_string()))
            }
            None => {
                tracing::warn!(
                    event = %"mtls_handshake",
                    outcome = %"rejected",
                    reason = %"unknown_fingerprint",
                    fingerprint = %fp_display,
                    remote_addr = %remote_addr,
                );
                Err(Error::General("client not authorized".to_string()))
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Простой session manager: ограничение активных сессий на клиента.
///
/// Не часть TLS-аутентификации (ADR-021): применяется после handshake.
#[derive(Debug, Default)]
pub struct SessionManager {
    counts: Mutex<HashMap<String, usize>>,
}

impl SessionManager {
    /// Создаёт пустой session manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Пытается занять сессию для fingerprint; `max == None` — без ограничения.
    /// Возвращает `false`, если лимит активных сессий исчерпан.
    pub fn try_acquire(&self, fingerprint: &str, max: Option<u32>) -> bool {
        let mut counts = self.counts.lock().unwrap();
        let n = counts.entry(fingerprint.to_string()).or_insert(0);
        if let Some(max) = max {
            if *n >= max as usize {
                return false;
            }
        }
        *n += 1;
        true
    }

    /// Освобождает сессию.
    pub fn release(&self, fingerprint: &str) {
        let mut counts = self.counts.lock().unwrap();
        if let Some(n) = counts.get_mut(fingerprint) {
            *n = n.saturating_sub(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_limit_enforced() {
        let m = SessionManager::new();
        assert!(m.try_acquire("fp-a", Some(1)));
        assert!(!m.try_acquire("fp-a", Some(1))); // лимит исчерпан
        m.release("fp-a");
        assert!(m.try_acquire("fp-a", Some(1))); // после release — снова можно
    }

    #[test]
    fn unlimited_sessions() {
        let m = SessionManager::new();
        assert!(m.try_acquire("fp-a", None));
        assert!(m.try_acquire("fp-a", None));
    }
}
