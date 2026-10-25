//! Серверная аутентификация: mTLS-верификатор и session manager.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::HashMap;
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
}

impl AuthClientVerifier {
    /// Создаёт верификатор. `roots` — доверенные CA клиентов,
    /// `registry` — реестр известных клиентов (fingerprint → отзыв).
    pub fn new(
        roots: Arc<RootCertStore>,
        registry: Arc<config::ClientRegistry>,
    ) -> Result<Self, rustls::server::VerifierBuilderError> {
        let inner = WebPkiClientVerifier::builder(roots).build()?;
        Ok(Self { inner, registry })
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
        self.inner
            .verify_client_cert(end_entity, intermediates, now)?;
        let fp = crypto::fingerprint(end_entity.as_ref());
        match self.registry.find_by_fingerprint(&fp) {
            Some(e) if !e.revoked => Ok(ClientCertVerified::assertion()),
            _ => Err(Error::General("client not authorized".to_string())),
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
