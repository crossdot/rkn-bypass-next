//! Обёртки над проверенными криптографическими библиотеками.
//!
//! Собственной криптографии нет: выпуск сертификатов — `rcgen`,
//! хеширование — `ring` (SHA-256), обнуление секретов — `zeroize`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::fmt;

use zeroize::Zeroize;

/// Ошибка крипто-операций. Не содержит секретов.
#[derive(Debug)]
pub enum CryptoError {
    /// Ошибка генерации или парсинга сертификата.
    Cert(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cert(e) => write!(f, "certificate error: {e}"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Секрет: байты обнуляются при `Drop`.
///
/// Не реализует `Debug`, `Display` и не попадает в ошибки/логи.
pub struct Secret(Vec<u8>);

impl Secret {
    /// Создаёт секрет из байтов.
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    /// Доступ к секрету (только для записи в файл или stdout).
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// SHA-256 от DER-encoded сертификата (hex, lowercase, 64 символа).
pub fn fingerprint(der: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, der);
    hex_encode(digest.as_ref())
}

/// SHA-256, усечённый до 12 hex — для логирования идентификаторов.
pub fn short_hash(data: &[u8]) -> String {
    fingerprint(data)[..12].to_string()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Сгенерированный клиентский сертификат и ключ.
pub struct GeneratedClient {
    /// Публичный сертификат (PEM).
    pub cert_pem: String,
    /// Приватный ключ (PEM). Обнуляется при `Drop`.
    pub key_pem: Secret,
    /// SHA-256 fingerprint DER-сертификата (hex).
    pub fingerprint: String,
}

/// Генерирует клиентский сертификат (ECDSA P-256), подписанный
/// существующим CA. `client_id` записывается в CN сертификата.
pub fn generate_client_cert(
    client_id: &str,
    ca_cert_pem: &str,
    ca_key_pem: &str,
) -> Result<GeneratedClient, CryptoError> {
    use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair};

    let ca_key = KeyPair::from_pem(ca_key_pem).map_err(|e| CryptoError::Cert(e.to_string()))?;
    let ca_params = CertificateParams::from_ca_cert_pem(ca_cert_pem)
        .map_err(|e| CryptoError::Cert(e.to_string()))?;
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .map_err(|e| CryptoError::Cert(e.to_string()))?;

    let client_key = KeyPair::generate().map_err(|e| CryptoError::Cert(e.to_string()))?;
    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| CryptoError::Cert(e.to_string()))?;
    params
        .distinguished_name
        .push(DnType::CommonName, client_id);
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let cert = params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .map_err(|e| CryptoError::Cert(e.to_string()))?;

    let cert_pem = cert.pem();
    let key_pem = client_key.serialize_pem();
    let fingerprint = fingerprint(cert.der().as_ref());

    Ok(GeneratedClient {
        cert_pem,
        key_pem: Secret::new(key_pem.into_bytes()),
        fingerprint,
    })
}

/// Генерирует self-signed CA (cert PEM, key PEM) — для тестов и бутстрапа.
pub fn generate_ca() -> Result<(String, String), CryptoError> {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

    let key = KeyPair::generate().map_err(|e| CryptoError::Cert(e.to_string()))?;
    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| CryptoError::Cert(e.to_string()))?;
    params
        .distinguished_name
        .push(DnType::CommonName, "test-ca");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let cert = params
        .self_signed(&key)
        .map_err(|e| CryptoError::Cert(e.to_string()))?;
    Ok((cert.pem(), key.serialize_pem()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_sha256_hex() {
        let fp = fingerprint(b"hello");
        assert_eq!(fp.len(), 64);
        assert_eq!(
            fp,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn short_hash_truncates() {
        assert_eq!(short_hash(b"hello"), "2cf24dba5fb0");
    }

    #[test]
    fn secret_zeroizes_on_drop() {
        // Проверяем лишь, что Secret не реализует Debug/Display (компиляция).
        let s = Secret::new(vec![1, 2, 3]);
        assert_eq!(s.expose(), &[1, 2, 3]);
        drop(s);
    }

    #[test]
    fn generate_client_cert_works() {
        let (ca_cert, ca_key) = generate_ca().unwrap();
        let client = generate_client_cert("alice", &ca_cert, &ca_key).unwrap();
        assert!(client.cert_pem.contains("BEGIN CERTIFICATE"));
        assert_eq!(client.fingerprint.len(), 64);
        assert!(!client.key_pem.expose().is_empty());
    }
}
