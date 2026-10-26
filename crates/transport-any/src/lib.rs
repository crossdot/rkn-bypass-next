//! Диспетчеризация транспортов: TLS (P4a) и QUIC (P4b) за единым `Transport`.
//!
//! Транспорт выбирается конфигом `[server] transport = "tls" | "quic"`
//! (см. `config::TransportKind`). Enum реализует [`Transport`] через `match`,
//! чтобы `proxy-core` не знал о конкретном транспорте.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use async_trait::async_trait;
use transport_api::{Transport, TransportError};
use transport_quic::{QuicClientTransport, QuicServerTransport};
use transport_tls::{ClientTransport, ServerTransport};

/// Клиентский транспорт: TLS или QUIC.
pub enum AnyClientTransport {
    /// TLS (P4a).
    Tls(ClientTransport),
    /// QUIC (P4b).
    Quic(QuicClientTransport),
}

/// Серверный транспорт: TLS или QUIC.
pub enum AnyServerTransport {
    /// TLS (P4a).
    Tls(ServerTransport),
    /// QUIC (P4b).
    Quic(QuicServerTransport),
}

macro_rules! dispatch_transport {
    ($ty:ty, $($variant:ident),+ $(,)?) => {
        #[async_trait]
        impl Transport for $ty {
            async fn connect(&mut self) -> Result<(), TransportError> {
                match self {
                    $(Self::$variant(t) => t.connect().await,)+
                }
            }
            async fn send(&mut self, data: &[u8]) -> Result<usize, TransportError> {
                match self {
                    $(Self::$variant(t) => t.send(data).await,)+
                }
            }
            async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
                match self {
                    $(Self::$variant(t) => t.recv(buf).await,)+
                }
            }
            async fn close(&mut self) -> Result<(), TransportError> {
                match self {
                    $(Self::$variant(t) => t.close().await,)+
                }
            }
        }
    };
}

impl AnyServerTransport {
    /// DER-сертификат клиента (после handshake), если предъявлен.
    /// Нужен общему per-connection пути (fingerprint → сессии → аудит).
    pub fn peer_certificate_der(&self) -> Option<Vec<u8>> {
        match self {
            Self::Tls(t) => t.peer_certificate_der(),
            Self::Quic(t) => t.peer_certificate_der(),
        }
    }
}

dispatch_transport!(AnyClientTransport, Tls, Quic);
dispatch_transport!(AnyServerTransport, Tls, Quic);
