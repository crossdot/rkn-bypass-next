//! TLS-транспорт на `rustls` — реализация [`Transport`] поверх tokio.
//!
//! Асинхронный: `tokio::net::TcpStream` + `tokio-rustls`. Не знает о профиле,
//! Fallbacks, nginx, домене, `mode` и `entry`; сертификаты передаются снаружи
//! через конфиг rustls.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::net::SocketAddr;
use std::sync::{Arc, Once};
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;

pub use transport_api::{Transport, TransportError};

/// Идемпотентно устанавливает `ring` как crypto-provider rustls по умолчанию.
pub fn ensure_crypto_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Клиентский TLS-транспорт.
///
/// [`Transport::connect`] устанавливает TCP-соединение и выполняет
/// TLS-handshake с таймаутами.
pub struct ClientTransport {
    addr: SocketAddr,
    server_name: rustls::pki_types::ServerName<'static>,
    config: Arc<rustls::ClientConfig>,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    stream: Option<ClientTlsStream<TcpStream>>,
}

impl ClientTransport {
    /// Создаёт клиентский транспорт без установки соединения.
    pub fn new(
        addr: SocketAddr,
        server_name: &str,
        config: Arc<rustls::ClientConfig>,
        connect_timeout: Duration,
        handshake_timeout: Duration,
    ) -> Result<Self, TransportError> {
        let server_name =
            rustls::pki_types::ServerName::try_from(server_name.to_owned()).map_err(|_| {
                TransportError::ConnectFailed(format!("invalid server name: {server_name}"))
            })?;
        Ok(Self {
            addr,
            server_name,
            config,
            connect_timeout,
            handshake_timeout,
            stream: None,
        })
    }
}

#[async_trait]
impl Transport for ClientTransport {
    async fn connect(&mut self) -> Result<(), TransportError> {
        ensure_crypto_provider();
        let sock = tokio::time::timeout(self.connect_timeout, TcpStream::connect(self.addr))
            .await
            .map_err(|_| {
                TransportError::ConnectFailed(format!("tcp connect to {}: timeout", self.addr))
            })?
            .map_err(|e| {
                TransportError::ConnectFailed(format!("tcp connect to {}: {e}", self.addr))
            })?;
        let connector = tokio_rustls::TlsConnector::from(Arc::clone(&self.config));
        let stream = tokio::time::timeout(
            self.handshake_timeout,
            connector.connect(self.server_name.clone(), sock),
        )
        .await
        .map_err(|_| TransportError::ConnectFailed("tls handshake timeout".to_string()))?
        .map_err(|e| TransportError::ConnectFailed(format!("tls handshake: {e}")))?;
        self.stream = Some(stream);
        Ok(())
    }

    async fn send(&mut self, data: &[u8]) -> Result<usize, TransportError> {
        self.stream
            .as_mut()
            .ok_or(TransportError::NotConnected)?
            .write_all(data)
            .await
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        Ok(data.len())
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
        self.stream
            .as_mut()
            .ok_or(TransportError::NotConnected)?
            .read(buf)
            .await
            .map_err(|e| TransportError::RecvFailed(e.to_string()))
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        let Some(mut stream) = self.stream.take() else {
            return Ok(());
        };
        let _ = stream.shutdown().await;
        Ok(())
    }
}

/// Серверный TLS-транспорт.
///
/// TLS-сессия устанавливается в [`ServerTransport::accept`]; после этого
/// [`Transport::connect`] — no-op (сессия уже активна).
pub struct ServerTransport {
    stream: ServerTlsStream<TcpStream>,
}

impl ServerTransport {
    /// Принимает TLS-сессию поверх уже принятого TCP-соединения.
    pub async fn accept(
        sock: TcpStream,
        config: Arc<rustls::ServerConfig>,
        handshake_timeout: Duration,
    ) -> Result<Self, TransportError> {
        ensure_crypto_provider();
        let acceptor = tokio_rustls::TlsAcceptor::from(config);
        let stream = tokio::time::timeout(handshake_timeout, acceptor.accept(sock))
            .await
            .map_err(|_| TransportError::ConnectFailed("tls handshake timeout".to_string()))?
            .map_err(|e| TransportError::ConnectFailed(format!("tls handshake: {e}")))?;
        Ok(Self { stream })
    }

    /// DER-сертификат клиента (после handshake), если предъявлен.
    pub fn peer_certificate_der(&self) -> Option<Vec<u8>> {
        self.stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certs| certs.first())
            .map(|c| c.as_ref().to_vec())
    }
}

#[async_trait]
impl Transport for ServerTransport {
    async fn connect(&mut self) -> Result<(), TransportError> {
        // Серверная сессия уже установлена в accept().
        Ok(())
    }

    async fn send(&mut self, data: &[u8]) -> Result<usize, TransportError> {
        self.stream
            .write_all(data)
            .await
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        Ok(data.len())
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
        self.stream
            .read(buf)
            .await
            .map_err(|e| TransportError::RecvFailed(e.to_string()))
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        let _ = self.stream.shutdown().await;
        Ok(())
    }
}
