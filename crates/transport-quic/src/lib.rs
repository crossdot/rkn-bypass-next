//! QUIC-транспорт на `quinn` (rustls-ring) — реализация [`Transport`].
//!
//! 0-RTT выключен: нигде не вызывается `Connecting::into_0rtt()` /
//! `Incoming::into_0rtt()` (в quinn 0.11 0-RTT — opt-in; см. ADR-022).
//!
//! Bi-directional stream открывается лениво (на первом `send`/`recv`):
//! quinn отправляет STREAM frame только после записи в `SendStream`.
//! Серверный транспорт держит `Arc<Endpoint>` — иначе UDP-сокет дропается
//! при возврате из accept-цикла и соединение закрывается.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use transport_api::{Transport, TransportError};

pub use quinn;

/// Идемпотентно устанавливает `ring` как crypto-provider rustls по умолчанию.
pub fn ensure_crypto_provider() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Собирает `quinn::ServerConfig` из `rustls::ServerConfig` (mTLS).
pub fn server_config(rustls: rustls::ServerConfig) -> Result<quinn::ServerConfig, TransportError> {
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(rustls)
        .map_err(|e| TransportError::ConnectFailed(e.to_string()))?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(crypto)))
}

/// Собирает `quinn::ClientConfig` из `rustls::ClientConfig` (mTLS).
pub fn client_config(rustls: rustls::ClientConfig) -> Result<quinn::ClientConfig, TransportError> {
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(rustls)
        .map_err(|e| TransportError::ConnectFailed(e.to_string()))?;
    Ok(quinn::ClientConfig::new(Arc::new(crypto)))
}

/// Клиентский QUIC-транспорт.
pub struct QuicClientTransport {
    endpoint: quinn::Endpoint,
    server_addr: SocketAddr,
    server_name: String,
    handshake_timeout: Duration,
    conn: Option<quinn::Connection>,
    send: Option<quinn::SendStream>,
    recv: Option<quinn::RecvStream>,
}

impl QuicClientTransport {
    /// Создаёт клиентский транспорт без установки соединения.
    pub fn new(
        server_addr: SocketAddr,
        server_name: &str,
        config: quinn::ClientConfig,
        handshake_timeout: Duration,
    ) -> Result<Self, TransportError> {
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| TransportError::ConnectFailed(format!("quic endpoint: {e}")))?;
        endpoint.set_default_client_config(config);
        Ok(Self {
            endpoint,
            server_addr,
            server_name: server_name.to_owned(),
            handshake_timeout,
            conn: None,
            send: None,
            recv: None,
        })
    }

    async fn ensure_stream(&mut self) -> Result<(), TransportError> {
        if self.send.is_some() {
            return Ok(());
        }
        let conn = self.conn.as_ref().ok_or(TransportError::NotConnected)?;
        let (send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| TransportError::ConnectFailed(format!("quic open_bi: {e}")))?;
        self.send = Some(send);
        self.recv = Some(recv);
        Ok(())
    }
}

#[async_trait]
impl Transport for QuicClientTransport {
    async fn connect(&mut self) -> Result<(), TransportError> {
        // `connect` (не `into_0rtt`) — полный handshake, 0-RTT выключен.
        let connecting = self
            .endpoint
            .connect(self.server_addr, &self.server_name)
            .map_err(|e| TransportError::ConnectFailed(format!("quic connect: {e}")))?;
        let conn = tokio::time::timeout(self.handshake_timeout, connecting)
            .await
            .map_err(|_| TransportError::ConnectFailed("quic handshake timeout".to_string()))?
            .map_err(|e| TransportError::ConnectFailed(format!("quic handshake: {e}")))?;
        self.conn = Some(conn);
        Ok(())
    }

    async fn send(&mut self, data: &[u8]) -> Result<usize, TransportError> {
        self.ensure_stream().await?;
        self.send
            .as_mut()
            .ok_or(TransportError::NotConnected)?
            .write_all(data)
            .await
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        Ok(data.len())
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
        self.ensure_stream().await?;
        match self
            .recv
            .as_mut()
            .ok_or(TransportError::NotConnected)?
            .read(buf)
            .await
        {
            Ok(Some(n)) => Ok(n),
            Ok(None) => Ok(0),
            Err(e) => Err(TransportError::RecvFailed(e.to_string())),
        }
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        if let Some(conn) = self.conn.take() {
            conn.close(0u32.into(), b"");
        }
        self.endpoint.wait_idle().await;
        Ok(())
    }
}

/// Серверный QUIC-транспорт: принятое соединение + ленивый bi-stream.
pub struct QuicServerTransport {
    // Keep-alive: держит UDP-сокет/driver, чтобы соединение не закрылось
    // после возврата из accept-цикла. Поле намеренно не читается.
    _endpoint: Arc<quinn::Endpoint>,
    conn: quinn::Connection,
    send: Option<quinn::SendStream>,
    recv: Option<quinn::RecvStream>,
}

impl QuicServerTransport {
    /// Оборачивает принятое соединение (bi-stream открывается лениво).
    /// Держит `Arc<Endpoint>`, чтобы UDP-сокет не закрылся до конца соединения.
    pub fn new(endpoint: Arc<quinn::Endpoint>, conn: quinn::Connection) -> Self {
        Self {
            _endpoint: endpoint,
            conn,
            send: None,
            recv: None,
        }
    }

    /// UDP-адрес пира.
    pub fn remote_address(&self) -> SocketAddr {
        self.conn.remote_address()
    }

    /// DER-сертификат клиента (после handshake), если предъявлен.
    pub fn peer_certificate_der(&self) -> Option<Vec<u8>> {
        let any = self.conn.peer_identity()?;
        let certs: Box<Vec<rustls::pki_types::CertificateDer>> = any.downcast().ok()?;
        certs.first().map(|c| c.as_ref().to_vec())
    }

    async fn ensure_stream(&mut self) -> Result<(), TransportError> {
        if self.send.is_some() {
            return Ok(());
        }
        let (send, recv) = self
            .conn
            .accept_bi()
            .await
            .map_err(|e| TransportError::RecvFailed(format!("quic accept_bi: {e}")))?;
        self.send = Some(send);
        self.recv = Some(recv);
        Ok(())
    }
}

#[async_trait]
impl Transport for QuicServerTransport {
    async fn connect(&mut self) -> Result<(), TransportError> {
        // Соединение уже установлено в accept-цикле.
        Ok(())
    }

    async fn send(&mut self, data: &[u8]) -> Result<usize, TransportError> {
        self.ensure_stream().await?;
        self.send
            .as_mut()
            .ok_or(TransportError::NotConnected)?
            .write_all(data)
            .await
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        Ok(data.len())
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
        self.ensure_stream().await?;
        match self
            .recv
            .as_mut()
            .ok_or(TransportError::NotConnected)?
            .read(buf)
            .await
        {
            Ok(Some(n)) => Ok(n),
            Ok(None) => Ok(0),
            Err(e) => Err(TransportError::RecvFailed(e.to_string())),
        }
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        self.conn.close(0u32.into(), b"");
        Ok(())
    }
}
