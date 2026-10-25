//! TLS-транспорт на `rustls` — первая реализация [`Transport`].
//!
//! Синхронный: блокирующий ввод-вывод поверх [`std::net::TcpStream`] и
//! `rustls::StreamOwned`. Не знает о профиле, Fallbacks, nginx, домене,
//! `mode` и `entry`; сертификаты передаются снаружи через конфиг rustls.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Once};
use std::time::Duration;

use rustls::{ClientConnection, ServerConnection, StreamOwned};

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
/// TLS-handshake с таймаутом.
pub struct ClientTransport {
    addr: SocketAddr,
    server_name: rustls::pki_types::ServerName<'static>,
    config: Arc<rustls::ClientConfig>,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    stream: Option<StreamOwned<ClientConnection, TcpStream>>,
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

impl Transport for ClientTransport {
    fn connect(&mut self) -> Result<(), TransportError> {
        ensure_crypto_provider();
        let sock = TcpStream::connect_timeout(&self.addr, self.connect_timeout).map_err(|e| {
            TransportError::ConnectFailed(format!("tcp connect to {}: {e}", self.addr))
        })?;
        sock.set_read_timeout(Some(self.handshake_timeout))
            .map_err(|e| TransportError::ConnectFailed(format!("set read timeout: {e}")))?;
        sock.set_write_timeout(Some(self.handshake_timeout))
            .map_err(|e| TransportError::ConnectFailed(format!("set write timeout: {e}")))?;

        let conn = ClientConnection::new(Arc::clone(&self.config), self.server_name.clone())
            .map_err(|e| TransportError::ConnectFailed(format!("tls init: {e}")))?;
        let mut stream = StreamOwned::new(conn, sock);

        while stream.conn.is_handshaking() {
            stream
                .conn
                .complete_io(&mut stream.sock)
                .map_err(|e| TransportError::ConnectFailed(format!("tls handshake: {e}")))?;
        }

        // Handshake прошёл — снимаем таймаут, дальше обычная блокирующая передача.
        let _ = stream.sock.set_read_timeout(None);
        let _ = stream.sock.set_write_timeout(None);
        self.stream = Some(stream);
        Ok(())
    }

    fn send(&mut self, data: &[u8]) -> Result<usize, TransportError> {
        self.stream
            .as_mut()
            .ok_or(TransportError::NotConnected)?
            .write_all(data)
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        Ok(data.len())
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
        self.stream
            .as_mut()
            .ok_or(TransportError::NotConnected)?
            .read(buf)
            .map_err(|e| TransportError::RecvFailed(e.to_string()))
    }

    fn close(&mut self) -> Result<(), TransportError> {
        let Some(mut stream) = self.stream.take() else {
            return Ok(());
        };
        stream.conn.send_close_notify();
        let _ = stream.conn.complete_io(&mut stream.sock);
        Ok(())
    }
}

impl Read for ClientTransport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.stream.as_mut() {
            Some(stream) => stream.read(buf),
            None => Err(io::Error::new(io::ErrorKind::NotConnected, "not connected")),
        }
    }
}

impl Write for ClientTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.stream.as_mut() {
            Some(stream) => stream.write(buf),
            None => Err(io::Error::new(io::ErrorKind::NotConnected, "not connected")),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.stream.as_mut() {
            Some(stream) => stream.flush(),
            None => Err(io::Error::new(io::ErrorKind::NotConnected, "not connected")),
        }
    }
}

/// Серверный TLS-транспорт.
///
/// TLS-сессия устанавливается в [`ServerTransport::accept`]; после этого
/// [`Transport::connect`] — no-op (сессия уже активна).
pub struct ServerTransport {
    stream: StreamOwned<ServerConnection, TcpStream>,
}

impl ServerTransport {
    /// Принимает TLS-сессию поверх уже принятого TCP-соединения.
    pub fn accept(
        sock: TcpStream,
        config: Arc<rustls::ServerConfig>,
        handshake_timeout: Duration,
    ) -> Result<Self, TransportError> {
        ensure_crypto_provider();
        sock.set_read_timeout(Some(handshake_timeout))
            .map_err(|e| TransportError::ConnectFailed(format!("set read timeout: {e}")))?;
        sock.set_write_timeout(Some(handshake_timeout))
            .map_err(|e| TransportError::ConnectFailed(format!("set write timeout: {e}")))?;

        let conn = ServerConnection::new(config)
            .map_err(|e| TransportError::ConnectFailed(format!("tls init: {e}")))?;
        let mut stream = StreamOwned::new(conn, sock);

        while stream.conn.is_handshaking() {
            stream
                .conn
                .complete_io(&mut stream.sock)
                .map_err(|e| TransportError::ConnectFailed(format!("tls handshake: {e}")))?;
        }

        let _ = stream.sock.set_read_timeout(None);
        let _ = stream.sock.set_write_timeout(None);
        Ok(Self { stream })
    }
}

impl Transport for ServerTransport {
    fn connect(&mut self) -> Result<(), TransportError> {
        // Серверная сессия уже установлена в accept().
        Ok(())
    }

    fn send(&mut self, data: &[u8]) -> Result<usize, TransportError> {
        self.stream
            .write_all(data)
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        Ok(data.len())
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
        self.stream
            .read(buf)
            .map_err(|e| TransportError::RecvFailed(e.to_string()))
    }

    fn close(&mut self) -> Result<(), TransportError> {
        self.stream.conn.send_close_notify();
        let _ = self.stream.conn.complete_io(&mut self.stream.sock);
        Ok(())
    }
}

impl Read for ServerTransport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
}

impl Write for ServerTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}
