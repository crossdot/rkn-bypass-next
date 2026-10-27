//! Абстракция транспорта: трейт [`Transport`], [`BidirectionalRelay`] и типы
//! ошибок.
//!
//! [`Transport`] не зависит от tokio напрямую (только [`async_trait`] для
//! object-safety и `Send`). [`BidirectionalRelay`] — отдельная от [`Transport`]
//! капабилити двунаправленного relay; её сигнатура принимает
//! [`tokio::net::TcpStream`] (прикладная сторона), поэтому для неё нужен tokio.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use async_trait::async_trait;
use std::fmt;
use tokio::net::TcpStream;

/// Трейт сетевого транспорта (асинхронный).
///
/// Определяет минимальный контракт передачи байтов поверх tokio.
/// Все методы принимают `&mut self`: транспорт владеет состоянием соединения.
///
/// `#[async_trait]` даёт object-safety и `Send` для `tokio::spawn`
/// (ADR-017: `Box<dyn Transport>` для диспетчеризации по конфигу).
#[async_trait]
pub trait Transport {
    /// Устанавливает соединение с удалённой точкой.
    async fn connect(&mut self) -> Result<(), TransportError>;

    /// Отправляет байты. Возвращает количество фактически записанных байт.
    async fn send(&mut self, data: &[u8]) -> Result<usize, TransportError>;

    /// Принимает байты в `buf`. Возвращает количество прочитанных байт;
    /// `0` означает конец потока (EOF).
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, TransportError>;

    /// Закрывает соединение и освобождает ресурсы.
    async fn close(&mut self) -> Result<(), TransportError>;
}

/// Ошибка транспортного уровня.
#[derive(Debug)]
pub enum TransportError {
    /// Ошибка ввода-вывода.
    Io(std::io::Error),
    /// Транспорт не подключён: `connect` не вызван или не завершился.
    NotConnected,
    /// Соединение закрыто.
    Closed,
    /// Ошибка установления соединения.
    ConnectFailed(String),
    /// Ошибка отправки данных.
    SendFailed(String),
    /// Ошибка приёма данных.
    RecvFailed(String),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "io error: {err}"),
            Self::NotConnected => write!(f, "transport not connected"),
            Self::Closed => write!(f, "transport closed"),
            Self::ConnectFailed(msg) => write!(f, "connect failed: {msg}"),
            Self::SendFailed(msg) => write!(f, "send failed: {msg}"),
            Self::RecvFailed(msg) => write!(f, "recv failed: {msg}"),
        }
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for TransportError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// Псевдоним результата транспортной операции.
pub type TransportResult<T, E = TransportError> = std::result::Result<T, E>;

/// Двунаправленная передача байтов между транспортом и TCP-сокетом.
///
/// Отдельный от [`Transport`] трейт (ADR-025 — контракт [`Transport`] не
/// изменяется). [`Transport::send`]/[`Transport::recv`] принимают `&mut self` и
/// не могут исполняться конкурентно на одном объекте; наивный опрос обеих
/// сторон (`timeout`-поллинг) приводит к дедлоку под backpressure, когда обе
/// стороны заполнены: каждый `send` ждёт, пока противоположная сторона не
/// освободит окно, а та — своего `send`. Поэтому корректный relay требует
/// знания конкретного транспорта:
///  - TLS (`TlsStream` — `AsyncRead + AsyncWrite`): `tokio::io::copy_bidirectional`;
///  - QUIC (`SendStream`/`RecvStream` — раздельные `&mut`-потоки):
///    два конкурентных `task`-а с одной стороной на каждый.
///
/// Реализации находятся в `transport-tls`, `transport-quic` и `transport-any`.
#[async_trait]
pub trait BidirectionalRelay {
    /// Передаёт байты в обе стороны до завершения потока.
    ///
    /// `tcp` — «прикладная» сторона: app-сокет клиента или TCP-соединение к
    /// цели на сервере. Транспорт должен быть уже подключён. Завершение одной
    /// стороны закрывает другую (graceful drain); ошибка любой стороны
    /// прерывает передачу.
    async fn relay_bidirectional(self, tcp: TcpStream) -> Result<(), TransportError>;
}
