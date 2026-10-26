//! Версионированный формат сообщений прикладного протокола.
//!
//! Wire-формат (big-endian):
//! ```text
//! +---------+---------+----------------+---------------+
//! | version | kind    | length         | payload       |
//! | u8      | u8      | u32 (BE)       | length байт   |
//! +---------+---------+----------------+---------------+
//! ```
//!
//! Заголовок — [`HEADER_LEN`] байт. Парсинг чистый; I/O асинхронный поверх
//! [`Transport`].

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::fmt;
use transport_api::{Transport, TransportError};

/// Текущая версия протокола.
pub const VERSION: u8 = 1;

/// Длина заголовка сообщения: version(1) + kind(1) + length(4).
pub const HEADER_LEN: usize = 6;

/// Максимальный размер payload одного сообщения (1 МиБ).
pub const MAX_PAYLOAD_SIZE: usize = 1024 * 1024;

/// Максимальный полный размер сообщения (заголовок + payload).
pub const MAX_MESSAGE_SIZE: usize = HEADER_LEN + MAX_PAYLOAD_SIZE;

/// Тип сообщения.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MessageKind {
    /// Контрольное сообщение (проверка соединения, контрольные байты).
    Control = 0x01,
    /// Запрос CONNECT: передача цели (адрес + порт) клиент → сервер.
    Connect = 0x02,
    /// Подтверждение CONNECT: REP-код (payload 1 байт) сервер → клиент.
    ConnectAck = 0x03,
}

impl MessageKind {
    /// Преобразует байт wire-формата в [`MessageKind`].
    ///
    /// Неизвестный тип → [`ProtocolError::UnknownMessageKind`].
    pub fn from_u8(value: u8) -> Result<Self, ProtocolError> {
        match value {
            0x01 => Ok(Self::Control),
            0x02 => Ok(Self::Connect),
            0x03 => Ok(Self::ConnectAck),
            other => Err(ProtocolError::UnknownMessageKind(other)),
        }
    }
}

/// Сообщение протокола текущей версии.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Тип сообщения.
    pub kind: MessageKind,
    /// Полезная нагрузка.
    pub payload: Vec<u8>,
}

impl Message {
    /// Создаёт сообщение.
    pub fn new(kind: MessageKind, payload: Vec<u8>) -> Self {
        Self { kind, payload }
    }

    /// Кодирует сообщение в wire-формат.
    ///
    /// Ошибка [`ProtocolError::PayloadTooLarge`], если payload превышает
    /// [`MAX_PAYLOAD_SIZE`].
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut buf = Vec::with_capacity(HEADER_LEN + self.payload.len());
        self.encode_into(&mut buf)?;
        Ok(buf)
    }

    /// Дописывает сообщение в `out` в wire-формате.
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), ProtocolError> {
        if self.payload.len() > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::PayloadTooLarge {
                got: self.payload.len(),
                max: MAX_PAYLOAD_SIZE,
            });
        }
        out.push(VERSION);
        out.push(self.kind as u8);
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.payload);
        Ok(())
    }

    /// Декодирует одно сообщение из начала `buf`.
    ///
    /// Возвращает сообщение и число потреблённых байт. Лишние байты после
    /// сообщения игнорируются. Порядок проверок: версия, тип, длина, payload.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), ProtocolError> {
        let header = buf.get(..HEADER_LEN).ok_or(ProtocolError::Truncated {
            needed: HEADER_LEN,
            got: buf.len(),
        })?;

        let version = header[0];
        if version != VERSION {
            return Err(ProtocolError::UnsupportedVersion {
                got: version,
                supported: VERSION,
            });
        }

        let kind = MessageKind::from_u8(header[1])?;

        let len = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
        if len > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::PayloadTooLarge {
                got: len,
                max: MAX_PAYLOAD_SIZE,
            });
        }

        let payload = buf
            .get(HEADER_LEN..HEADER_LEN + len)
            .ok_or(ProtocolError::Truncated {
                needed: HEADER_LEN + len,
                got: buf.len(),
            })?;

        Ok((
            Self {
                kind,
                payload: payload.to_vec(),
            },
            HEADER_LEN + len,
        ))
    }
}

/// Ошибка протокола.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    /// Версия сообщения не поддерживается: принимающая сторона обязана
    /// отвергнуть сообщение, не разбирая payload.
    UnsupportedVersion {
        /// Полученная версия.
        got: u8,
        /// Поддерживаемая версия.
        supported: u8,
    },
    /// Неизвестный тип сообщения: отвергнуть, не обрабатывая payload.
    UnknownMessageKind(u8),
    /// Payload превышает [`MAX_PAYLOAD_SIZE`].
    PayloadTooLarge {
        /// Заявленный размер.
        got: usize,
        /// Максимально допустимый размер.
        max: usize,
    },
    /// Сообщение обрезано: не хватает байт.
    Truncated {
        /// Сколько байт требуется.
        needed: usize,
        /// Сколько байт доступно.
        got: usize,
    },
    /// Ошибка ввода-вывода нижележащего потока.
    Io(String),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion { got, supported } => {
                write!(
                    f,
                    "unsupported protocol version {got} (supported: {supported})"
                )
            }
            Self::UnknownMessageKind(kind) => write!(f, "unknown message kind 0x{kind:02x}"),
            Self::PayloadTooLarge { got, max } => {
                write!(f, "payload too large: {got} bytes (max {max})")
            }
            Self::Truncated { needed, got } => {
                write!(f, "message truncated: need {needed} bytes, have {got}")
            }
            Self::Io(err) => write!(f, "io error: {err}"),
        }
    }
}

impl std::error::Error for ProtocolError {}

/// Читает одно сообщение из транспорта.
pub async fn read_message<T: Transport + ?Sized>(
    transport: &mut T,
) -> Result<Message, ProtocolError> {
    let mut header = [0u8; HEADER_LEN];
    read_exact(transport, &mut header).await.map_err(io_err)?;

    let version = header[0];
    if version != VERSION {
        return Err(ProtocolError::UnsupportedVersion {
            got: version,
            supported: VERSION,
        });
    }

    let kind = MessageKind::from_u8(header[1])?;

    let len = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
    if len > MAX_PAYLOAD_SIZE {
        return Err(ProtocolError::PayloadTooLarge {
            got: len,
            max: MAX_PAYLOAD_SIZE,
        });
    }

    let mut payload = vec![0u8; len];
    read_exact(transport, &mut payload).await.map_err(io_err)?;

    Ok(Message { kind, payload })
}

/// Записывает одно сообщение в транспорт.
pub async fn write_message<T: Transport + ?Sized>(
    transport: &mut T,
    message: &Message,
) -> Result<(), ProtocolError> {
    let encoded = message.encode()?;
    transport.send(&encoded).await.map_err(io_err)?;
    Ok(())
}

/// Читает ровно `buf.len()` байт из транспорта (аналог `read_exact`).
async fn read_exact<T: Transport + ?Sized>(
    transport: &mut T,
    buf: &mut [u8],
) -> Result<(), TransportError> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = transport.recv(&mut buf[filled..]).await?;
        if n == 0 {
            return Err(TransportError::Closed);
        }
        filled += n;
    }
    Ok(())
}

fn io_err(e: TransportError) -> ProtocolError {
    ProtocolError::Io(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(version: u8, kind: u8, len: u32) -> Vec<u8> {
        let mut v = vec![version, kind];
        v.extend_from_slice(&len.to_be_bytes());
        v
    }

    #[test]
    fn roundtrip() {
        let m = Message::new(MessageKind::Control, b"hello".to_vec());
        let enc = m.encode().unwrap();
        let (dec, consumed) = Message::decode(&enc).unwrap();
        assert_eq!(dec, m);
        assert_eq!(consumed, enc.len());
    }

    #[test]
    fn unknown_kind_rejected() {
        let buf = header(VERSION, 0x99, 0);
        assert_eq!(
            Message::decode(&buf).unwrap_err(),
            ProtocolError::UnknownMessageKind(0x99)
        );
    }

    #[test]
    fn payload_too_large_rejected() {
        let buf = header(VERSION, 0x01, (MAX_PAYLOAD_SIZE as u32) + 1);
        assert!(matches!(
            Message::decode(&buf).unwrap_err(),
            ProtocolError::PayloadTooLarge { .. }
        ));
    }

    #[test]
    fn truncated_rejected() {
        // Заголовок заявляет 10 байт payload, которых нет.
        let buf = header(VERSION, 0x01, 10);
        assert!(matches!(
            Message::decode(&buf).unwrap_err(),
            ProtocolError::Truncated { .. }
        ));
    }

    #[test]
    fn unsupported_version_rejected() {
        let buf = header(2, 0x01, 0);
        assert_eq!(
            Message::decode(&buf).unwrap_err(),
            ProtocolError::UnsupportedVersion {
                got: 2,
                supported: VERSION,
            }
        );
    }

    #[test]
    fn oversized_encode_rejected() {
        let m = Message::new(MessageKind::Control, vec![0u8; MAX_PAYLOAD_SIZE + 1]);
        assert!(matches!(
            m.encode().unwrap_err(),
            ProtocolError::PayloadTooLarge { .. }
        ));
    }
}
