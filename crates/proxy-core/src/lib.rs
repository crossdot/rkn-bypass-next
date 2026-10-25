//! SOCKS5-режим: handshake, двунаправленный relay и логические потоки.
//!
//! Thread-per-connection (ADR-017). Использует [`socks5`] для парсинга,
//! [`protocol`] для прикладного протокола клиент↔сервер и
//! [`transport_tls`] для транспорта.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, TcpStream};
use std::time::Duration;

use transport_tls::{ClientTransport, ServerTransport, Transport};

/// Интервал опроса relay-цикла (таймаут чтения на обеих сторонах).
pub const RELAY_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Ошибка SOCKS5-режима.
#[derive(Debug)]
pub enum ProxyError {
    /// Ошибка SOCKS5-протокола.
    Socks5(socks5::Socks5Error),
    /// Ошибка прикладного протокола.
    Protocol(protocol::ProtocolError),
    /// Ошибка транспорта.
    Transport(transport_tls::TransportError),
    /// Ошибка ввода-вывода.
    Io(std::io::Error),
    /// Команда распознана, но не поддерживается (BIND/UDP ASSOCIATE).
    CommandNotSupported(socks5::Command),
    /// Нет приемлемого метода аутентификации.
    NoAcceptableMethod,
    /// Прикладное сообщение имеет неожиданный тип (ожидался `Connect`).
    UnexpectedMessage(protocol::MessageKind),
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Socks5(e) => write!(f, "socks5: {e}"),
            Self::Protocol(e) => write!(f, "protocol: {e}"),
            Self::Transport(e) => write!(f, "transport: {e}"),
            Self::Io(e) => write!(f, "io: {e}"),
            Self::CommandNotSupported(c) => write!(f, "command not supported: {c:?}"),
            Self::NoAcceptableMethod => write!(f, "no acceptable authentication method"),
            Self::UnexpectedMessage(k) => write!(f, "unexpected protocol message kind: {k:?}"),
        }
    }
}

impl std::error::Error for ProxyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Socks5(e) => Some(e),
            Self::Protocol(e) => Some(e),
            Self::Transport(e) => Some(e),
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<socks5::Socks5Error> for ProxyError {
    fn from(e: socks5::Socks5Error) -> Self {
        Self::Socks5(e)
    }
}

impl From<protocol::ProtocolError> for ProxyError {
    fn from(e: protocol::ProtocolError) -> Self {
        Self::Protocol(e)
    }
}

impl From<transport_tls::TransportError> for ProxyError {
    fn from(e: transport_tls::TransportError) -> Self {
        Self::Transport(e)
    }
}

impl From<std::io::Error> for ProxyError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Выполняет SOCKS5-handshake и возвращает цель CONNECT.
///
/// Метод — только NO AUTH. Отклоняет BIND и UDP ASSOCIATE ответом
/// [`socks5::REP_COMMAND_NOTSUPPORTED`]; неверная версия или отсутствие
/// приемлемого метода — ошибка без положительного ответа.
pub fn handshake<S: Read + Write>(stream: &mut S) -> Result<socks5::Target, ProxyError> {
    let greeting = socks5::read_greeting(stream)?;
    if greeting.methods.contains(&socks5::AUTH_NONE) {
        socks5::write_method_selection(stream, socks5::AUTH_NONE)?;
    } else {
        socks5::write_method_selection(stream, socks5::AUTH_NO_ACCEPTABLE)?;
        return Err(ProxyError::NoAcceptableMethod);
    }

    let request = socks5::read_request(stream)?;
    if request.command != socks5::Command::Connect {
        socks5::write_reply(
            stream,
            socks5::REP_COMMAND_NOT_SUPPORTED,
            &socks5::Addr::IPv4([0, 0, 0, 0]),
            0,
        )?;
        return Err(ProxyError::CommandNotSupported(request.command));
    }
    Ok(request.target)
}

/// Отправляет цель CONNECT по прикладному протоколу (клиент → сервер).
pub fn write_connect_target<W: Write>(
    writer: &mut W,
    target: &socks5::Target,
) -> Result<(), ProxyError> {
    protocol::write_message(
        writer,
        &protocol::Message::new(protocol::MessageKind::Connect, target.encode()),
    )?;
    Ok(())
}

/// Читает цель CONNECT из прикладного протокола (на стороне сервера).
pub fn read_connect_target<R: Read>(reader: &mut R) -> Result<socks5::Target, ProxyError> {
    let message = protocol::read_message(reader)?;
    if message.kind != protocol::MessageKind::Connect {
        return Err(ProxyError::UnexpectedMessage(message.kind));
    }
    let (target, _) = socks5::Target::decode(&message.payload)?;
    Ok(target)
}

/// Устанавливает TCP-соединение к цели.
fn connect_target(target: &socks5::Target) -> io::Result<TcpStream> {
    match &target.addr {
        socks5::Addr::IPv4(b) => TcpStream::connect((Ipv4Addr::from(*b), target.port)),
        socks5::Addr::IPv6(b) => TcpStream::connect((Ipv6Addr::from(*b), target.port)),
        socks5::Addr::Domain(d) => {
            let host = String::from_utf8_lossy(d).into_owned();
            TcpStream::connect((host.as_str(), target.port))
        }
    }
}

/// Обрабатывает одно соединение на стороне клиента (SOCKS5 → TLS).
///
/// После успешного CONNECT релеит байты между app-сокетом и TLS-потоком.
pub fn serve_client_connection(
    mut app: TcpStream,
    mut client: ClientTransport,
) -> Result<(), ProxyError> {
    let target = handshake(&mut app)?;

    if let Err(e) = client.connect() {
        let _ = socks5::write_reply(
            &mut app,
            socks5::REP_GENERAL_FAILURE,
            &socks5::Addr::IPv4([0, 0, 0, 0]),
            0,
        );
        return Err(ProxyError::Transport(e));
    }
    client.set_read_timeout(Some(RELAY_POLL_INTERVAL))?;

    if let Err(e) = write_connect_target(&mut client, &target) {
        let _ = socks5::write_reply(
            &mut app,
            socks5::REP_GENERAL_FAILURE,
            &socks5::Addr::IPv4([0, 0, 0, 0]),
            0,
        );
        return Err(e);
    }

    socks5::write_reply(
        &mut app,
        socks5::REP_SUCCESS,
        &socks5::Addr::IPv4([0, 0, 0, 0]),
        0,
    )?;
    relay(app, client).map_err(ProxyError::Io)
}

/// Обрабатывает одно соединение на стороне сервера (TLS → TCP-цель).
pub fn serve_server_connection(mut server: ServerTransport) -> Result<(), ProxyError> {
    let target = read_connect_target(&mut server)?;
    let tcp = connect_target(&target).map_err(ProxyError::Io)?;
    server.set_read_timeout(Some(RELAY_POLL_INTERVAL))?;
    relay(tcp, server).map_err(ProxyError::Io)
}

/// Двунаправленная передача байтов между TCP-сокетом и потоком.
///
/// Оба потока должны быть с настроенным таймаутом чтения [`RELAY_POLL_INTERVAL`]
/// (таймаут TCP выставляется здесь). Завершение одной из сторон закрывает
/// другую; обрыв соединения распознаётся как конец потока.
pub fn relay<T: Read + Write>(mut tcp: TcpStream, mut stream: T) -> io::Result<()> {
    tcp.set_read_timeout(Some(RELAY_POLL_INTERVAL))?;
    let mut buf = [0u8; 64 * 1024];

    loop {
        // tcp -> stream
        loop {
            match tcp.read(&mut buf) {
                Ok(0) => return Ok(()),
                Ok(n) => stream.write_all(&buf[..n])?,
                Err(e) => {
                    if is_retryable(&e) {
                        break;
                    }
                    if is_disconnect(&e) {
                        return Ok(());
                    }
                    return Err(e);
                }
            }
        }

        // stream -> tcp
        loop {
            match stream.read(&mut buf) {
                Ok(0) => {
                    let _ = tcp.shutdown(Shutdown::Both);
                    return Ok(());
                }
                Ok(n) => tcp.write_all(&buf[..n])?,
                Err(e) => {
                    if is_retryable(&e) {
                        break;
                    }
                    if is_disconnect(&e) {
                        let _ = tcp.shutdown(Shutdown::Both);
                        return Ok(());
                    }
                    return Err(e);
                }
            }
        }
    }
}

fn is_retryable(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

fn is_disconnect(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
    )
}
