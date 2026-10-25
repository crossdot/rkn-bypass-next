//! SOCKS5-режим: handshake, двунаправленный relay и логические потоки.
//!
//! Thread-per-connection (ADR-017). Использует [`socks5`] для парсинга,
//! [`protocol`] для прикладного протокола клиент↔сервер и
//! [`transport_tls`] для транспорта.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use transport_tls::{ClientTransport, ServerTransport, Transport};

/// Интервал опроса relay-цикла (таймаут чтения на обеих сторонах).
pub const RELAY_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Таймаут ожидания `ConnectAck` на клиенте.
pub const ACK_TIMEOUT: Duration = Duration::from_secs(10);

/// Таймаут установления TCP-соединения к цели на сервере.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

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
    /// Истёк таймаут ожидания `ConnectAck` от сервера.
    ConnectAckTimeout,
    /// Некорректный `ConnectAck` (битый payload).
    BadConnectAck,
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
            Self::ConnectAckTimeout => write!(f, "timed out waiting for ConnectAck"),
            Self::BadConnectAck => write!(f, "malformed ConnectAck"),
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

/// Отправляет `ConnectAck` по прикладному протоколу (сервер → клиент).
///
/// Payload — один байт REP-кода: `0x00` = успех, иначе код ошибки.
pub fn write_connect_ack<W: Write>(writer: &mut W, rep_code: u8) -> Result<(), ProxyError> {
    protocol::write_message(
        writer,
        &protocol::Message::new(protocol::MessageKind::ConnectAck, vec![rep_code]),
    )?;
    Ok(())
}

/// Читает `ConnectAck` и возвращает REP-код (`0x00` = успех).
///
/// Отличает таймаут чтения ([`ProxyError::ConnectAckTimeout`]) от битого
/// payload ([`ProxyError::BadConnectAck`]).
pub fn read_connect_ack<R: Read>(reader: &mut R) -> Result<u8, ProxyError> {
    let mut header = [0u8; protocol::HEADER_LEN];
    if let Err(e) = reader.read_exact(&mut header) {
        return Err(if is_retryable(&e) {
            ProxyError::ConnectAckTimeout
        } else {
            ProxyError::Io(e)
        });
    }

    if header[0] != protocol::VERSION {
        return Err(ProxyError::Protocol(
            protocol::ProtocolError::UnsupportedVersion {
                got: header[0],
                supported: protocol::VERSION,
            },
        ));
    }

    let kind = protocol::MessageKind::from_u8(header[1])?;
    if kind != protocol::MessageKind::ConnectAck {
        return Err(ProxyError::UnexpectedMessage(kind));
    }

    let len = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
    if len != 1 {
        return Err(ProxyError::BadConnectAck);
    }

    let mut payload = [0u8; 1];
    reader.read_exact(&mut payload).map_err(ProxyError::Io)?;
    Ok(payload[0])
}

/// Сопоставляет ошибку TCP-connect с SOCKS5 REP-кодом.
fn map_connect_error(e: &io::Error) -> u8 {
    match e.kind() {
        io::ErrorKind::ConnectionRefused => socks5::REP_CONNECTION_REFUSED,
        io::ErrorKind::NetworkUnreachable => socks5::REP_NETWORK_UNREACHABLE,
        io::ErrorKind::HostUnreachable | io::ErrorKind::TimedOut => socks5::REP_HOST_UNREACHABLE,
        _ => socks5::REP_GENERAL_FAILURE,
    }
}

/// Разрешает цель в список IP-адресов (для домена — все адреса из DNS).
fn resolve_target_ips(target: &socks5::Target) -> Result<Vec<IpAddr>, ProxyError> {
    match &target.addr {
        socks5::Addr::IPv4(b) => Ok(vec![IpAddr::V4(Ipv4Addr::from(*b))]),
        socks5::Addr::IPv6(b) => Ok(vec![IpAddr::V6(Ipv6Addr::from(*b))]),
        socks5::Addr::Domain(d) => {
            let host = String::from_utf8_lossy(d).into_owned();
            let ips = (host.as_str(), 0)
                .to_socket_addrs()
                .map_err(ProxyError::Io)?
                .map(|a| a.ip())
                .collect::<Vec<_>>();
            if ips.is_empty() {
                return Err(ProxyError::Io(io::Error::new(
                    io::ErrorKind::HostUnreachable,
                    "no address resolved",
                )));
            }
            Ok(ips)
        }
    }
}

/// Подключается к `ip:port` с таймаутом.
fn connect_ip(ip: IpAddr, port: u16, timeout: Duration) -> io::Result<TcpStream> {
    TcpStream::connect_timeout(&SocketAddr::new(ip, port), timeout)
}

/// Обрабатывает одно соединение на стороне клиента (SOCKS5 → TLS).
///
/// После успешного CONNECT релеит байты между app-сокетом и TLS-потоком.
pub fn serve_client_connection(
    mut app: TcpStream,
    mut client: ClientTransport,
    ack_timeout: Duration,
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

    client.set_read_timeout(Some(ack_timeout))?;

    if let Err(e) = write_connect_target(&mut client, &target) {
        let _ = socks5::write_reply(
            &mut app,
            socks5::REP_GENERAL_FAILURE,
            &socks5::Addr::IPv4([0, 0, 0, 0]),
            0,
        );
        return Err(e);
    }

    // Ждём подтверждение соединения с целью от сервера.
    let rep = match read_connect_ack(&mut client) {
        Ok(rep) => rep,
        Err(ProxyError::ConnectAckTimeout) => {
            let _ = socks5::write_reply(
                &mut app,
                socks5::REP_HOST_UNREACHABLE,
                &socks5::Addr::IPv4([0, 0, 0, 0]),
                0,
            );
            return Ok(());
        }
        Err(_) => {
            let _ = socks5::write_reply(
                &mut app,
                socks5::REP_GENERAL_FAILURE,
                &socks5::Addr::IPv4([0, 0, 0, 0]),
                0,
            );
            return Ok(());
        }
    };

    if rep != socks5::REP_SUCCESS {
        let _ = socks5::write_reply(&mut app, rep, &socks5::Addr::IPv4([0, 0, 0, 0]), 0);
        return Ok(());
    }

    client.set_read_timeout(Some(RELAY_POLL_INTERVAL))?;
    socks5::write_reply(
        &mut app,
        socks5::REP_SUCCESS,
        &socks5::Addr::IPv4([0, 0, 0, 0]),
        0,
    )?;
    relay(app, client).map_err(ProxyError::Io)
}

/// Обрабатывает одно соединение на стороне сервера (TLS → TCP-цель).
pub fn serve_server_connection(
    mut server: ServerTransport,
    connect_timeout: Duration,
    rules: &config::AddressRules,
) -> Result<(), ProxyError> {
    let target = read_connect_target(&mut server)?;
    let ips = resolve_target_ips(&target)?;

    // Проверка адресных правил (SSRF) до подключения.
    for ip in &ips {
        if rules.check(*ip, target.port).is_err() {
            let _ = write_connect_ack(&mut server, socks5::REP_CONNECTION_NOT_ALLOWED);
            return Ok(());
        }
    }

    let mut tcp = None;
    let mut last_err = None;
    for ip in &ips {
        match connect_ip(*ip, target.port, connect_timeout) {
            Ok(sock) => {
                tcp = Some(sock);
                break;
            }
            Err(e) => last_err = Some(e),
        }
    }
    let tcp = match tcp {
        Some(sock) => sock,
        None => {
            let rep = last_err
                .as_ref()
                .map(map_connect_error)
                .unwrap_or(socks5::REP_GENERAL_FAILURE);
            let _ = write_connect_ack(&mut server, rep);
            return Ok(());
        }
    };

    write_connect_ack(&mut server, socks5::REP_SUCCESS)?;
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
