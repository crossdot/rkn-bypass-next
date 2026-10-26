//! SOCKS5-режим: handshake, двунаправленный relay и логические потоки.
//!
//! Асинхронный (tokio, task-per-connection). Использует [`socks5`] для парсинга,
//! [`protocol`] для прикладного протокола клиент↔сервер и generic [`Transport`]
//! для транспорта (расцеплен от `transport-tls`).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use transport_api::{Transport, TransportError};

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
    Transport(TransportError),
    /// Ошибка ввода-вывода.
    Io(std::io::Error),
    /// Команда распознана, но не поддерживается (BIND/UDP ASSOCIATE).
    CommandNotSupported(socks5::Command),
    /// Нет приемлемого метода аутентификации.
    NoAcceptableMethod,
    /// Прикладное сообщение имеет неожиданный тип (ожидался `Connect`).
    UnexpectedMessage(protocol::MessageKind),
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

impl From<TransportError> for ProxyError {
    fn from(e: TransportError) -> Self {
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
pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
) -> Result<socks5::Target, ProxyError> {
    let greeting = socks5::read_greeting(stream).await?;
    if greeting.methods.contains(&socks5::AUTH_NONE) {
        socks5::write_method_selection(stream, socks5::AUTH_NONE).await?;
    } else {
        socks5::write_method_selection(stream, socks5::AUTH_NO_ACCEPTABLE).await?;
        return Err(ProxyError::NoAcceptableMethod);
    }

    let request = socks5::read_request(stream).await?;
    if request.command != socks5::Command::Connect {
        socks5::write_reply(
            stream,
            socks5::REP_COMMAND_NOT_SUPPORTED,
            &socks5::Addr::IPv4([0, 0, 0, 0]),
            0,
        )
        .await?;
        return Err(ProxyError::CommandNotSupported(request.command));
    }
    Ok(request.target)
}

/// Отправляет цель CONNECT по прикладному протоколу (клиент → сервер).
pub async fn write_connect_target<T: Transport + ?Sized>(
    transport: &mut T,
    target: &socks5::Target,
) -> Result<(), ProxyError> {
    protocol::write_message(
        transport,
        &protocol::Message::new(protocol::MessageKind::Connect, target.encode()),
    )
    .await?;
    Ok(())
}

/// Читает цель CONNECT из прикладного протокола (на стороне сервера).
pub async fn read_connect_target<T: Transport + ?Sized>(
    transport: &mut T,
) -> Result<socks5::Target, ProxyError> {
    let message = protocol::read_message(transport).await?;
    if message.kind != protocol::MessageKind::Connect {
        return Err(ProxyError::UnexpectedMessage(message.kind));
    }
    let (target, _) = socks5::Target::decode(&message.payload)?;
    Ok(target)
}

/// Отправляет `ConnectAck` по прикладному протоколу (сервер → клиент).
///
/// Payload — один байт REP-кода: `0x00` = успех, иначе код ошибки.
pub async fn write_connect_ack<T: Transport + ?Sized>(
    transport: &mut T,
    rep_code: u8,
) -> Result<(), ProxyError> {
    protocol::write_message(
        transport,
        &protocol::Message::new(protocol::MessageKind::ConnectAck, vec![rep_code]),
    )
    .await?;
    Ok(())
}

/// Читает `ConnectAck` и возвращает REP-код (`0x00` = успех).
///
/// Битый payload (неверный kind или длина) → [`ProxyError`]. Таймаут задаётся
/// вызывающей стороной через `tokio::time::timeout`.
pub async fn read_connect_ack<T: Transport + ?Sized>(transport: &mut T) -> Result<u8, ProxyError> {
    let message = protocol::read_message(transport).await?;
    if message.kind != protocol::MessageKind::ConnectAck {
        return Err(ProxyError::UnexpectedMessage(message.kind));
    }
    if message.payload.len() != 1 {
        return Err(ProxyError::BadConnectAck);
    }
    Ok(message.payload[0])
}

/// Ошибка TCP-connect к цели: таймаут или I/O.
enum ConnectError {
    Timeout,
    Io(io::Error),
}

/// Сопоставляет ошибку TCP-connect с SOCKS5 REP-кодом (ADR-020).
fn map_connect_error(e: &ConnectError) -> u8 {
    match e {
        // tokio::time::timeout → Elapsed → 0x04, как TimedOut в sync (ADR-020).
        ConnectError::Timeout => socks5::REP_HOST_UNREACHABLE,
        ConnectError::Io(io) => match io.kind() {
            io::ErrorKind::ConnectionRefused => socks5::REP_CONNECTION_REFUSED,
            io::ErrorKind::NetworkUnreachable => socks5::REP_NETWORK_UNREACHABLE,
            io::ErrorKind::HostUnreachable | io::ErrorKind::TimedOut => {
                socks5::REP_HOST_UNREACHABLE
            }
            _ => socks5::REP_GENERAL_FAILURE,
        },
    }
}

/// Разрешает цель в список IP-адресов (для домена — все адреса из DNS).
async fn resolve_target_ips(target: &socks5::Target) -> Result<Vec<IpAddr>, ProxyError> {
    match &target.addr {
        socks5::Addr::IPv4(b) => Ok(vec![IpAddr::V4(Ipv4Addr::from(*b))]),
        socks5::Addr::IPv6(b) => Ok(vec![IpAddr::V6(Ipv6Addr::from(*b))]),
        socks5::Addr::Domain(d) => {
            let host = String::from_utf8_lossy(d).into_owned();
            let ips: Vec<IpAddr> = tokio::net::lookup_host((host.as_str(), target.port))
                .await
                .map_err(ProxyError::Io)?
                .map(|a| a.ip())
                .collect();
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
async fn connect_ip(ip: IpAddr, port: u16, timeout: Duration) -> Result<TcpStream, ConnectError> {
    match tokio::time::timeout(timeout, TcpStream::connect(SocketAddr::new(ip, port))).await {
        Ok(Ok(sock)) => Ok(sock),
        Ok(Err(e)) => Err(ConnectError::Io(e)),
        Err(_) => Err(ConnectError::Timeout),
    }
}

/// Обрабатывает одно соединение на стороне клиента (SOCKS5 → транспорт).
///
/// После успешного CONNECT релеит байты между app-сокетом и транспортом.
pub async fn serve_client_connection<T: Transport>(
    mut app: TcpStream,
    mut client: T,
    ack_timeout: Duration,
) -> Result<(), ProxyError> {
    let target = handshake(&mut app).await?;

    if let Err(e) = client.connect().await {
        let _ = socks5::write_reply(
            &mut app,
            socks5::REP_GENERAL_FAILURE,
            &socks5::Addr::IPv4([0, 0, 0, 0]),
            0,
        )
        .await;
        return Err(ProxyError::Transport(e));
    }

    if let Err(e) = write_connect_target(&mut client, &target).await {
        let _ = socks5::write_reply(
            &mut app,
            socks5::REP_GENERAL_FAILURE,
            &socks5::Addr::IPv4([0, 0, 0, 0]),
            0,
        )
        .await;
        return Err(e);
    }

    // Ждём ConnectAck с таймаутом. Elapsed → 0x04 (host unreachable, ADR-020).
    let rep = match tokio::time::timeout(ack_timeout, read_connect_ack(&mut client)).await {
        Ok(Ok(rep)) => rep,
        Ok(Err(_)) => {
            let _ = socks5::write_reply(
                &mut app,
                socks5::REP_GENERAL_FAILURE,
                &socks5::Addr::IPv4([0, 0, 0, 0]),
                0,
            )
            .await;
            return Ok(());
        }
        Err(_) => {
            let _ = socks5::write_reply(
                &mut app,
                socks5::REP_HOST_UNREACHABLE,
                &socks5::Addr::IPv4([0, 0, 0, 0]),
                0,
            )
            .await;
            return Ok(());
        }
    };

    if rep != socks5::REP_SUCCESS {
        let _ = socks5::write_reply(&mut app, rep, &socks5::Addr::IPv4([0, 0, 0, 0]), 0).await;
        return Ok(());
    }

    socks5::write_reply(
        &mut app,
        socks5::REP_SUCCESS,
        &socks5::Addr::IPv4([0, 0, 0, 0]),
        0,
    )
    .await?;
    relay(app, client).await
}

/// Обрабатывает одно соединение на стороне сервера (транспорт → TCP-цель).
pub async fn serve_server_connection<T: Transport>(
    mut server: T,
    connect_timeout: Duration,
    rules: &config::AddressRules,
) -> Result<(), ProxyError> {
    let target = read_connect_target(&mut server).await?;
    let ips = resolve_target_ips(&target).await?;

    // Проверка адресных правил (SSRF) до подключения.
    for ip in &ips {
        if rules.check(*ip, target.port).is_err() {
            let _ = write_connect_ack(&mut server, socks5::REP_CONNECTION_NOT_ALLOWED).await;
            return Ok(());
        }
    }

    let mut tcp = None;
    let mut last_err = None;
    for ip in &ips {
        match connect_ip(*ip, target.port, connect_timeout).await {
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
            let _ = write_connect_ack(&mut server, rep).await;
            return Ok(());
        }
    };

    write_connect_ack(&mut server, socks5::REP_SUCCESS).await?;
    relay(tcp, server).await
}

/// Двунаправленная передача байтов между TCP-сокетом и транспортом.
///
/// Полинг обеих сторон через `tokio::time::timeout` ([`RELAY_POLL_INTERVAL`]).
/// Завершение одной из сторон закрывает другую.
pub async fn relay<T: Transport>(mut tcp: TcpStream, mut transport: T) -> Result<(), ProxyError> {
    let mut buf = [0u8; 64 * 1024];

    loop {
        // tcp -> transport
        match tokio::time::timeout(RELAY_POLL_INTERVAL, tcp.read(&mut buf)).await {
            Ok(Ok(0)) => return Ok(()),
            Ok(Ok(n)) => {
                transport.send(&buf[..n]).await?;
            }
            Ok(Err(_)) => return Ok(()),
            Err(_) => {}
        }

        // transport -> tcp
        match tokio::time::timeout(RELAY_POLL_INTERVAL, transport.recv(&mut buf)).await {
            Ok(Ok(0)) => {
                let _ = tcp.shutdown().await;
                return Ok(());
            }
            Ok(Ok(n)) => tcp.write_all(&buf[..n]).await?,
            Ok(Err(_)) => {
                let _ = tcp.shutdown().await;
                return Ok(());
            }
            Err(_) => {}
        }
    }
}
