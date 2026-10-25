//! SOCKS5 wire-протокол: парсинг приветствия, методов, запросов и ответов.
//!
//! Чистый парсер без I/O-оркестрации: работает поверх `std::io::Read`/`Write`.
//! Не знает о транспорте и профиле.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::fmt;
use std::io::{Read, Write};

/// Версия протокола SOCKS5.
pub const VERSION: u8 = 0x05;

/// Максимальная длина доменного имени (1 байт длины в wire-формате).
pub const MAX_DOMAIN_LEN: usize = 255;

/// Метод аутентификации: без аутентификации.
pub const AUTH_NONE: u8 = 0x00;
/// Отказ: нет приемлемых методов аутентификации.
pub const AUTH_NO_ACCEPTABLE: u8 = 0xFF;

/// Код ответа: успех.
pub const REP_SUCCESS: u8 = 0x00;
/// Код ответа: общий сбой.
pub const REP_GENERAL_FAILURE: u8 = 0x01;
/// Код ответа: сеть недоступна.
pub const REP_NETWORK_UNREACHABLE: u8 = 0x03;
/// Код ответа: узел недоступен.
pub const REP_HOST_UNREACHABLE: u8 = 0x04;
/// Код ответа: соединение отклонено.
pub const REP_CONNECTION_REFUSED: u8 = 0x05;
/// Код ответа: команда не поддерживается.
pub const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
/// Код ответа: тип адреса не поддерживается.
pub const REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

/// Тип адреса: IPv4.
pub const ATYP_IPV4: u8 = 0x01;
/// Тип адреса: доменное имя.
pub const ATYP_DOMAIN: u8 = 0x03;
/// Тип адреса: IPv6.
pub const ATYP_IPV6: u8 = 0x04;

/// Команда запроса.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Command {
    /// CONNECT — установить TCP-соединение.
    Connect,
    /// BIND — не поддерживается в MVP.
    Bind,
    /// UDP ASSOCIATE — не поддерживается в MVP.
    UdpAssociate,
}

impl Command {
    /// Преобразует байт команды в [`Command`].
    ///
    /// Неизвестный код → [`Socks5Error::UnsupportedCommand`].
    pub fn from_u8(value: u8) -> Result<Self, Socks5Error> {
        match value {
            0x01 => Ok(Self::Connect),
            0x02 => Ok(Self::Bind),
            0x03 => Ok(Self::UdpAssociate),
            other => Err(Socks5Error::UnsupportedCommand(other)),
        }
    }

    /// Обратное преобразование в байт wire-формата.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Connect => 0x01,
            Self::Bind => 0x02,
            Self::UdpAssociate => 0x03,
        }
    }
}

/// Адрес назначения (без порта).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Addr {
    /// IPv4-адрес.
    IPv4([u8; 4]),
    /// Доменное имя (сырые байты).
    Domain(Vec<u8>),
    /// IPv6-адрес.
    IPv6([u8; 16]),
}

/// Адрес назначения с портом.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target {
    /// Адрес.
    pub addr: Addr,
    /// Порт.
    pub port: u16,
}

impl Target {
    /// Кодирует цель в wire-формат: ATYP + адрес + порт (big-endian).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 16 + 2);
        self.encode_into(&mut out);
        out
    }

    /// Дописывает цель в `out`.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        match &self.addr {
            Addr::IPv4(b) => {
                out.push(ATYP_IPV4);
                out.extend_from_slice(b);
            }
            Addr::Domain(d) => {
                out.push(ATYP_DOMAIN);
                out.push(d.len() as u8);
                out.extend_from_slice(d);
            }
            Addr::IPv6(b) => {
                out.push(ATYP_IPV6);
                out.extend_from_slice(b);
            }
        }
        out.extend_from_slice(&self.port.to_be_bytes());
    }

    /// Декодирует цель из `buf`. Возвращает цель и число потреблённых байт.
    ///
    /// Не читает за границы буфера; обрезанная цель → [`Socks5Error::Truncated`].
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), Socks5Error> {
        let atyp = *buf.first().ok_or(Socks5Error::Truncated)?;
        let (addr, consumed) = match atyp {
            ATYP_IPV4 => {
                let b = buf.get(1..5).ok_or(Socks5Error::Truncated)?;
                let mut a = [0u8; 4];
                a.copy_from_slice(b);
                (Addr::IPv4(a), 5)
            }
            ATYP_DOMAIN => {
                let dlen = *buf.get(1).ok_or(Socks5Error::Truncated)? as usize;
                if dlen > MAX_DOMAIN_LEN {
                    return Err(Socks5Error::DomainTooLong {
                        len: dlen,
                        max: MAX_DOMAIN_LEN,
                    });
                }
                let d = buf.get(2..2 + dlen).ok_or(Socks5Error::Truncated)?;
                (Addr::Domain(d.to_vec()), 2 + dlen)
            }
            ATYP_IPV6 => {
                let b = buf.get(1..17).ok_or(Socks5Error::Truncated)?;
                let mut a = [0u8; 16];
                a.copy_from_slice(b);
                (Addr::IPv6(a), 17)
            }
            other => return Err(Socks5Error::AddressTypeNotSupported(other)),
        };
        let port = buf
            .get(consumed..consumed + 2)
            .ok_or(Socks5Error::Truncated)?;
        let port = u16::from_be_bytes([port[0], port[1]]);
        Ok((Self { addr, port }, consumed + 2))
    }
}

/// Приветствие от клиента: VER + NMETHODS + METHODS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Greeting {
    /// Версия.
    pub version: u8,
    /// Предлагаемые методы аутентификации.
    pub methods: Vec<u8>,
}

/// Запрос от клиента: VER + CMD + RSV + ATYP + DST.ADDR + DST.PORT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Версия.
    pub version: u8,
    /// Команда.
    pub command: Command,
    /// Цель.
    pub target: Target,
}

/// Читает приветствие.
pub fn read_greeting<R: Read>(reader: &mut R) -> Result<Greeting, Socks5Error> {
    let mut head = [0u8; 2];
    reader.read_exact(&mut head).map_err(io_err)?;
    let version = head[0];
    if version != VERSION {
        return Err(Socks5Error::UnsupportedVersion(version));
    }
    let nmethods = head[1] as usize;
    let mut methods = vec![0u8; nmethods];
    reader.read_exact(&mut methods).map_err(io_err)?;
    Ok(Greeting { version, methods })
}

/// Записывает выбор метода аутентификации.
pub fn write_method_selection<W: Write>(writer: &mut W, method: u8) -> Result<(), Socks5Error> {
    writer.write_all(&[VERSION, method]).map_err(io_err)
}

/// Читает запрос (CONNECT/BIND/UDP ASSOCIATE).
pub fn read_request<R: Read>(reader: &mut R) -> Result<Request, Socks5Error> {
    let mut head = [0u8; 4]; // VER CMD RSV ATYP
    reader.read_exact(&mut head).map_err(io_err)?;
    let version = head[0];
    if version != VERSION {
        return Err(Socks5Error::UnsupportedVersion(version));
    }
    let command = Command::from_u8(head[1])?;
    // head[2] — RSV, игнорируется.
    let addr = read_addr(reader, head[3])?;

    let mut port_bytes = [0u8; 2];
    reader.read_exact(&mut port_bytes).map_err(io_err)?;
    let port = u16::from_be_bytes(port_bytes);

    Ok(Request {
        version,
        command,
        target: Target { addr, port },
    })
}

/// Записывает ответ: VER + REP + RSV + ATYP + BND.ADDR + BND.PORT.
pub fn write_reply<W: Write>(
    writer: &mut W,
    reply_code: u8,
    bind_addr: &Addr,
    bind_port: u16,
) -> Result<(), Socks5Error> {
    writer
        .write_all(&[VERSION, reply_code, 0x00])
        .map_err(io_err)?;
    let bind = Target {
        addr: bind_addr.clone(),
        port: bind_port,
    };
    writer.write_all(&bind.encode()).map_err(io_err)
}

fn read_addr<R: Read>(reader: &mut R, atyp: u8) -> Result<Addr, Socks5Error> {
    match atyp {
        ATYP_IPV4 => {
            let mut b = [0u8; 4];
            reader.read_exact(&mut b).map_err(io_err)?;
            Ok(Addr::IPv4(b))
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            reader.read_exact(&mut len).map_err(io_err)?;
            let dlen = len[0] as usize;
            if dlen > MAX_DOMAIN_LEN {
                return Err(Socks5Error::DomainTooLong {
                    len: dlen,
                    max: MAX_DOMAIN_LEN,
                });
            }
            let mut d = vec![0u8; dlen];
            reader.read_exact(&mut d).map_err(io_err)?;
            Ok(Addr::Domain(d))
        }
        ATYP_IPV6 => {
            let mut b = [0u8; 16];
            reader.read_exact(&mut b).map_err(io_err)?;
            Ok(Addr::IPv6(b))
        }
        other => Err(Socks5Error::AddressTypeNotSupported(other)),
    }
}

/// Ошибка протокола SOCKS5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Socks5Error {
    /// Неподдерживаемая версия протокола.
    UnsupportedVersion(u8),
    /// Неизвестная команда.
    UnsupportedCommand(u8),
    /// Неподдерживаемый тип адреса (ATYP).
    AddressTypeNotSupported(u8),
    /// Доменное имя превышает [`MAX_DOMAIN_LEN`].
    DomainTooLong {
        /// Фактическая длина.
        len: usize,
        /// Максимально допустимая длина.
        max: usize,
    },
    /// Сообщение обрезано.
    Truncated,
    /// Ошибка ввода-вывода нижележащего потока.
    Io(String),
}

fn io_err(e: std::io::Error) -> Socks5Error {
    Socks5Error::Io(e.to_string())
}

impl fmt::Display for Socks5Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(v) => write!(f, "unsupported SOCKS5 version {v}"),
            Self::UnsupportedCommand(c) => write!(f, "unsupported SOCKS5 command 0x{c:02x}"),
            Self::AddressTypeNotSupported(a) => write!(f, "unsupported address type 0x{a:02x}"),
            Self::DomainTooLong { len, max } => {
                write!(f, "domain too long: {len} bytes (max {max})")
            }
            Self::Truncated => write!(f, "message truncated"),
            Self::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for Socks5Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greeting_no_auth() {
        let mut data: &[u8] = &[0x05, 0x02, 0x00, 0x02];
        let g = read_greeting(&mut data).unwrap();
        assert_eq!(g.version, VERSION);
        assert_eq!(g.methods, vec![0x00, 0x02]);
    }

    #[test]
    fn greeting_bad_version() {
        let mut data: &[u8] = &[0x04, 0x01, 0x00];
        assert_eq!(
            read_greeting(&mut data).unwrap_err(),
            Socks5Error::UnsupportedVersion(0x04)
        );
    }

    #[test]
    fn request_connect_ipv4() {
        let mut data: &[u8] = &[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50];
        let r = read_request(&mut data).unwrap();
        assert_eq!(r.command, Command::Connect);
        assert_eq!(
            r.target,
            Target {
                addr: Addr::IPv4([127, 0, 0, 1]),
                port: 80
            }
        );
    }

    #[test]
    fn request_bind_and_udp_parsed() {
        let mut udp: &[u8] = &[0x05, 0x03, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x01];
        assert_eq!(
            read_request(&mut udp).unwrap().command,
            Command::UdpAssociate
        );

        let mut bind: &[u8] = &[0x05, 0x02, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x01];
        assert_eq!(read_request(&mut bind).unwrap().command, Command::Bind);
    }

    #[test]
    fn request_unknown_command() {
        let mut data: &[u8] = &[0x05, 0x09, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x01];
        assert_eq!(
            read_request(&mut data).unwrap_err(),
            Socks5Error::UnsupportedCommand(0x09)
        );
    }

    #[test]
    fn target_roundtrip() {
        for target in [
            Target {
                addr: Addr::IPv4([1, 2, 3, 4]),
                port: 443,
            },
            Target {
                addr: Addr::Domain(b"example.com".to_vec()),
                port: 80,
            },
            Target {
                addr: Addr::IPv6([0; 16]),
                port: 22,
            },
        ] {
            let enc = target.encode();
            let (dec, consumed) = Target::decode(&enc).unwrap();
            assert_eq!(dec, target);
            assert_eq!(consumed, enc.len());
        }
    }

    #[test]
    fn target_truncated() {
        // ATYP=domain, dlen=100, но в буфере только 3 байта.
        let buf = [ATYP_DOMAIN, 100, 1, 2, 3];
        assert_eq!(Target::decode(&buf).unwrap_err(), Socks5Error::Truncated);
    }

    #[test]
    fn target_address_type_not_supported() {
        let buf = [0x02, 1, 2, 3, 4, 0x00, 0x01];
        assert_eq!(
            Target::decode(&buf).unwrap_err(),
            Socks5Error::AddressTypeNotSupported(0x02)
        );
    }
}
