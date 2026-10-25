//! Конфигурация клиента и сервера: парсинг TOML, валидация, адресные правила.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::fmt;
use std::net::IpAddr;
use std::sync::LazyLock;

use ipnet::IpNet;
use serde::Deserialize;

/// Ошибка парсинга/валидации конфигурации.
#[derive(Debug)]
pub enum ConfigError {
    /// Ошибка разбора TOML.
    Parse(String),
    /// Некорректный CIDR.
    InvalidCidr(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "config parse error: {e}"),
            Self::InvalidCidr(e) => write!(f, "invalid CIDR: {e}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Ошибка адресного правила.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressError {
    /// Адрес запрещён.
    Blocked,
    /// Порт ниже 1024 и не разрешён.
    LowPort,
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Blocked => write!(f, "address blocked by ruleset"),
            Self::LowPort => write!(f, "port below 1024 not allowed"),
        }
    }
}

impl std::error::Error for AddressError {}

#[derive(Deserialize, Default)]
struct RawConfig {
    #[serde(default)]
    server: RawServer,
}

#[derive(Deserialize, Default)]
struct RawServer {
    #[serde(default)]
    address_rules: RawAddressRules,
}

#[derive(Deserialize, Default)]
struct RawAddressRules {
    #[serde(default)]
    allow_ports_low: Vec<u16>,
    #[serde(default)]
    allow_cidrs: Vec<String>,
    #[serde(default)]
    deny_cidrs: Vec<String>,
}

/// Правила допустимых адресов назначения.
///
/// Порядок оценки [`AddressRules::check`]:
/// 1. hardcoded always-deny (loopback/link-local/unspecified/multicast/ULA) —
///    не переопределяется;
/// 2. `deny_cidrs` — запрещённые CIDR (переопределяют `allow_cidrs`);
/// 3. RFC1918 private (10/8, 172.16/12, 192.168/16) — default-deny,
///    переопределяется `allow_cidrs`;
/// 4. порт < 1024 — deny, кроме `allow_ports_low`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AddressRules {
    /// Низкие порты (<1024), разрешённые явно.
    pub allow_ports_low: Vec<u16>,
    /// Разрешённые CIDR (переопределяют default-deny приватных диапазонов).
    pub allow_cidrs: Vec<IpNet>,
    /// Запрещённые CIDR (переопределяют allow_cidrs).
    pub deny_cidrs: Vec<IpNet>,
}

impl AddressRules {
    /// Парсит TOML с таблицей `[server.address_rules]`.
    pub fn from_toml(s: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig = toml::from_str(s).map_err(|e| ConfigError::Parse(e.to_string()))?;
        let r = raw.server.address_rules;

        let allow_cidrs = r
            .allow_cidrs
            .iter()
            .map(|c| parse_cidr(c))
            .collect::<Result<Vec<_>, _>>()?;
        let deny_cidrs = r
            .deny_cidrs
            .iter()
            .map(|c| parse_cidr(c))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            allow_ports_low: r.allow_ports_low,
            allow_cidrs,
            deny_cidrs,
        })
    }

    /// Проверяет `ip:port` на допустимость.
    pub fn check(&self, ip: IpAddr, port: u16) -> Result<(), AddressError> {
        if HARDCODED_DENY.iter().any(|net| net.contains(&ip)) {
            return Err(AddressError::Blocked);
        }
        if self.deny_cidrs.iter().any(|net| net.contains(&ip)) {
            return Err(AddressError::Blocked);
        }
        let explicitly_allowed = self.allow_cidrs.iter().any(|net| net.contains(&ip));
        if !explicitly_allowed && PRIVATE_DENY.iter().any(|net| net.contains(&ip)) {
            return Err(AddressError::Blocked);
        }
        if port < 1024 && !self.allow_ports_low.contains(&port) {
            return Err(AddressError::LowPort);
        }
        Ok(())
    }
}

fn parse_cidr(s: &str) -> Result<IpNet, ConfigError> {
    s.parse::<IpNet>()
        .map_err(|e| ConfigError::InvalidCidr(format!("{s}: {e}")))
}

/// Always-deny: loopback, link-local, unspecified, multicast, ULA.
static HARDCODED_DENY: LazyLock<Vec<IpNet>> = LazyLock::new(|| {
    [
        "127.0.0.0/8",
        "::1/128",
        "169.254.0.0/16",
        "0.0.0.0/8",
        "224.0.0.0/4",
        "fc00::/7",
        "fe80::/10",
    ]
    .iter()
    .map(|s| s.parse().unwrap())
    .collect()
});

/// Default-deny: приватные диапазоны RFC1918.
static PRIVATE_DENY: LazyLock<Vec<IpNet>> = LazyLock::new(|| {
    ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect()
});

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn ip4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn parse_rules() {
        let rules = AddressRules::from_toml(
            r#"
            [server.address_rules]
            allow_ports_low = [80, 443]
            allow_cidrs = ["192.168.1.0/24"]
            deny_cidrs = ["10.0.0.0/8"]
            "#,
        )
        .unwrap();
        assert_eq!(rules.allow_ports_low, vec![80, 443]);
        assert_eq!(rules.allow_cidrs, vec!["192.168.1.0/24".parse().unwrap()]);
        assert_eq!(rules.deny_cidrs, vec!["10.0.0.0/8".parse().unwrap()]);
    }

    #[test]
    fn empty_config_is_default() {
        let rules = AddressRules::from_toml("").unwrap();
        assert_eq!(rules, AddressRules::default());
    }

    #[test]
    fn invalid_cidr_rejected() {
        let err = AddressRules::from_toml(
            r#"
            [server.address_rules]
            deny_cidrs = ["not-a-cidr"]
            "#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::InvalidCidr(_)));
    }

    #[test]
    fn hardcoded_deny_ranges() {
        let rules = AddressRules::default();
        for ip in [
            ip4(127, 0, 0, 1), // loopback
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            ip4(169, 254, 1, 1), // link-local
            ip4(0, 0, 0, 1),     // unspecified
            ip4(224, 0, 0, 1),   // multicast
            IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
        ] {
            assert_eq!(rules.check(ip, 8080), Err(AddressError::Blocked), "{ip}");
        }
    }

    #[test]
    fn rfc1918_denied_by_default() {
        let rules = AddressRules::default();
        assert_eq!(
            rules.check(ip4(192, 168, 1, 1), 8080),
            Err(AddressError::Blocked)
        );
        assert_eq!(
            rules.check(ip4(10, 0, 0, 1), 8080),
            Err(AddressError::Blocked)
        );
        assert_eq!(
            rules.check(ip4(172, 16, 0, 1), 8080),
            Err(AddressError::Blocked)
        );
    }

    #[test]
    fn allow_cidr_overrides_rfc1918() {
        let rules = AddressRules::from_toml(
            r#"
            [server.address_rules]
            allow_cidrs = ["192.168.1.0/24"]
            "#,
        )
        .unwrap();
        assert_eq!(rules.check(ip4(192, 168, 1, 1), 8080), Ok(()));
        // Вне allow_cidrs — всё ещё приватный.
        assert_eq!(
            rules.check(ip4(192, 168, 2, 1), 8080),
            Err(AddressError::Blocked)
        );
    }

    #[test]
    fn deny_cidr_overrides_allow_cidr() {
        let rules = AddressRules::from_toml(
            r#"
            [server.address_rules]
            allow_cidrs = ["192.168.1.0/24"]
            deny_cidrs = ["192.168.1.0/24"]
            "#,
        )
        .unwrap();
        assert_eq!(
            rules.check(ip4(192, 168, 1, 1), 8080),
            Err(AddressError::Blocked)
        );
    }

    #[test]
    fn low_port_rule() {
        let rules = AddressRules::default();
        // Публичный IP, порт 22 — отклонён.
        assert_eq!(rules.check(ip4(8, 8, 8, 8), 22), Err(AddressError::LowPort));

        let allowed = AddressRules::from_toml(
            r#"
            [server.address_rules]
            allow_ports_low = [22]
            "#,
        )
        .unwrap();
        assert_eq!(allowed.check(ip4(8, 8, 8, 8), 22), Ok(()));
    }

    #[test]
    fn public_high_port_allowed() {
        let rules = AddressRules::default();
        assert_eq!(rules.check(ip4(8, 8, 8, 8), 8443), Ok(()));
    }
}
