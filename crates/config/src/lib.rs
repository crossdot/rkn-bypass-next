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
    /// Некорректная per-client конфигурация.
    InvalidClient(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "config parse error: {e}"),
            Self::InvalidCidr(e) => write!(f, "invalid CIDR: {e}"),
            Self::InvalidClient(e) => write!(f, "invalid client: {e}"),
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
    #[serde(default)]
    clients: Vec<RawClient>,
}

#[derive(Deserialize)]
struct RawClient {
    client_id: String,
    key_material: String,
    #[serde(default)]
    revoked: bool,
    max_sessions: Option<u32>,
}

fn default_allow_ports_low() -> Vec<u16> {
    vec![80, 443]
}

#[derive(Deserialize)]
struct RawAddressRules {
    #[serde(default = "default_allow_ports_low")]
    allow_ports_low: Vec<u16>,
    #[serde(default)]
    allow_cidrs: Vec<String>,
    #[serde(default)]
    deny_cidrs: Vec<String>,
}

impl Default for RawAddressRules {
    fn default() -> Self {
        Self {
            allow_ports_low: default_allow_ports_low(),
            allow_cidrs: Vec::new(),
            deny_cidrs: Vec::new(),
        }
    }
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressRules {
    /// Низкие порты (<1024), разрешённые явно (по умолчанию 80, 443).
    pub allow_ports_low: Vec<u16>,
    /// Разрешённые CIDR (переопределяют default-deny приватных диапазонов).
    pub allow_cidrs: Vec<IpNet>,
    /// Запрещённые CIDR (переопределяют allow_cidrs).
    pub deny_cidrs: Vec<IpNet>,
}

impl Default for AddressRules {
    fn default() -> Self {
        Self {
            allow_ports_low: default_allow_ports_low(),
            allow_cidrs: Vec::new(),
            deny_cidrs: Vec::new(),
        }
    }
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

/// Один клиент.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientEntry {
    /// Идентификатор клиента (не секрет).
    pub client_id: String,
    /// SHA-256 fingerprint DER-сертификата (hex).
    pub fingerprint: String,
    /// Отозван ли клиент.
    pub revoked: bool,
    /// Максимум одновременных сессий (`None` = без ограничения).
    pub max_sessions: Option<u32>,
}

/// Реестр клиентов.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientRegistry {
    entries: Vec<ClientEntry>,
}

impl ClientRegistry {
    /// Парсит `[[server.clients]]` из TOML, загружает сертификаты,
    /// вычисляет fingerprint и валидирует (непустой `client_id`,
    /// уникальность `client_id` и fingerprint, читаемость `key_material`).
    pub fn from_toml(s: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig = toml::from_str(s).map_err(|e| ConfigError::Parse(e.to_string()))?;
        let mut entries = Vec::new();
        let mut seen_ids = std::collections::HashSet::new();
        let mut seen_fps = std::collections::HashSet::new();

        for c in raw.server.clients {
            if c.client_id.trim().is_empty() {
                return Err(ConfigError::InvalidClient("empty client_id".into()));
            }
            if !seen_ids.insert(c.client_id.clone()) {
                return Err(ConfigError::InvalidClient(format!(
                    "duplicate client_id: {}",
                    c.client_id
                )));
            }
            let der = load_cert_der(&c.key_material)?;
            let fp = crypto::fingerprint(&der);
            if !seen_fps.insert(fp.clone()) {
                return Err(ConfigError::InvalidClient(format!(
                    "duplicate fingerprint: {fp}"
                )));
            }
            entries.push(ClientEntry {
                client_id: c.client_id,
                fingerprint: fp,
                revoked: c.revoked,
                max_sessions: c.max_sessions,
            });
        }
        Ok(Self { entries })
    }

    /// Ищет клиента по fingerprint сертификата.
    pub fn find_by_fingerprint(&self, fingerprint: &str) -> Option<&ClientEntry> {
        self.entries.iter().find(|e| e.fingerprint == fingerprint)
    }

    /// Итератор по клиентам.
    pub fn iter(&self) -> impl Iterator<Item = &ClientEntry> {
        self.entries.iter()
    }

    /// Количество клиентов.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Пуст ли реестр.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Загружает DER-сертификат из `key_material` (путь к файлу или inline PEM).
fn load_cert_der(key_material: &str) -> Result<Vec<u8>, ConfigError> {
    let pem = if key_material.trim_start().starts_with("-----BEGIN") {
        key_material.to_string()
    } else {
        std::fs::read_to_string(key_material).map_err(|e| {
            ConfigError::InvalidClient(format!("cannot read key_material {key_material}: {e}"))
        })?
    };
    let der = rustls_pemfile::certs(&mut pem.as_bytes())
        .next()
        .ok_or_else(|| ConfigError::InvalidClient("no certificate in key_material".into()))?
        .map_err(|e| ConfigError::InvalidClient(format!("bad key_material: {e}")))?;
    Ok(der.as_ref().to_vec())
}

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

    #[test]
    fn parse_clients() {
        let (ca_cert, ca_key) = crypto::generate_ca().unwrap();
        let client = crypto::generate_client_cert("alice", &ca_cert, &ca_key).unwrap();
        let path = std::env::temp_dir().join(format!("netcore-test-{}.crt", std::process::id()));
        std::fs::write(&path, &client.cert_pem).unwrap();

        let toml = format!(
            "[[server.clients]]\nclient_id = \"alice\"\nkey_material = \"{}\"\nmax_sessions = 5\n",
            path.display()
        );
        let reg = ClientRegistry::from_toml(&toml).unwrap();
        assert_eq!(reg.len(), 1);
        let e = reg.find_by_fingerprint(&client.fingerprint).unwrap();
        assert_eq!(e.client_id, "alice");
        assert_eq!(e.max_sessions, Some(5));
        assert!(!e.revoked);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn clients_validation() {
        // Пустой client_id — отказ до чтения key_material.
        assert!(ClientRegistry::from_toml(
            "[[server.clients]]\nclient_id = \"\"\nkey_material = \"missing.crt\""
        )
        .is_err());

        // Дубликат client_id — отказ.
        let (ca_cert, ca_key) = crypto::generate_ca().unwrap();
        let c1 = crypto::generate_client_cert("dup", &ca_cert, &ca_key).unwrap();
        let c2 = crypto::generate_client_cert("dup", &ca_cert, &ca_key).unwrap();
        let toml = format!(
            "[[server.clients]]\nclient_id = \"dup\"\nkey_material = '''{}'''\n\
             [[server.clients]]\nclient_id = \"dup\"\nkey_material = '''{}'''\n",
            c1.cert_pem, c2.cert_pem
        );
        assert!(ClientRegistry::from_toml(&toml).is_err());
    }

    #[test]
    fn default_allows_http_https() {
        let rules = AddressRules::default();
        assert_eq!(rules.check(ip4(8, 8, 8, 8), 80), Ok(()));
        assert_eq!(rules.check(ip4(8, 8, 8, 8), 443), Ok(()));
    }

    #[test]
    fn partial_toml_keeps_http_https_defaults() {
        let rules = AddressRules::from_toml(
            r#"
            [server.address_rules]
            deny_cidrs = ["10.0.0.0/8"]
            "#,
        )
        .unwrap();
        // allow_ports_low не задан — по умолчанию [80, 443].
        assert_eq!(rules.check(ip4(8, 8, 8, 8), 80), Ok(()));
        assert_eq!(rules.check(ip4(8, 8, 8, 8), 443), Ok(()));
    }
}
