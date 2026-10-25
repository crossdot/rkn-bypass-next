//! Базовые типы и ошибки, общие для всех крейтов системы.
//!
//! Парсинг конфигурации здесь не выполняется — он находится в крейте `config`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::fmt;

/// Режим приёма трафика клиентом от приложений на том же устройстве.
///
/// В MVP реализован только [`Mode::Socks5`]; `tun` — Phase 2 и здесь отсутствует.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode {
    /// Локальный SOCKS5-прокси (TCP CONNECT).
    Socks5,
}

/// Принимает ли клиент трафик от других устройств.
///
/// `wireguard` (AmneziaWG) — Phase 2 / опционально, здесь отсутствует.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Entry {
    /// Клиент не является точкой входа для других устройств.
    #[default]
    None,
}

/// Профиль развёртывания точки входа — как клиент соединяется с сервером.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Profile {
    /// Profile A — Direct: открытый порт, TLS-сертификат, без nginx/Reality.
    #[default]
    Direct,
    /// Profile B — Camouflaged entry (Reality + Fallbacks). Опционален.
    Camouflaged,
}

/// Общая ошибка ядра.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    /// Некорректное значение конфигурации.
    InvalidConfig(String),
    /// Значение не поддерживается в текущей версии.
    Unsupported(String),
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(msg) => write!(f, "invalid configuration: {msg}"),
            Self::Unsupported(msg) => write!(f, "unsupported: {msg}"),
        }
    }
}

impl std::error::Error for CoreError {}

/// Псевдоним результата с ошибкой ядра.
pub type Result<T, E = CoreError> = std::result::Result<T, E>;
