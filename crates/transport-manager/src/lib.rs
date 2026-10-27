//! Политика выбора транспорта (P5.3): детерминированная, без ML и эвристик.
//!
//! Модель: у каждого транспорта есть состояние `Available(TTL)` /
//! `Unavailable(backoff)`. Выбор идёт по фиксированному порядку
//! [`config::TransportPolicy::order`]; первый доступный побеждает.
//! Задержка пробы **только логируется** и никогда не участвует в решении,
//! поэтому «скачок задержки» не может вызвать переключение.
//!
//! Проверка доступности — `connect → mTLS → Ping/Pong` (1 байт в обе стороны).
//! Handshake недостаточно: у QUIC `connect` не открывает bi-stream, а отозванный
//! клиент должен отсекаться до пробы (сервер проверяет mTLS и сессию раньше
//! прикладного слоя).
//!
//! Если все кандидаты недоступны, возвращается `preferred` с причиной
//! `all_failed_default` — не «последний успешный» (иначе осцилляция при флапе).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use config::{TransportKind, TransportPolicy, TransportStrategy};
use tokio::sync::Notify;
use transport_any::AnyClientTransport;
use transport_api::{Transport, TransportError};

/// Payload Ping/Pong пробы (1 байт).
pub const PROBE_BYTE: u8 = 0x01;

/// Порог (мс) для INFO-уровня метрики `transport_acquire_wait_ms`.
/// Ниже — DEBUG: ожидания нет, это обычный выбор.
const ACQUIRE_WAIT_INFO_MS: u64 = 100;

/// Фабрика транспорта нужного типа (TLS/QUIC).
pub type TransportFactory =
    Arc<dyn Fn(TransportKind) -> Result<AnyClientTransport, TransportError> + Send + Sync>;

/// Строит клиентский транспорт для `kind` из готового rustls-конфига.
///
/// Дефолтный конструктор для [`TransportProbe`], `client` и `diag-cli`;
/// вызывающий может подставить свою [`TransportFactory`].
pub fn client_transport(
    kind: TransportKind,
    server_addr: SocketAddr,
    server_name: &str,
    rustls_config: &Arc<rustls::ClientConfig>,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> Result<AnyClientTransport, TransportError> {
    match kind {
        TransportKind::Tls => transport_tls::ClientTransport::new(
            server_addr,
            server_name,
            Arc::clone(rustls_config),
            connect_timeout,
            handshake_timeout,
        )
        .map(AnyClientTransport::Tls),
        TransportKind::Quic => {
            let quinn_config = transport_quic::client_config((**rustls_config).clone())?;
            transport_quic::QuicClientTransport::new(
                server_addr,
                server_name,
                quinn_config,
                handshake_timeout,
            )
            .map(AnyClientTransport::Quic)
        }
    }
}

/// Причина неудачи пробы.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeFailure {
    /// QUIC не прошёл, но TCP до того же адреса доступен → UDP фильтруется.
    UdpFiltered,
    /// TLS: TCP-соединение отвергнуто (сервер не слушает TCP).
    TlsRefused,
    /// Сервер недоступен ни по TCP, ни по UDP.
    ServerUnreachable,
    /// Handshake не завершился при доступном TCP.
    Handshake(String),
    /// Data-path (Ping/Pong) не подтвердился.
    DataPath(String),
}

impl ProbeFailure {
    /// Значение поля `reason=` для structured-лога.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::UdpFiltered => "udp_filtered",
            Self::TlsRefused => "tls_refused",
            Self::ServerUnreachable => "server_unreachable",
            Self::Handshake(_) | Self::DataPath(_) => "fallback_prev_failed",
        }
    }
}

/// Результат одной пробы.
#[derive(Debug, Clone)]
pub struct ProbeReport {
    /// Проверяемый транспорт.
    pub kind: TransportKind,
    /// Суммарная длительность пробы (включая повторные попытки).
    pub elapsed: Duration,
    /// `None` — проба успешна.
    pub failure: Option<ProbeFailure>,
}

impl ProbeReport {
    /// Успешна ли проба.
    pub fn is_ok(&self) -> bool {
        self.failure.is_none()
    }
}

/// Проверка доступности транспорта (в тестах подменяется mock-ом).
#[async_trait]
pub trait Probe: Send + Sync {
    /// Прогоняет одну пробу: connect → mTLS → Ping/Pong.
    async fn probe(&self, kind: TransportKind) -> ProbeReport;
}

/// Причина выбора — закрытый enum для `event=transport_selected`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectReason {
    /// Успешный результат в кэше (TTL не истёк).
    CachedOk,
    /// Первый в порядке транспортов прошёл пробу.
    ProbeOk,
    /// Fallback: предыдущий кандидат не прошёл по неуточнённой причине.
    FallbackPrevFailed,
    /// Fallback: UDP фильтруется (QUIC не прошёл, TCP жив).
    UdpFiltered,
    /// Fallback: TLS отказал на TCP (сервер не слушает TCP).
    TlsRefused,
    /// Fallback: сервер недоступен.
    ServerUnreachable,
    /// Все кандидаты недоступны → возвращён `preferred`.
    AllFailedDefault,
    /// Явно заданный транспорт (`strategy = tls|quic`), без проб.
    Manual,
}

impl SelectReason {
    /// Значение поля `reason=`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CachedOk => "cached_ok",
            Self::ProbeOk => "probe_ok",
            Self::FallbackPrevFailed => "fallback_prev_failed",
            Self::UdpFiltered => "udp_filtered",
            Self::TlsRefused => "tls_refused",
            Self::ServerUnreachable => "server_unreachable",
            Self::AllFailedDefault => "all_failed_default",
            Self::Manual => "manual",
        }
    }

    /// Требует ли причина уровня WARN (fallback/деградация).
    fn is_warn(&self) -> bool {
        !matches!(self, Self::CachedOk | Self::ProbeOk | Self::Manual)
    }
}

impl From<&ProbeFailure> for SelectReason {
    fn from(f: &ProbeFailure) -> Self {
        match f {
            ProbeFailure::UdpFiltered => Self::UdpFiltered,
            ProbeFailure::TlsRefused => Self::TlsRefused,
            ProbeFailure::ServerUnreachable => Self::ServerUnreachable,
            ProbeFailure::Handshake(_) | ProbeFailure::DataPath(_) => Self::FallbackPrevFailed,
        }
    }
}

/// Источник времени (в тестах — управляемые часы).
pub trait Clock: Send + Sync {
    /// Текущий момент.
    fn now(&self) -> Instant;
}

/// Системные монотонные часы.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Результат выбора транспорта.
#[derive(Debug, Clone)]
pub struct Selection {
    /// Выбранный транспорт.
    pub kind: TransportKind,
    /// Причина выбора.
    pub reason: SelectReason,
    /// Транспорт, с которого начали и который не прошёл (`None` — первый прошёл).
    pub fallback_from: Option<TransportKind>,
    /// Счётчик подряд идущих неудач выбранного транспорта.
    pub fail_count: u32,
    /// Сколько осталось от TTL кэша (только при `CachedOk`).
    pub cached_age: Option<Duration>,
    /// Пробы, выполненные в этом вызове: `(транспорт, длительность)`.
    pub probed: Vec<(TransportKind, Duration)>,
}

#[derive(Debug, Default, Clone)]
struct Entry {
    /// До какого момента результат считается успешным.
    ok_until: Option<Instant>,
    /// Сколько подряд неудач.
    fail_count: u32,
    /// До какого момента пробу не повторять (backoff).
    blocked_until: Option<Instant>,
    /// Последняя причина неудачи.
    last_failure: Option<ProbeFailure>,
    /// Последняя причина выбора/недоступности (для лога следующего выбора).
    last_reason: Option<SelectReason>,
}

#[derive(Debug, Clone)]
struct State {
    tls: Entry,
    quic: Entry,
    /// Токен: какой транспорт сейчас в пробе (`Some` — весь цикл выбора занят).
    probing: Option<TransportKind>,
    /// Пробуждение ожидающих по завершении probe-цикла.
    notify: Arc<Notify>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            tls: Entry::default(),
            quic: Entry::default(),
            probing: None,
            notify: Arc::new(Notify::new()),
        }
    }
}

impl State {
    fn get(&self, kind: TransportKind) -> &Entry {
        match kind {
            TransportKind::Tls => &self.tls,
            TransportKind::Quic => &self.quic,
        }
    }

    fn get_mut(&mut self, kind: TransportKind) -> &mut Entry {
        match kind {
            TransportKind::Tls => &mut self.tls,
            TransportKind::Quic => &mut self.quic,
        }
    }
}

/// Детерминированный менеджер выбора транспорта.
///
/// Выбор сериализован (один `tokio::sync::Mutex`): конкурентные соединения не
/// устраивают «стадо» одинаковых проб. Худшая цена холодного выбора —
/// `order().len() × max_probe_attempts × probe_timeout`.
pub struct TransportManager {
    policy: TransportPolicy,
    probe: Arc<dyn Probe>,
    clock: Arc<dyn Clock>,
    state: tokio::sync::Mutex<State>,
}

impl TransportManager {
    /// Создаёт менеджер с системными часами.
    pub fn new(policy: TransportPolicy, probe: Arc<dyn Probe>) -> Self {
        Self::with_clock(policy, probe, Arc::new(SystemClock))
    }

    /// Создаёт менеджер с заданными часами (детерминированные тесты).
    pub fn with_clock(
        policy: TransportPolicy,
        probe: Arc<dyn Probe>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            policy,
            probe,
            clock,
            state: tokio::sync::Mutex::new(State::default()),
        }
    }

    /// Политика (для логирования/диагностики).
    pub fn policy(&self) -> &TransportPolicy {
        &self.policy
    }

    /// Выбирает транспорт. Никогда не возвращает ошибку: при тотальном отказе
    /// возвращает `preferred` с причиной [`SelectReason::AllFailedDefault`].
    ///
    /// Проба идёт по singleflight: лок **не** держится через
    /// [`Self::probe_with_attempts`]; остальные acquire ждут результат через
    /// `Notify` (ADR-027). Метрика `transport_acquire_wait_ms` — INFO при
    /// ожидании ≥ [`ACQUIRE_WAIT_INFO_MS`], иначе DEBUG.
    pub async fn select(&self) -> Selection {
        let start = Instant::now();
        let sel = self.emit(self.select_inner().await);
        let wait_ms = start.elapsed().as_millis() as u64;
        let event = "transport_acquire_wait_ms";
        if wait_ms >= ACQUIRE_WAIT_INFO_MS {
            tracing::info!(
                event = %event,
                transport = %kind_str(sel.kind),
                reason = %sel.reason.as_str(),
                strategy = %strategy_str(self.policy.strategy),
                wait_ms = wait_ms,
            );
        } else {
            tracing::debug!(
                event = %event,
                transport = %kind_str(sel.kind),
                reason = %sel.reason.as_str(),
                strategy = %strategy_str(self.policy.strategy),
                wait_ms = wait_ms,
            );
        }
        sel
    }

    /// Логика выбора без метрики: singleflight-цикл.
    async fn select_inner(&self) -> Selection {
        let order = self.policy.order();

        // Явный транспорт: без проб и кэша.
        if order.len() == 1 {
            return Selection {
                kind: order[0],
                reason: SelectReason::Manual,
                fallback_from: None,
                fail_count: 0,
                cached_age: None,
                probed: Vec::new(),
            };
        }

        let mut probed: Vec<(TransportKind, Duration)> = Vec::new();
        let mut first_failure: Option<SelectReason> = None;
        let mut last_failed: Option<(TransportKind, u32)> = None;
        let mut idx = 0usize;

        'outer: loop {
            let mut state = self.state.lock().await;
            let now = self.clock.now();

            // Первый кандидат: cached → вернуть; blocked → пропустить;
            // иначе нужна проба.
            let mut target = None;
            let mut target_idx = idx;
            while target_idx < order.len() {
                let kind = order[target_idx];
                let e = state.get(kind);
                if let Some(until) = e.ok_until {
                    if now < until {
                        let cached_age = self.policy.ttl.saturating_sub(until - now);
                        let reason = if target_idx == 0 {
                            SelectReason::CachedOk
                        } else {
                            first_failure.unwrap_or(SelectReason::FallbackPrevFailed)
                        };
                        return Selection {
                            kind,
                            reason,
                            fallback_from: (target_idx > 0).then(|| order[0]),
                            fail_count: e.fail_count,
                            cached_age: Some(cached_age),
                            probed: std::mem::take(&mut probed),
                        };
                    }
                }
                if let Some(until) = e.blocked_until {
                    if now < until {
                        let reason = e
                            .last_reason
                            .or_else(|| e.last_failure.as_ref().map(SelectReason::from))
                            .unwrap_or(SelectReason::FallbackPrevFailed);
                        if target_idx == 0 && first_failure.is_none() {
                            first_failure = Some(reason);
                        }
                        last_failed = Some((kind, e.fail_count));
                        target_idx += 1;
                        continue;
                    }
                }
                target = Some(kind);
                break;
            }

            // Все кандидаты в backoff (или order пуст) → preferred.
            let Some(kind) = target else {
                let (last_kind, last_count) = last_failed.unwrap_or((order[0], 0));
                return Selection {
                    kind: order[0],
                    reason: SelectReason::AllFailedDefault,
                    fallback_from: (last_kind != order[0]).then_some(last_kind),
                    fail_count: last_count,
                    cached_age: None,
                    probed: std::mem::take(&mut probed),
                };
            };

            // Singleflight: кто-то уже пробит — ждём результат.
            if state.probing.is_some() {
                let notify = state.notify.clone();
                drop(state);
                notify.notified().await;
                continue 'outer;
            }

            // Мы — единственный пробирщик на весь цикл: лок отпускается
            // до `probe_with_attempts().await`.
            state.probing = Some(kind);
            drop(state);

            let report = self.probe_with_attempts(kind).await;
            probed.push((kind, report.elapsed));
            let at = self.clock.now();

            let mut state = self.state.lock().await;
            if state.probing == Some(kind) {
                // Мы всё ещё владеем токеном (invalidate не снял).
                match report.failure {
                    None => {
                        let e = state.get_mut(kind);
                        e.ok_until = Some(at + self.policy.ttl);
                        e.blocked_until = None;
                        e.fail_count = 0;
                        e.last_failure = None;
                        e.last_reason = None;
                        state.probing = None;
                        state.notify.notify_waiters();
                        let reason = if target_idx == 0 {
                            SelectReason::ProbeOk
                        } else {
                            first_failure.unwrap_or(SelectReason::FallbackPrevFailed)
                        };
                        return Selection {
                            kind,
                            reason,
                            fallback_from: (target_idx > 0).then(|| order[0]),
                            fail_count: 0,
                            cached_age: None,
                            probed: std::mem::take(&mut probed),
                        };
                    }
                    Some(failure) => {
                        let reason = SelectReason::from(&failure);
                        let e = state.get_mut(kind);
                        e.ok_until = None;
                        e.fail_count = e.fail_count.saturating_add(1);
                        let backoff = self.backoff(e.fail_count);
                        e.blocked_until = Some(at + backoff);
                        e.last_failure = Some(failure);
                        e.last_reason = Some(reason);
                        let fail_count = e.fail_count;
                        tracing::warn!(
                            event = %"transport_state",
                            transport = %kind_str(kind),
                            state = %"unavailable",
                            reason = %reason.as_str(),
                            fail_count = fail_count,
                            until_s = backoff.as_secs(),
                        );
                        state.probing = None;
                        state.notify.notify_waiters();
                        if target_idx == 0 && first_failure.is_none() {
                            first_failure = Some(reason);
                        }
                        last_failed = Some((kind, fail_count));
                        idx = target_idx + 1;
                        drop(state);
                        continue 'outer;
                    }
                }
            } else {
                // invalidate снял токен → результат пробы отбрасываем:
                // blocked_until от invalidate сохраняется, ok_until не пишем.
                state.notify.notify_waiters();
                drop(state);
                continue 'outer;
            }
        }
    }

    /// Помечает транспорт недоступным по итогу реального соединения
    /// (ошибка транспортного уровня, а не ответ цели).
    ///
    /// Singleflight (ADR-027): если этот транспорт сейчас в пробе — снимаем
    /// токен, чтобы результат пробы не перезаписал `blocked_until`. `invalidate`
    /// побеждает: `ok_until` не пишется, `blocked_until` сохраняется.
    pub async fn invalidate(&self, kind: TransportKind, reason: SelectReason) {
        let mut state = self.state.lock().await;
        let (fail_count, backoff) = {
            let e = state.get_mut(kind);
            e.ok_until = None;
            e.fail_count = e.fail_count.saturating_add(1);
            let backoff = self.backoff(e.fail_count);
            e.blocked_until = Some(self.clock.now() + backoff);
            e.last_reason = Some(reason);
            (e.fail_count, backoff)
        };
        if state.probing == Some(kind) {
            state.probing = None;
            state.notify.notify_waiters();
        }
        tracing::warn!(
            event = %"transport_state",
            transport = %kind_str(kind),
            state = %"unavailable",
            reason = %reason.as_str(),
            fail_count = fail_count,
            until_s = backoff.as_secs(),
        );
    }

    /// Экспоненциальный backoff: 1s, 2s, 4s, … с потолком `fail_ttl`.
    fn backoff(&self, fail_count: u32) -> Duration {
        let exp = fail_count.saturating_sub(1).min(16);
        let secs = 1u64.checked_shl(exp).unwrap_or(u64::MAX);
        Duration::from_secs(secs).min(self.policy.fail_ttl)
    }

    async fn probe_with_attempts(&self, kind: TransportKind) -> ProbeReport {
        let attempts = self.policy.max_probe_attempts.max(1);
        let mut total = Duration::ZERO;
        let mut failure = None;
        for _ in 0..attempts {
            let report = self.probe.probe(kind).await;
            total += report.elapsed;
            failure = report.failure;
            if failure.is_none() {
                break;
            }
        }
        ProbeReport {
            kind,
            elapsed: total,
            failure,
        }
    }

    fn emit(&self, selection: Selection) -> Selection {
        let probe_tls = probe_ms(&selection.probed, TransportKind::Tls);
        let probe_quic = probe_ms(&selection.probed, TransportKind::Quic);
        let cached_age_s = selection.cached_age.map(|d| d.as_secs()).unwrap_or(0);
        let fallback_from = selection.fallback_from.map(kind_str).unwrap_or("-");

        if selection.reason.is_warn() {
            tracing::warn!(
                event = %"transport_selected",
                transport = %kind_str(selection.kind),
                reason = %selection.reason.as_str(),
                strategy = %strategy_str(self.policy.strategy),
                preferred = %kind_str(self.policy.preferred),
                fallback_from = %fallback_from,
                probe_tls_ms = %probe_tls,
                probe_quic_ms = %probe_quic,
                cached_age_s = cached_age_s,
                fail_count = selection.fail_count,
            );
        } else {
            tracing::info!(
                event = %"transport_selected",
                transport = %kind_str(selection.kind),
                reason = %selection.reason.as_str(),
                strategy = %strategy_str(self.policy.strategy),
                preferred = %kind_str(self.policy.preferred),
                fallback_from = %fallback_from,
                probe_tls_ms = %probe_tls,
                probe_quic_ms = %probe_quic,
                cached_age_s = cached_age_s,
                fail_count = selection.fail_count,
            );
        }
        selection
    }
}

/// Реальная проба: создаёт транспорт, выполняет connect и Ping/Pong.
pub struct TransportProbe {
    factory: TransportFactory,
    timeout: Duration,
    server_addr: SocketAddr,
}

impl TransportProbe {
    /// `timeout` применяется отдельно к connect и к Ping/Pong.
    pub fn new(factory: TransportFactory, timeout: Duration, server_addr: SocketAddr) -> Self {
        Self {
            factory,
            timeout,
            server_addr,
        }
    }

    async fn run(&self, kind: TransportKind) -> Option<ProbeFailure> {
        let t_factory = Instant::now();
        let mut transport = match (self.factory)(kind) {
            Ok(t) => t,
            Err(e) => return Some(ProbeFailure::Handshake(e.to_string())),
        };
        let factory_ms = t_factory.elapsed().as_millis();

        let t_connect = Instant::now();
        let connect = tokio::time::timeout(self.timeout, transport.connect()).await;
        let connect_ms = t_connect.elapsed().as_millis();
        match connect {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Some(self.classify(kind, e.to_string()).await),
            Err(_) => return Some(self.classify(kind, "connect timeout".to_string()).await),
        }

        // Data-path: 1 байт туда и обратно. Handshake-only недостаточно.
        let t_data = Instant::now();
        let data = tokio::time::timeout(self.timeout, async {
            protocol::write_message(
                &mut transport,
                &protocol::Message::new(protocol::MessageKind::Ping, vec![PROBE_BYTE]),
            )
            .await
            .map_err(|e| e.to_string())?;

            let pong = protocol::read_message(&mut transport)
                .await
                .map_err(|e| e.to_string())?;
            if pong.kind != protocol::MessageKind::Pong {
                return Err(format!("expected Pong, got {:?}", pong.kind));
            }
            if pong.payload != [PROBE_BYTE] {
                return Err(format!("bad Pong payload {:?}", pong.payload));
            }
            Ok::<(), String>(())
        })
        .await;
        let data_ms = t_data.elapsed().as_millis();

        let result = match data {
            Ok(Ok(())) => None,
            Ok(Err(e)) => Some(ProbeFailure::DataPath(e)),
            Err(_) => Some(ProbeFailure::DataPath("timeout".into())),
        };

        // Закрываем всегда: проба не должна оставлять висящих соединений.
        let t_close = Instant::now();
        let _ = transport.close().await;
        let close_ms = t_close.elapsed().as_millis();

        tracing::debug!(
            transport = %kind_str(kind),
            factory_ms = factory_ms as u64,
            connect_ms = connect_ms as u64,
            data_ms = data_ms as u64,
            close_ms = close_ms as u64,
            ok = result.is_none(),
            "probe timings"
        );
        result
    }

    /// Классификация: UDP-фильтр отличается от «сервер недоступен» проверкой
    /// TCP до того же адреса.
    async fn classify(&self, kind: TransportKind, error: String) -> ProbeFailure {
        let tcp = tcp_reach(self.server_addr, self.timeout).await;
        match kind {
            TransportKind::Quic => match tcp {
                TcpReach::Open => ProbeFailure::UdpFiltered,
                TcpReach::Refused | TcpReach::Timeout => ProbeFailure::ServerUnreachable,
            },
            TransportKind::Tls => match tcp {
                TcpReach::Refused => ProbeFailure::TlsRefused,
                TcpReach::Open | TcpReach::Timeout => ProbeFailure::Handshake(error),
            },
        }
    }
}

#[async_trait]
impl Probe for TransportProbe {
    async fn probe(&self, kind: TransportKind) -> ProbeReport {
        let start = Instant::now();
        let failure = self.run(kind).await;
        if let Some(f) = &failure {
            tracing::debug!(
                transport = %kind_str(kind),
                reason = %f.reason(),
                detail = %match f {
                    ProbeFailure::Handshake(m) | ProbeFailure::DataPath(m) => m.as_str(),
                    _ => "",
                },
                "probe failed"
            );
        }
        ProbeReport {
            kind,
            elapsed: start.elapsed(),
            failure,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpReach {
    Open,
    Refused,
    Timeout,
}

async fn tcp_reach(addr: SocketAddr, timeout: Duration) -> TcpReach {
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(_)) => TcpReach::Open,
        Ok(Err(_)) => TcpReach::Refused,
        Err(_) => TcpReach::Timeout,
    }
}

fn kind_str(kind: TransportKind) -> &'static str {
    match kind {
        TransportKind::Tls => "tls",
        TransportKind::Quic => "quic",
    }
}

fn strategy_str(strategy: TransportStrategy) -> &'static str {
    match strategy {
        TransportStrategy::Auto => "auto",
        TransportStrategy::Tls => "tls",
        TransportStrategy::Quic => "quic",
    }
}

fn probe_ms(probed: &[(TransportKind, Duration)], kind: TransportKind) -> String {
    probed
        .iter()
        .find(|(k, _)| *k == kind)
        .map(|(_, d)| d.as_millis().to_string())
        .unwrap_or_else(|| "-".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;
    use tokio::sync::{Barrier, Notify};

    /// Управляемые часы: TTL/backoff проверяются без `sleep`.
    struct ManualClock(Mutex<Instant>);

    impl ManualClock {
        fn new() -> Self {
            Self(Mutex::new(Instant::now()))
        }

        fn advance(&self, d: Duration) {
            *self.0.lock().unwrap() += d;
        }
    }

    impl Clock for ManualClock {
        fn now(&self) -> Instant {
            *self.0.lock().unwrap()
        }
    }

    /// Mock-проба: поведение задаётся на транспорт, вызовы считаются.
    /// `gate` (опционально) блокирует пробу до `notify_waiters()` — для
    /// детерминированных concurrency-тестов (singleflight).
    struct MockProbe {
        behavior: Mutex<HashMap<TransportKind, Option<ProbeFailure>>>,
        calls: Mutex<Vec<TransportKind>>,
        in_flight: AtomicUsize,
        max_in_flight: AtomicUsize,
        gate: Option<Arc<Notify>>,
        released: AtomicBool,
    }

    impl MockProbe {
        fn new() -> Self {
            Self {
                behavior: Mutex::new(HashMap::new()),
                calls: Mutex::new(Vec::new()),
                in_flight: AtomicUsize::new(0),
                max_in_flight: AtomicUsize::new(0),
                gate: None,
                released: AtomicBool::new(false),
            }
        }

        fn with_gate(gate: Arc<Notify>) -> Self {
            Self {
                behavior: Mutex::new(HashMap::new()),
                calls: Mutex::new(Vec::new()),
                in_flight: AtomicUsize::new(0),
                max_in_flight: AtomicUsize::new(0),
                gate: Some(gate),
                released: AtomicBool::new(false),
            }
        }

        fn set(&self, kind: TransportKind, failure: Option<ProbeFailure>) {
            self.behavior.lock().unwrap().insert(kind, failure);
        }

        fn calls(&self) -> Vec<TransportKind> {
            self.calls.lock().unwrap().clone()
        }

        fn max_in_flight(&self) -> usize {
            self.max_in_flight.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl Probe for MockProbe {
        async fn probe(&self, kind: TransportKind) -> ProbeReport {
            let in_flight = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_in_flight.fetch_max(in_flight, Ordering::SeqCst);
            self.calls.lock().unwrap().push(kind);
            if let Some(g) = &self.gate {
                // Одноразовый gate: блокируем только первую пробу (пока тест
                // не отпустит). Последующие (fallback) пробы не блокируем.
                if !self.released.load(Ordering::SeqCst) {
                    g.notified().await;
                    self.released.store(true, Ordering::SeqCst);
                }
            }
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            let failure = self.behavior.lock().unwrap().get(&kind).cloned().flatten();
            ProbeReport {
                kind,
                elapsed: Duration::from_millis(1),
                failure,
            }
        }
    }

    fn policy(preferred: TransportKind) -> TransportPolicy {
        TransportPolicy {
            preferred,
            ..TransportPolicy::default()
        }
    }

    fn manager(
        policy: TransportPolicy,
        probe: Arc<MockProbe>,
        clock: Arc<ManualClock>,
    ) -> TransportManager {
        TransportManager::with_clock(policy, probe, clock)
    }

    #[tokio::test]
    async fn udp_blocked_falls_back_to_tls() {
        let clock = Arc::new(ManualClock::new());
        let probe = Arc::new(MockProbe::new());
        probe.set(TransportKind::Quic, Some(ProbeFailure::UdpFiltered));
        probe.set(TransportKind::Tls, None);
        let mgr = manager(policy(TransportKind::Quic), probe.clone(), clock);

        let sel = mgr.select().await;
        assert_eq!(sel.kind, TransportKind::Tls);
        assert_eq!(sel.reason, SelectReason::UdpFiltered);
        assert_eq!(sel.fallback_from, Some(TransportKind::Quic));
        assert_eq!(
            probe.calls(),
            vec![TransportKind::Quic, TransportKind::Tls],
            "QUIC сначала (preferred=quic), затем TLS"
        );
    }

    #[tokio::test]
    async fn tls_refused_falls_back_to_quic() {
        let clock = Arc::new(ManualClock::new());
        let probe = Arc::new(MockProbe::new());
        probe.set(TransportKind::Tls, Some(ProbeFailure::TlsRefused));
        probe.set(TransportKind::Quic, None);
        let mgr = manager(policy(TransportKind::Tls), probe.clone(), clock);

        let sel = mgr.select().await;
        assert_eq!(sel.kind, TransportKind::Quic);
        assert_eq!(sel.reason, SelectReason::TlsRefused);
        assert_eq!(sel.fallback_from, Some(TransportKind::Tls));
        assert_eq!(probe.calls(), vec![TransportKind::Tls, TransportKind::Quic]);
    }

    #[tokio::test]
    async fn backoff_prevents_probe_storm() {
        let clock = Arc::new(ManualClock::new());
        let probe = Arc::new(MockProbe::new());
        probe.set(TransportKind::Tls, Some(ProbeFailure::TlsRefused));
        probe.set(TransportKind::Quic, Some(ProbeFailure::ServerUnreachable));
        let mgr = manager(policy(TransportKind::Tls), probe.clone(), clock.clone());

        let first = mgr.select().await;
        assert_eq!(first.reason, SelectReason::AllFailedDefault);
        assert_eq!(first.kind, TransportKind::Tls, "все упали → preferred");
        assert_eq!(probe.calls().len(), 2, "по одной пробе на транспорт");

        // В пределах backoff (1s после первой неудачи) проб нет.
        clock.advance(Duration::from_millis(500));
        let second = mgr.select().await;
        assert_eq!(second.reason, SelectReason::AllFailedDefault);
        assert_eq!(
            probe.calls().len(),
            2,
            "backoff: повторных проб в пределах паузы нет"
        );

        // После backoff — снова пробы.
        clock.advance(Duration::from_secs(1));
        let _ = mgr.select().await;
        assert!(probe.calls().len() > 2, "после backoff проба повторяется");
    }

    #[tokio::test]
    async fn cache_within_ttl_skips_probe() {
        let clock = Arc::new(ManualClock::new());
        let probe = Arc::new(MockProbe::new());
        probe.set(TransportKind::Tls, None);
        probe.set(TransportKind::Quic, None);
        let mgr = manager(policy(TransportKind::Tls), probe.clone(), clock.clone());

        let first = mgr.select().await;
        assert_eq!(first.reason, SelectReason::ProbeOk);
        assert_eq!(probe.calls(), vec![TransportKind::Tls]);

        clock.advance(Duration::from_secs(60));
        let second = mgr.select().await;
        assert_eq!(second.kind, TransportKind::Tls);
        assert_eq!(second.reason, SelectReason::CachedOk);
        assert_eq!(
            probe.calls().len(),
            1,
            "в пределах TTL проба не повторяется"
        );
        assert!(second.cached_age.is_some());

        clock.advance(Duration::from_secs(300));
        let _ = mgr.select().await;
        assert_eq!(probe.calls().len(), 2, "после TTL проба повторяется");
    }

    #[tokio::test]
    async fn all_failed_default_is_preferred_not_last_success() {
        let clock = Arc::new(ManualClock::new());
        let probe = Arc::new(MockProbe::new());
        // preferred=tls: сначала TLS падает, QUIC успешен.
        probe.set(TransportKind::Tls, Some(ProbeFailure::TlsRefused));
        probe.set(TransportKind::Quic, None);
        let mgr = manager(policy(TransportKind::Tls), probe.clone(), clock.clone());
        let sel = mgr.select().await;
        assert_eq!(sel.kind, TransportKind::Quic, "первый успешный — QUIC");

        // Оба падают после истечения TTL: результат — preferred (TLS),
        // а не последний успешный (QUIC).
        probe.set(TransportKind::Quic, Some(ProbeFailure::ServerUnreachable));
        clock.advance(Duration::from_secs(301));
        let sel = mgr.select().await;
        assert_eq!(sel.kind, TransportKind::Tls);
        assert_eq!(sel.reason, SelectReason::AllFailedDefault);
    }

    #[tokio::test]
    async fn manual_strategy_skips_probes() {
        let clock = Arc::new(ManualClock::new());
        let probe = Arc::new(MockProbe::new());
        let mgr = manager(
            TransportPolicy {
                strategy: TransportStrategy::Quic,
                ..TransportPolicy::default()
            },
            probe.clone(),
            clock,
        );
        let sel = mgr.select().await;
        assert_eq!(sel.kind, TransportKind::Quic);
        assert_eq!(sel.reason, SelectReason::Manual);
        assert!(probe.calls().is_empty());
    }

    #[tokio::test]
    async fn invalidate_forces_reprobe() {
        let clock = Arc::new(ManualClock::new());
        let probe = Arc::new(MockProbe::new());
        probe.set(TransportKind::Tls, None);
        probe.set(TransportKind::Quic, None);
        let mgr = manager(policy(TransportKind::Tls), probe.clone(), clock.clone());
        let _ = mgr.select().await;
        assert_eq!(probe.calls().len(), 1);

        mgr.invalidate(TransportKind::Tls, SelectReason::TlsRefused)
            .await;
        probe.set(TransportKind::Tls, Some(ProbeFailure::TlsRefused));
        let sel = mgr.select().await;
        assert_eq!(
            sel.kind,
            TransportKind::Quic,
            "после инвалидации — fallback"
        );
        assert_eq!(sel.reason, SelectReason::TlsRefused);
    }

    #[tracing_test::traced_test]
    #[tokio::test]
    async fn emits_transport_selected_with_reason() {
        let clock = Arc::new(ManualClock::new());
        let probe = Arc::new(MockProbe::new());
        probe.set(TransportKind::Quic, Some(ProbeFailure::UdpFiltered));
        probe.set(TransportKind::Tls, None);
        let mgr = manager(policy(TransportKind::Quic), probe, clock);

        let _ = mgr.select().await;

        assert!(logs_contain("event=transport_selected"));
        assert!(logs_contain("transport=tls"));
        assert!(logs_contain("reason=udp_filtered"));
        assert!(logs_contain("fallback_from=quic"));
        assert!(logs_contain("event=transport_state"));
        assert!(logs_contain("state=unavailable"));
    }

    // ---- ADR-027: singleflight ----

    /// 100 одновременных acquire на холодном кэше → ровно 1 проба, остальные
    /// ждут через `Notify` и берут результат из кэша. Лок не держится через
    /// `probe().await`.
    #[tokio::test]
    async fn concurrency_cold_select_single_probe() {
        let clock = Arc::new(ManualClock::new());
        let gate = Arc::new(Notify::new());
        let probe = Arc::new(MockProbe::with_gate(gate.clone()));
        probe.set(TransportKind::Tls, None);
        probe.set(TransportKind::Quic, None);
        let mgr = Arc::new(manager(
            policy(TransportKind::Tls),
            probe.clone(),
            clock.clone(),
        ));

        let barrier = Arc::new(Barrier::new(100 + 1));
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..100 {
            let mgr = mgr.clone();
            let barrier = barrier.clone();
            set.spawn(async move {
                barrier.wait().await;
                mgr.select().await
            });
        }
        barrier.wait().await; // стартуют одновременно

        // Первая проба в полёте (блокирована на gate).
        while probe.max_in_flight() == 0 {
            tokio::task::yield_now().await;
        }
        assert_eq!(probe.calls().len(), 1, "singleflight: 1 проба, не N");
        assert!(probe.max_in_flight() <= 1, "нет параллельных проб");

        gate.notify_waiters();

        let mut probe_ok = 0;
        let mut cached_ok = 0;
        while let Some(res) = set.join_next().await {
            let sel = res.unwrap();
            assert_eq!(sel.kind, TransportKind::Tls, "все выбрали TLS");
            match sel.reason {
                SelectReason::ProbeOk => probe_ok += 1,
                SelectReason::CachedOk => cached_ok += 1,
                r => panic!("неожиданная причина {r:?}"),
            }
        }
        assert_eq!(probe.calls().len(), 1, "всего одна проба на 100 acquire");
        assert_eq!(probe_ok, 1, "один пробил");
        assert_eq!(cached_ok, 99, "остальные взяли из кэша");
    }

    /// 100 acquire в пределах TTL → 0 новых проб (кэш).
    #[tokio::test]
    async fn ttl_100_acquires_zero_probes() {
        let clock = Arc::new(ManualClock::new());
        let probe = Arc::new(MockProbe::new());
        probe.set(TransportKind::Tls, None);
        probe.set(TransportKind::Quic, None);
        let mgr = Arc::new(manager(
            policy(TransportKind::Tls),
            probe.clone(),
            clock.clone(),
        ));

        let first = mgr.select().await;
        assert_eq!(first.reason, SelectReason::ProbeOk);
        assert_eq!(probe.calls().len(), 1);

        let mut set = tokio::task::JoinSet::new();
        for _ in 0..100 {
            let mgr = mgr.clone();
            set.spawn(async move { mgr.select().await });
        }
        while let Some(res) = set.join_next().await {
            let sel = res.unwrap();
            assert_eq!(sel.kind, TransportKind::Tls);
            assert_eq!(sel.reason, SelectReason::CachedOk);
        }
        assert_eq!(
            probe.calls().len(),
            1,
            "в пределах TTL пробы не повторяются"
        );
    }

    /// Проба упала → blocked_until; 100 acquire в пределах backoff → 0 проб.
    #[tokio::test]
    async fn backoff_concurrent_no_reprobe() {
        let clock = Arc::new(ManualClock::new());
        let probe = Arc::new(MockProbe::new());
        probe.set(TransportKind::Tls, Some(ProbeFailure::TlsRefused));
        probe.set(TransportKind::Quic, Some(ProbeFailure::ServerUnreachable));
        let mgr = Arc::new(manager(
            policy(TransportKind::Tls),
            probe.clone(),
            clock.clone(),
        ));

        let first = mgr.select().await;
        assert_eq!(first.reason, SelectReason::AllFailedDefault);
        assert_eq!(probe.calls().len(), 2, "по одной пробе на транспорт");

        let mut set = tokio::task::JoinSet::new();
        for _ in 0..100 {
            let mgr = mgr.clone();
            set.spawn(async move { mgr.select().await });
        }
        while let Some(res) = set.join_next().await {
            let sel = res.unwrap();
            assert_eq!(sel.reason, SelectReason::AllFailedDefault);
        }
        assert_eq!(
            probe.calls().len(),
            2,
            "backoff: 0 новых проб в пределах паузы"
        );
    }

    /// `invalidate` во время пробы побеждает: результат пробы отбрасывается,
    /// `blocked_until` от invalidate сохраняется, `ok_until` не пишется.
    #[tokio::test]
    async fn invalidate_during_probe_wins() {
        let clock = Arc::new(ManualClock::new());
        let gate = Arc::new(Notify::new());
        let probe = Arc::new(MockProbe::with_gate(gate.clone()));
        probe.set(TransportKind::Tls, None); // проба была бы успешной
        probe.set(TransportKind::Quic, None);
        let mgr = Arc::new(manager(
            policy(TransportKind::Tls),
            probe.clone(),
            clock.clone(),
        ));

        let handle = {
            let mgr = mgr.clone();
            tokio::spawn(async move { mgr.select().await })
        };
        while probe.max_in_flight() == 0 {
            tokio::task::yield_now().await;
        }
        assert_eq!(probe.calls().len(), 1, "TLS в полёте");

        // invalidate во время пробы.
        mgr.invalidate(TransportKind::Tls, SelectReason::TlsRefused)
            .await;

        // Отпускаем gate: проба завершается, но её результат отбрасывается.
        gate.notify_waiters();
        let sel = handle.await.unwrap();

        let s = mgr.state.lock().await;
        let tls = s.get(TransportKind::Tls);
        assert!(tls.ok_until.is_none(), "результат пробы TLS не записан");
        assert!(
            tls.blocked_until.is_some(),
            "blocked_until от invalidate сохранён"
        );
        assert_eq!(tls.fail_count, 1);
        drop(s);

        assert_eq!(
            sel.kind,
            TransportKind::Quic,
            "после invalidate — fallback на QUIC"
        );
        assert_eq!(sel.reason, SelectReason::TlsRefused);
    }

    /// Churn (P11 regression): быстрые connect/disconnect — 0 probe storm.
    #[tokio::test]
    async fn churn_no_probe_storm() {
        let clock = Arc::new(ManualClock::new());
        let probe = Arc::new(MockProbe::new());
        probe.set(TransportKind::Tls, None);
        probe.set(TransportKind::Quic, None);
        let mgr = Arc::new(manager(
            policy(TransportKind::Tls),
            probe.clone(),
            clock.clone(),
        ));

        let _ = mgr.select().await; // warmup: 1 проба
        assert_eq!(probe.calls().len(), 1);

        // Быстрые connect/disconnect в пределах TTL → 0 новых проб.
        for _ in 0..200 {
            let _ = mgr.select().await;
            tokio::task::yield_now().await;
        }
        assert_eq!(
            probe.calls().len(),
            1,
            "churn в пределах TTL: probe storm нет"
        );

        // После истечения TTL — снова ровно 1 новая проба (не N).
        clock.advance(Duration::from_secs(301));
        let _ = mgr.select().await;
        assert_eq!(probe.calls().len(), 2, "после TTL ровно 1 новая проба");
    }

    /// Пока проба в полёте (gate), лок свободен: второй acquire не блокируется
    /// на `Mutex`, а ждёт `Notify`. Если бы лок держался через `probe()` —
    /// `lock()` не прошёл бы за таймаут.
    #[tokio::test]
    async fn lock_not_held_through_probe() {
        let clock = Arc::new(ManualClock::new());
        let gate = Arc::new(Notify::new());
        let probe = Arc::new(MockProbe::with_gate(gate.clone()));
        probe.set(TransportKind::Tls, None);
        probe.set(TransportKind::Quic, None);
        let mgr = Arc::new(manager(
            policy(TransportKind::Tls),
            probe.clone(),
            clock.clone(),
        ));

        let handle = {
            let mgr = mgr.clone();
            tokio::spawn(async move { mgr.select().await })
        };
        while probe.max_in_flight() == 0 {
            tokio::task::yield_now().await;
        }

        // Лок доступен во время пробы (singleflight снял его до probe()).
        let guard = tokio::time::timeout(Duration::from_millis(500), mgr.state.lock())
            .await
            .expect("лок свободен во время пробы");
        assert_eq!(guard.probing, Some(TransportKind::Tls), "токен выставлен");
        drop(guard);

        gate.notify_waiters();
        let sel = handle.await.unwrap();
        assert_eq!(sel.kind, TransportKind::Tls);
        assert_eq!(probe.calls().len(), 1);
    }
}
