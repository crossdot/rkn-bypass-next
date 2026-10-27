# ADR-025: Двунаправленный relay — устранение дедлока под backpressure

## Статус: Принято

## Контекст
Контракт [`Transport`] (ADR-017): `send`/`recv` принимают `&mut self` и не
могут исполняться конкурентно на одном объекте. `proxy_core::relay` делал
поллинг обеих сторон через `tokio::time::timeout` (`RELAY_POLL_INTERVAL = 10 мс`):
сначала пытался прочитать TCP-сокет, затем транспорт.

Под backpressure это даёт **дедлок**: когда обе стороны заполнены, каждый
`transport.send().await` ждёт, пока противоположная сторона не освободит окно,
а та — своего `send`. Таймаут оборачивал только чтение, но не `send`, поэтому
цикл зависал навсегда. Кроме того, таймерный поллинг даёт задержки и churn
таймеров на каждом соединении.

## Решение

### 1. Отдельная капабилити `BidirectionalRelay`
Новый трейт `BidirectionalRelay` в `transport-api` — **не изменение контракта
[`Transport`]**:

```rust
#[async_trait]
pub trait BidirectionalRelay {
    async fn relay_bidirectional(self, tcp: TcpStream) -> Result<(), TransportError>;
}
```

`self` владеет транспортом; `tcp` — «прикладная» сторона (app-сокет клиента
или TCP-соединение к цели на сервере). Реализации знают конкретный транспорт:

- **TLS** (`ClientTransport`/`ServerTransport`): `TlsStream` — `AsyncRead +
  AsyncWrite`, используется `tokio::io::copy_bidirectional` (полный дуплекс).
- **QUIC** (`QuicClientTransport`/`QuicServerTransport`): `SendStream`/`RecvStream`
  — раздельные `&mut`-потоки, поэтому копируются двумя конкурентными фьючами
  (`pump_tcp_to_quic` + `pump_quic_to_tcp`), разнесёнными по половинкам
  TCP-сокета (`tokio::io::split`). Неисполненная фьюча дропается при выходе из
  функции — это и есть отмена по ошибке. Завершение одной стороны `shutdown`'ит
  другую (graceful drain), но продолжает дренаж второй стороны.
- **`transport-any`** (`AnyClientTransport`/`AnyServerTransport`): `match` по
  варианту, делегирование во внутренний транспорт.

### 2. `proxy_core::relay` делегирует
`serve_client_connection`, `serve_server_connection` и `relay` требуют
`T: Transport + BidirectionalRelay` и вызывают `relay_bidirectional`. Поллинг и
`RELAY_POLL_INTERVAL` удалены.

## Почему не в `Transport`
Добавление в контракт `Transport` потребовало бы обязательной реализации во
всех транспортах и изменило бы контракт (ADR-025 — это не изменение).
Отдельный трейт — opt-in капабилити: транспорты, которые relay не используют,
не обязаны её реализовывать.

## Что ломается
- `proxy_core::relay`, `serve_client_connection`, `serve_server_connection`
  требуют `T: Transport + BidirectionalRelay`. Все существующие транспорты
  (TLS, QUIC, `transport-any`) реализуют капабилити.
- `transport-api` и `transport-any` теперь зависят от `tokio` (сигнатура
  использует `TcpStream`); контракт async уже был (ADR-017).
- `RELAY_POLL_INTERVAL` удалён (не использовался вне `relay`).

## Проверка
- `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test --workspace`, `cargo build --workspace` — зелёные.
- `scripts/e2e.sh`: `manual-tls`, `manual-quic`, `auto-default`,
  `dual-listen-manual-quic`, `auto-preferred-quic`, `auto-fallback-udp` → `HTTP 200`.

## Последствия
- Нет поллинга → выше пропускная способность, нет дедлока под backpressure.
- mTLS/аудит/`max_sessions` не затрагиваются (relay идёт после handshake и
  аутентификации, ADR-021).
- Профили A (Direct) и B (Camouflaged) не затрагиваются; transport/tls и
  protocol профиль не знают (ADR-013).
