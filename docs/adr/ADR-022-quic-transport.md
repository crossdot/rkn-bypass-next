# ADR-022: QUIC-транспорт (P4b)

## Статус: Принято

## Контекст
P4b — второй транспорт (QUIC на quinn) после TLS (P4a, async). Дополнительный
транспорт для обхода DPI; маскировка под HTTP/3.

## Решение
1. `transport-quic` — реализация `Transport` на `quinn` 0.11 (rustls-ring):
   `QuicClientTransport` (Endpoint + connect + bi-stream) и `QuicServerTransport`
   (принятое соединение + bi-stream).
2. mTLS: тот же `AuthClientVerifier` (rustls `ServerConfig`) → `verify_client_cert`
   → `find_by_fingerprint` + `revoked` → `event=mtls_handshake`. Отказ на
   TLS-уровне (до завершения handshake), идентично TLS (ADR-021).
3. `quinn` зафиксирован на `ring` (`default-features = false`,
   `features = ["runtime-tokio", "rustls-ring", "log"]`) — иначе `aws-lc-rs`
   (cmake + C-компилятор). MSRV 1.85 (quinn 0.11.12 `rust-version = 1.85`).
4. Диспетчеризация: `enum AnyTransport { Tls(..), Quic(..) }` (impl `Transport`
   через `match`); выбор по конфигу `transport = "tls" | "quic"`.

## 0-RTT — отключён
- В quinn 0.11 0-RTT — opt-in: `Connecting::into_0rtt()` / `Incoming::into_0rtt()`.
  Мы нигде их не вызываем (клиент `connect`, сервер `Incoming::await` — полный
  handshake). 0-RTT выключен по умолчанию.
- Причина: в 0-RTT клиент не аутентифицирован (ранние данные идут до завершения
  handshake) → обход `verify_client_cert` и аудита (как session resumption, ADR-021).

## Ограничения аудита в QUIC
- `AuthClientVerifier` в QUIC — общий (на `Endpoint`), не per-connection;
  `remote_addr` недоступен в verifier'е.
- `ok`-события: `remote_addr` через `Connection::remote_address()` post-handshake.
- `rejected`-события: `remote_addr` отсутствует (поле не эмитится, как
  `missing_cert` в TLS) — deviation от TLS (там remote_addr и для rejected).
  Детекция брутфорса по IP в QUIC недоступна — известное ограничение MVP.
- Phase 2: pre-handshake logging в accept-цикле (`Incoming::remote_address()`
  до `accept()`) или кастомный verifier-контекст.

## UDP на мобильных
- QUIC может не работать на части мобильных сетей РФ (UDP блокируется).
  Fallback на TLS — политика выбора транспорта, Phase 2 (P5). Не обещаем,
  что QUIC везде работает.

## Последствия
- Новые крейты `transport-quic`, `testkit` (общий `contract_suite`).
- Контрактные тесты шарятся между TLS и QUIC (дублируется только фабрика).
- Несовместимость транспортов обнаруживается на handshake (до передачи
  пользовательских данных).
