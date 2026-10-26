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
4. Диспетчеризация: крейт `transport-any` — `AnyClientTransport` /
   `AnyServerTransport` (`enum Tls(..) | Quic(..)`, impl `Transport` через
   `match`). Выбор по `config::TransportKind` (`[server] transport =
   "tls" | "quic"`, по умолчанию `tls`). `proxy-core` не знает о конкретном
   транспорте.

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
- `rejected`-события: `remote_addr` — `Option<SocketAddr>`; в QUIC verifier
  общий на `Endpoint`, адрес до handshake недоступен → `remote_addr=-`
  (в TLS — реальный адрес). Детекция брутфорса по IP в QUIC недоступна —
  известное ограничение MVP.
- Phase 2: pre-handshake logging в accept-цикле (`Incoming::remote_address()`
  до `accept()`) или кастомный verifier-контекст.

## UDP на мобильных
- QUIC может не работать на части мобильных сетей РФ (UDP блокируется).
  Fallback на TLS — политика выбора транспорта, Phase 2 (P5). Не обещаем,
  что QUIC везде работает.

## Ограничения QUIC-транспорта
- **Инициатор bi-stream всегда клиент.** Клиент открывает поток (`open_bi`),
  сервер принимает (`accept_bi`). Серверный `accept_bi` ждёт STREAM-фрейм от
  клиента, поэтому сервер не может начать передачу первым.
- В SOCKS5-сценарии это свойство не проявляется: клиент всегда инициирует
  запрос (CONNECT → данные), сервер только отвечает.
- Контрактный тест `mid_transfer_drop_detected` адаптирован под это свойство:
  параметризован `Initiator` (`Client | Server`). TLS (симметричный поток)
  прогоняет оба варианта, QUIC — только `Initiator::Client` (клиент шлёт первый
  байт, открывая bi-stream). Перед `drop` соединения тест даёт QUIC-драйверу
  время дослать STREAM-фреймы, иначе клиент может увидеть пустой поток.
- Флак-проверка `mid_transfer_drop_detected` (sleep 50 мс + drop): 10/10
  прогонов зелёные, флаков нет — детерминированное ожидание не потребовалось.
- E2E (`scripts/e2e.sh`): server + client с `TRANSPORT=tls|quic` →
  SOCKS5 → HTTP 200 в обеих конфигурациях. Путь per-connection (mTLS-identity
  → session-limit → `serve_server_connection`) общий, через `AnyServerTransport`;
  прикладной код (proxy-core) не знает о транспорте.

## Последствия
- Новые крейты `transport-quic`, `transport-any` (диспетчеризация), `testkit`
  (общий `contract_suite`).
- Контрактные тесты шарятся между TLS и QUIC (дублируется только фабрика).
- Несовместимость транспортов обнаруживается на handshake (до передачи
  пользовательских данных).
