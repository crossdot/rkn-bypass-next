# Ограничения SOCKS5-режима (MVP)

## Известные ограничения
- **Нет UDP ASSOCIATE и BIND.** Обе команды отклоняются с `0x07`
  (Command not supported). Это осознанно для MVP.
- **Thread-per-connection.** Масштабируется ограниченно; async —
  Phase 2 (ADR-017).
- **DNS-rebinding (TOCTOU).** Для доменных целей адресные правила
  проверяются по всем разрешённым IP, но подключение идёт к первому IP;
  гонка между проверкой и connect не устранена (MVP).

## Реализовано

### ack-протокол (P3-fix)
- Сервер после `TcpStream::connect` к цели отправляет `ConnectAck`
  (payload = 1 байт REP-кода). Клиент ждёт ack с таймаутом
  (`ACK_TIMEOUT`) и только затем отправляет `REP_SUCCESS`.
- Ошибки connect → REP-коды: `ConnectionRefused → 0x05`,
  `NetworkUnreachable → 0x03`, `HostUnreachable/TimedOut → 0x04`,
  прочее → `0x01`. Таймаут ack → `0x04`.

### Адресные правила (P7.3)
- `[server.address_rules]` в TOML: `allow_ports_low`, `allow_cidrs`,
  `deny_cidrs`. Парсинг + валидация CIDR в `crates/config`.
- Hardcoded always-deny (не переопределяется): loopback, link-local,
  unspecified, multicast, ULA — `127/8`, `::1`, `169.254/16`, `0/8`,
  `224/4`, `fc00::/7`, `fe80::/10`.
- RFC1918 (`10/8`, `172.16/12`, `192.168/16`) — default-deny,
  переопределяется `allow_cidrs`.
- Порт < 1024 — deny, кроме `allow_ports_low`.
- `deny_cidrs` переопределяет `allow_cidrs`.
- При отказе — `ConnectAck` с `REP_CONNECTION_NOT_ALLOWED` (0x02).

### Диагностика (P9)
- `apps/diag-cli` — `diag check <host>:<port>`: connect → TLS →
  SOCKS5-ack → relay, класс ошибки на каждом этапе, без root.

## Что проверено
- `curl --socks5 127.0.0.1:1080 http://127.0.0.1/` → 0x02 (not allowed).
- 44 автоматических теста: relay, конкурентные CONNECT, отказ UDP/BIND,
  ack-протокол (0x05/0x04/0x01), адресные правила (loopback/link-local/
  low-port/private, allow/deny CIDR).
