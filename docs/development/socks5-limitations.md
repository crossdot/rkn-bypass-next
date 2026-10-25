# Ограничения SOCKS5-режима (MVP)

## Известные ограничения
- **Ограничения по адресам на сервере.** Сервер пока открывает TCP
  к любому запрошенному адресу. Ограничения — следующий шаг.
- **Нет UDP ASSOCIATE и BIND.** Обе команды отклоняются с `0x07`
  (Command not supported). Это осознанно для MVP.
- **Thread-per-connection.** Масштабируется ограниченно; async —
  Phase 2 (ADR-017).

## Реализовано: ack-протокол (P3-fix)
- Сервер после `TcpStream::connect` к цели отправляет `ConnectAck`
  (payload = 1 байт REP-кода). Клиент ждёт ack с таймаутом
  (`ACK_TIMEOUT`) и только затем отправляет `REP_SUCCESS`.
- Ошибки connect маппятся в REP-коды: `ConnectionRefused → 0x05`,
  `NetworkUnreachable → 0x03`, `HostUnreachable/TimedOut → 0x04`,
  прочее → `0x01`. Таймаут ack → `0x04`.

## Что проверено
- `curl -4 --socks5 127.0.0.1:1080 http://example.com` → HTTP 200.
- `curl --socks5-hostname 127.0.0.1:1080 http://example.com` → HTTP 200.
- 30 автоматических тестов: relay mid-transfer, 8 конкурентных CONNECT,
  отказ UDP/BIND, connection-refused (0x05), ack-timeout (0x04),
  битый ConnectAck (0x01), IPv6-loopback (::1).

## Что не проверено в этой среде
- Точная команда `curl --socks5 127.0.0.1:1080 http://example.com`
  без флагов: в песочнице нет IPv6-маршрута, резолвер отдаёт IPv6,
  сервер получает `ENETUNREACH`. Это не баг relay; проверено
  прямым `TcpStream::connect` и IPv6-литералом.
