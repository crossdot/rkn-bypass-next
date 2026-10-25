# ADR-017: Синхронный контракт Transport в MVP

## Статус: Принято

## Контекст
`transport-api` уже содержит синхронный трейт `Transport`
(connect/send/recv/close, все `&mut self`). Первый транспорт — TLS
на `rustls`. В production понадобится async (SOCKS5 с конкурентными
соединениями, mux), но для минимального сквозного сценария P2/P3
sync достаточно.

## Решение
1. В MVP `Transport` остаётся синхронным. Реализация TLS — `rustls`
   (sync), `rustls::StreamOwned` поверх `std::net::TcpStream`.
2. Сервер и клиент — thread-per-connection (`std::thread` +
   `std::net`). Async runtime (`tokio`) в MVP не вводится.
3. Таймауты handshake — через `TcpStream::set_read_timeout` /
   `set_write_timeout` до обёртки в TLS.
4. Переход на async (`tokio-rustls`) — Phase 2, отдельный ADR.
   Контракт `Transport` при этом меняется; это осознанное решение,
   а не побочный эффект.
5. `rustls` sans-I/O: `ClientConfig`/`ServerConfig` переносятся
   в async без изменений. Меняется только обвязка I/O и сигнатуры
   трейта.

## Последствия
- MVP проще для отладки и не требует tokio.
- Thread-per-connection не масштабируется до production-нагрузки;
  это принимается осознанно на этапе MVP.
- Phase 2 включает рефакторинг `Transport` и серверного/клиентского
  цикла; sync-версия остаётся как эталон для проверки корректности.
- ADR-017 не отменяет и не меняет ADR-011/012/013/016.