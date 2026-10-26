# ADR-020: Connect-Ack протокол

## Статус: Принято

## Контекст
ADR-019 (оптимистичный SOCKS5 REP_SUCCESS) нарушал требование
«клиент не сообщает об успехе, которого фактически нет»
(docs/requirements.md). Требуется ack-протокол.

## Решение
1. `MessageKind::ConnectAck` — payload = 1 байт REP-кода, 0x00 = успех.
2. Сервер отправляет `ConnectAck` после `TcpStream::connect` к цели.
3. Клиент ждёт `ConnectAck` перед отправкой SOCKS5 `REP_SUCCESS`.
4. Маппинг ошибок:
   - ConnectionRefused → 0x05 (connection refused)
   - NetworkUnreachable → 0x03 (network unreachable)
   - HostUnreachable | TimedOut → 0x04 (host unreachable)
   - Прочее → 0x01 (general failure)
5. Таймаут ack → 0x04.
6. Таймауты параметризованы (ack_timeout, connect_timeout).

## Последствия
- Один лишний round-trip на CONNECT.
- Тесты на «цель недоступна» проверяют корректный SOCKS5-ответ.
- Маппинг ошибок зафиксирован здесь, а не только в коде.
- При рефакторинге `proxy-core` маппинг не «упрощать» без пересмотра ADR.

## Дополнение P5.3: Ping/Pong
1. `MessageKind::Ping = 0x04` (payload 1 байт, клиент → сервер);
   `MessageKind::Pong = 0x05` (payload — эхо Ping, сервер → клиент).
2. Сервер обрабатывает `Ping` **до** `Connect` и адресных правил: отвечает
   `Pong` с тем же payload и закрывает соединение. Цель для Ping не нужна.
   Перед закрытием сервер ждёт клиента (≤1 с): иначе у QUIC закрытие может
   опередить доставку `Pong`.
3. Назначение — доказательство живости data-path для политики выбора
   транспорта (ADR-023), а не только handshake.
4. `Connect`/`ConnectAck` не меняются; неизвестный `kind` по-прежнему
   отвергается, поэтому старые peer'ы не ломаются.
5. Проба идёт через полный серверный путь (mTLS → session-limit → протокол):
   отозванный клиент не проходит дальше `verify_client_cert` (ADR-021).