# ADR-027: Cold-select singleflight в TransportManager

## Статус: Принято (2026-10-27)

## Контекст

`TransportManager::select()` сериализован через `Mutex<State>`
(`crates/transport-manager/src/lib.rs:253`): guard берётся на `:298` и
**удерживается через `probe_with_attempts().await`** (`:342`). Холодный выбор
(старт / истечение TTL) держит лок до
`order().len() × max_probe_attempts × probe_timeout` — для `auto` это
`2 × 1 × 2 с = 4 с` худший случай.

Finding из P11 (`docs/operations/load-testing.md`): при 500 одновременных
соединениях на холодном старте 499 ждут первую пробу. На localhost это
не видно (проба sub-ms, `probe_ok=1`, `cached_ok≈N`, p50≈p99), но в реальной
сети (RTT 25–50 мс) холодная проба — десятки-сотни мс, и залповый старт N
соединений (или залп после истечения TTL) сериализуется на пробе.

## Решение

**Singleflight**: только один поток выполняет probe-цикл; остальные ждут
результата через `Notify`, не пробуя.

```rust
struct State {
    tls: Entry,
    quic: Entry,
    /// Токен: какой транспорт сейчас в пробе (`Some` = весь цикл выбора занят).
    probing: Option<TransportKind>,
    /// Пробуждение ожидающих по завершении probe-цикла.
    notify: Arc<Notify>,
}
```

- `probe_with_attempts()` вызывается **без** удержания `Mutex` (она не трогает
  `self.state` — использует только `policy.max_probe_attempts` и `probe`).
- Первый acquire: берёт лок, видит холодный кэш, ставит `probing = Some(kind)`,
  **отпускает лок**, выполняет `probe().await`, перебирает результат, чистит
  `probing`, `notify_waiters()`.
- Остальные acquire: берут лок, видят `probing.is_some()` → отпускают лок,
  `notify.notified().await` → re-check после пробуждения. Повторных проб нет.
- `notify_waiters()` **не** хранит permit для будущих вейтеров (в отличие от
  `notify_one()`, который кладёт permit). Поэтому waiter обязан
  зарегистрироваться (`notified()`) ДО того, как пробирщик вызовет
  `notify_waiters()`. Первая реализация это нарушала — см. «Lost-wakeup и фикс».

### Lost-wakeup и фикс (review)

Реализация создавала `notify.notified()` **после** проверки `probing` и
`drop(state)` — гонка:
```rust
if state.probing.is_some() {
    let notify = state.notify.clone();
    drop(state);
    notify.notified().await;   // RACY: notified() создаётся после drop
}
```
Окно: между `drop(state)` и `notified()` пробирщик на другом потоке успевает
пере-захватить lock и вызвать `notify_waiters()`. `Notify` не хранит permit для
`notify_waiters()`: `tokio/src/sync/notify.rs:529-531` — гарантия wakeup только
если `Notified` создан до `notify_waiters()`; `:562-571` — `notified()` снимает
счётчик `notify_waiters_calls` в момент создания. Вейтер теряет wakeup →
блокируется до следующей пробы. Current-thread тесты (`#[tokio::test]`) этого не
ловили — нет вытеснения между `drop(state)` и `notified()`.

Фикс — pre-register: `notified` создаётся **до** `lock().await`:
```rust
let notified = self.notify.notified();   // до любого notify_waiters()
let mut state = self.state.lock().await;
// ...
if state.probing.is_some() {
    drop(state);
    notified.await;   // уже зарегистрирован → wakeup не потерян
    continue 'outer;
}
```
`notified` создаётся в начале каждой итерации `'outer` (при каждом
`continue 'outer` — новый, старый израсходован). `TransportManager` хранит
`notify: Arc<Notify>` (та же Arc, что и `State.notify`) для пре-регистрации до
захвата лока. Пробирщик вызывает `notify_waiters()` только после повторного
захвата лока, который происходит позже нашего `notified()`.

Доказательство: `lost_wakeup_multi_thread`
(`#[tokio::test(flavor = "multi_thread", worker_threads = 2)`), включает
`FORCE_WINDOW_YIELD` (cfg(test)) — расширяет окно между `drop(state)` и
`notified().await` yield-ами. На раци-коде тест падает по таймауту
(`Elapsed(())` — вейтеры потеряли `notify_waiters()`), на исправленном —
проходит (`1 проба на 100`).

### Семантика `invalidate`

`invalidate(kind, reason)` вызывается по ошибке реального соединения и
**побеждает** результат пробы: ставит `fail_count++`, `blocked_until = now+backoff`,
и если `probing == Some(kind)` — снимает токен (`probing = None`), `notify_waiters()`.
Прочерщик после `probe()` пере-локится, видит `probing != Some(kind)` →
**отбрасывает** результат (не пишет `ok_until`, сохраняет `blocked_until` от
invalidate). Waiters к этому моменту уже ушли в fallback. Это консервативно и
безопасно: успешная проба не «разблокирует» транспорт после ошибки реального
соединения.

### Метрика

`event=transport_acquire_wait_ms` — полное время `select()` (замер в обёртке).
Поля: `wait_ms`, `transport`, `reason`, `strategy`. Уровень: **INFO** при
`wait_ms ≥ 100` мс (реальный контеншен/ожидание), **DEBUG** иначе. Раньше
тайминга ожидания лока не было.

## Альтернативы

- **Release-lock-before-probe**: отпускать лок перед `probe().await` и
  перезабирать после. Проще (без `Notify`), но убирает только удержание ложа,
  а не «стадо» проб: два acquire() могут одновременно увидеть «нет кэша»,
  оба отпустить лок и оба пробить → 2+ пробы. Не гарантирует «1 пробу на N».
- **Гибрид (release-lock + probing-флаг + spin)**: spin-wait не рекомендован
  (busy-spin, без блокирующего ожидания).

Выбран singleflight: гарантирует ровно 1 пробу на транспорт за холодный цикл
и снимает удержание ложа через `probe().await`.

## Последствия

- 1 проба на транспорт за холодный цикл (не N); lock не держится через probe.
- Waiters просыпаются через `notify_waiters()` и перечитывают `Entry` (cache /
  backoff) — повторных проб нет.
- **Lost-wakeup исправлен pre-register** (см. «Lost-wakeup и фикс»): `notified`
  создаётся до `lock`. Без этого на multi-thread рантайме вейтер мог потерять
  `notify_waiters()` и зависнуть; current-thread тесты не ловили, добавлен
  multi-thread тест `lost_wakeup_multi_thread`.
- Метрика `transport_acquire_wait_ms` позволяет измерить эффект на реальной
  сети.
- Гистерезис переключения (`min_switch_interval=30с`) **не реализован**: он был
  в исходном плане P5.3, в коде/конфиге/ADR-023 отсутствует. Выбор управляется
  `TTL=300с` + `backoff` (`fail_ttl=30с`); латентность не участвует, осцилляция
  ограничена `blocked_until`. Если реальные замеры покажут флап — отдельный
  ADR-028.
- UI/API не меняются (`select()` сигнатура и `Selection` без изменений).

## Что не делаем

- Никаких ML/эвристик в выборе (только явные пороги TTL/backoff).
- Не меняем политику выбора (`auto`, serial, TLS-first).
- Не добавляем `min_switch_interval` в этом ADR (см. «Последствия», ADR-028).
